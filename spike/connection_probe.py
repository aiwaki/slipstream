"""Race existing per-address probe dialers without changing route policy."""

from dataclasses import dataclass
import ipaddress
from typing import Awaitable, Callable, Optional

import address_attempts
import connection_race
import connection_race_io
import route_circuit


ProbeDialer = Callable[[str], Awaitable[Optional[tuple]]]


@dataclass(frozen=True)
class RacedProbeResult:
    transition: connection_race.ConnectionRaceTransition
    address: str = ""
    connection: Optional[connection_race_io.OwnedStream] = None
    server_first: bytes = b""

    async def close(self):
        if self.connection is not None:
            await self.connection.close()

    @property
    def attempted_count(self):
        return len(self.transition.state.attempts)


def numeric_candidates(addresses, source="runtime"):
    """Return stable, deduplicated candidates for already-resolved addresses."""
    candidates = []
    seen = set()
    for raw_address in addresses:
        address = str(raw_address or "").strip()
        if not address:
            continue
        base, separator, scope = address.partition("%")
        try:
            parsed = ipaddress.ip_address(base)
        except ValueError as exc:
            raise ValueError("probe candidates must be numeric IP addresses") from exc
        normalized = parsed.compressed
        if separator:
            normalized = f"{normalized}%{scope}"
        family = (
            address_attempts.FAMILY_IPV4
            if parsed.version == 4
            else address_attempts.FAMILY_IPV6
        )
        identity = (family, normalized)
        if identity in seen:
            continue
        seen.add(identity)
        candidates.append(
            address_attempts.AddressCandidate(
                id=f"{source}:{family}:{normalized}",
                family=family,
                address=normalized,
                source=source,
            )
        )
    return tuple(candidates)


async def race_probe_dials(
    host,
    port,
    addresses,
    dial_candidate: ProbeDialer,
    *,
    service_group,
    route_class,
    backend_id,
    timeout_ms=9_000,
    stagger_ms=250,
    max_concurrent=2,
    preferred_family=address_attempts.FAMILY_IPV4,
    circuit_states=None,
    circuit_config=None,
    clock_ms=connection_race_io.monotonic_ms,
):
    """Race complete first-payload probes and transfer only the winning stream."""
    candidates = numeric_candidates(addresses)
    payloads = {}

    async def resolver(_host, _port):
        return candidates

    async def connector(candidate, _port):
        result = await dial_candidate(candidate.address)
        if result is None:
            raise OSError("candidate probe returned no payload")
        reader, writer, server_first = result
        if not isinstance(server_first, bytes) or not server_first:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            raise OSError("candidate probe returned an invalid payload")
        payloads[candidate.id] = server_first
        return reader, writer

    key = route_circuit.RouteCircuitKey(
        service_group,
        route_class,
        backend_id,
    )
    race_config = connection_race.ConnectionRaceConfig(
        timeout_ms=timeout_ms,
        stagger_ms=stagger_ms,
        max_concurrent=max_concurrent,
        preferred_family=preferred_family,
    )
    if circuit_config is None:
        circuit_config = route_circuit.CircuitConfig(
            failure_threshold=2,
            open_duration_ms=1_000,
            half_open_max_in_flight=1,
            success_threshold=1,
        )
    io_result = await connection_race_io.open_connection_race(
        host,
        port,
        {} if circuit_states is None else circuit_states,
        key,
        race_config,
        circuit_config,
        resolver=resolver,
        connector=connector,
        clock_ms=clock_ms,
    )
    if io_result.connection is None:
        return RacedProbeResult(io_result.transition)

    winner_id = io_result.connection.candidate_id
    winner = next(
        (candidate for candidate in candidates if candidate.id == winner_id),
        None,
    )
    server_first = payloads.get(winner_id, b"")
    if winner is None or not server_first:
        await io_result.connection.close()
        raise RuntimeError("connected probe is missing winner metadata")
    return RacedProbeResult(
        io_result.transition,
        address=winner.address,
        connection=io_result.connection,
        server_first=server_first,
    )
