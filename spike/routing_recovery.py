"""Pure routing recovery model with no sockets, files, or OS side effects."""

from dataclasses import dataclass


ROUTE_LOCAL_BYPASS = "local_bypass"
ROUTE_GEO_EXIT = "geo_exit"
ROUTE_UNKNOWN = "unknown"

SERVICE_DISCORD = "discord"
SERVICE_YOUTUBE = "youtube_video"

POLICY_PROTECTED_LOCAL_BYPASS_GROUPS = frozenset(
    (SERVICE_DISCORD, SERVICE_YOUTUBE)
)

RECOVERY_NONE = "none"
RECOVERY_INVALIDATE_STRATEGY = "invalidate_strategy"
RECOVERY_RESWEEP_EXACT_HOST = "resweep_exact_host"
RECOVERY_RESTART_OWNED_GEPH = "restart_owned_geph"
RECOVERY_RECHECK = "recheck"
RECOVERY_WARN_EXTERNAL = "warn_external"


@dataclass(frozen=True)
class ConnectionOutcome:
    host: str
    service_group: str
    route_class: str
    backend: str
    failure_phase: str
    bytes_received: int
    duration: float
    reason: str
    ok: bool


@dataclass(frozen=True)
class RecoveryContext:
    backend_owned: bool = False
    restart_recommended: bool = False
    restart_rate_limited: bool = False
    strategy_invalidation_recommended: bool = False
    recheck_recommended: bool = False
    external_state: bool = False


@dataclass(frozen=True)
class RecoveryAction:
    kind: str
    target: str = ""
    reason: str = ""


def reduce_connection_outcome(outcome, context=None):
    """Choose safe recovery work without performing any side effects."""
    context = context or RecoveryContext()
    if outcome.ok:
        return (RecoveryAction(RECOVERY_NONE),)

    reason = outcome.reason[:200]
    protected_local = outcome.service_group in POLICY_PROTECTED_LOCAL_BYPASS_GROUPS
    if protected_local or outcome.route_class == ROUTE_LOCAL_BYPASS:
        return (
            RecoveryAction(
                RECOVERY_INVALIDATE_STRATEGY,
                outcome.service_group,
                reason,
            ),
            RecoveryAction(RECOVERY_RESWEEP_EXACT_HOST, outcome.host, reason),
            RecoveryAction(RECOVERY_RECHECK, outcome.service_group, reason),
        )

    if context.external_state:
        return (RecoveryAction(RECOVERY_WARN_EXTERNAL, outcome.backend, reason),)

    if outcome.route_class == ROUTE_GEO_EXIT:
        actions = []
        if context.strategy_invalidation_recommended:
            actions.append(
                RecoveryAction(RECOVERY_INVALIDATE_STRATEGY, outcome.host, reason)
            )
        if (
            context.backend_owned
            and context.restart_recommended
            and not context.restart_rate_limited
        ):
            actions.append(
                RecoveryAction(RECOVERY_RESTART_OWNED_GEPH, outcome.backend, reason)
            )
        else:
            actions.append(
                RecoveryAction(RECOVERY_RECHECK, outcome.service_group, reason)
            )
        return tuple(actions)

    if outcome.route_class == ROUTE_UNKNOWN and context.recheck_recommended:
        return (RecoveryAction(RECOVERY_RECHECK, outcome.host, reason),)

    return (RecoveryAction(RECOVERY_NONE),)
