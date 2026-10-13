"""Retiring a DNS provider cannot leave implicit routing authority behind."""
import json

import tproxy
import app_dns


def test_independent_app_dns_uses_only_public_resolvers():
    assert app_dns.APP_DOH_ENDPOINTS == (
        ("1.1.1.1", "cloudflare-dns.com"),
        ("8.8.8.8", "dns.google"),
    )


def test_former_provider_system_dns_is_read_only_generic_configuration():
    status = tproxy.system_dns_status_from_scutil(
        "nameserver[0] : 111.88.96.50\nnameserver[1] : 2a00:ab00:1233:26::51\n"
    )
    assert status == {
        "state": "configured", "providers": "",
        "servers": ["111.88.96.50", "2a00:ab00:1233:26::51"],
        "managed_by_slipstream": False,
    }


def test_stale_provider_status_and_canary_cannot_enable_smart_dns(monkeypatch):
    monkeypatch.setattr(tproxy, "current_system_dns_status", lambda: {
        "state": "xbox_dns", "providers": "xbox_dns",
        "servers": ["111.88.96.50"],
    })
    monkeypatch.setattr(tproxy, "_smart_dns_ok_until", {tproxy.SERVICE_OPENAI: 200.0})
    assert not tproxy.smart_dns_available()
    assert not tproxy.smart_dns_route_enabled("chatgpt.com", now=100.0)
    assert tproxy.smart_dns_status_snapshot(now=100.0)["state"] == "off"


def test_legacy_learned_route_without_dns_provenance_is_not_loaded(tmp_path, monkeypatch):
    path = tmp_path / "routes.json"
    path.write_text(json.dumps({"unknown.example": tproxy.time.time() + 3600}))
    monkeypatch.setattr(tproxy, "_AUTO_GEPH_PATH", str(path))
    monkeypatch.setattr(tproxy, "_auto_geph", {})
    tproxy.load_auto_geph()
    assert not tproxy._auto_geph
    assert json.loads(path.read_text()) == {
        "__v__": tproxy.AUTO_GEPH_STATE_VERSION, "routes": {},
    }


def test_new_dns_proof_routes_round_trip_without_resetting_strategy_learning(tmp_path, monkeypatch):
    path = tmp_path / "routes.json"
    routes = {"unknown.example": tproxy.time.time() + 3600}
    strategies = {"discord.com": "discord_matched_fake"}
    monkeypatch.setattr(tproxy, "_AUTO_GEPH_PATH", str(path))
    monkeypatch.setattr(tproxy, "_auto_geph", dict(routes))
    monkeypatch.setattr(tproxy, "_strat_cache", strategies)
    tproxy.save_auto_geph()
    tproxy._auto_geph.clear()
    tproxy.load_auto_geph()
    assert tproxy._auto_geph == routes
    assert tproxy._strat_cache is strategies
    assert tproxy._strat_cache == {"discord.com": "discord_matched_fake"}
    assert path.stat().st_mode & 0o777 == 0o600


def test_legacy_dns_observation_cannot_fill_new_independent_stage():
    observations = {"system": 1, "xbox_dns": 1, "strategy:split64": 1,
                    "strategy:split16": 1}
    assert not tproxy._valid_auto_geph_stage("xbox_dns")
    assert not tproxy._local_route_evidence_complete(observations, 2)
    observations.pop("xbox_dns")
    assert not tproxy._local_route_evidence_complete(observations, 2)
    observations["app_dns"] = 1
    assert tproxy._valid_auto_geph_stage("app_dns")
    assert tproxy._local_route_evidence_complete(observations, 2)
