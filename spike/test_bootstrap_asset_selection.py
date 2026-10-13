"""Keep an unrelated script from occupying the only child recovery probe."""
import pytest
import tproxy
from bootstrap_asset_preflight import EphemeralBootstrapAsset


def asset(host):
    return EphemeralBootstrapAsset(exact_host=host, host_header=host,
                                   request_target='/bundle.js?private-build=1')


@pytest.mark.parametrize('hosts,expected', [
    (['ads.example.net', 'cdn.gallery.example', 'metrics.example.net'], 'cdn.gallery.example'),
    (['cdn.gallery.example', 'ads.example.net'], 'cdn.gallery.example'),
    (['notgallery.example', 'gallery.example.attacker.net', 'cdn.gallery.example'], 'cdn.gallery.example'),
    (['gallery.example', 'library.example.net'], 'library.example.net'),
    (['a.gallery.example', 'b.gallery.example'], 'a.gallery.example'),
    (['gallery.example'], 'gallery.example'),
])
def test_prefers_owned_child_with_stable_order_and_forgets_others(monkeypatch, hosts, expected):
    monkeypatch.setattr(tproxy, '_auto_geph_base_host_allowed', lambda h: True)
    items = [asset(h) for h in hosts]
    selected, cross = tproxy._select_route_preflight_bootstrap_asset(items, 'gallery.example')
    assert selected.exact_host == expected
    assert cross is (expected != 'gallery.example')
    assert b'/bundle.js?' in selected.build_range_request()
    for item in items:
        if item is not selected:
            with pytest.raises(RuntimeError):
                item.build_range_request()


def test_owned_child_preference_cannot_override_policy_exclusion(monkeypatch):
    monkeypatch.setattr(tproxy, '_auto_geph_base_host_allowed', lambda h: h != 'blocked.gallery.example')
    blocked, allowed = asset('blocked.gallery.example'), asset('library.example.net')
    selected, cross = tproxy._select_route_preflight_bootstrap_asset([blocked, allowed], 'gallery.example')
    assert selected is allowed and cross
    with pytest.raises(RuntimeError):
        blocked.build_range_request()


def test_reviewed_explorecams_cdn_does_not_route_parent_or_unrelated_hosts():
    assert tproxy.route_policy('cdn.explorecams.com')['route_class'] == 'geo_exit'
    for host in ('explorecams.com', 'notcdn.explorecams.com',
                 'cdn.explorecams.com.attacker.example', 'sampleshots.com',
                 'onfotolife.com.attacker.example', 'discord.com', 'gateway.discord.gg',
                 'youtube.com', 'video.googlevideo.com'):
        assert tproxy.route_policy(host)['route_class'] != 'geo_exit'


def test_reviewed_photo_challenge_hosts_are_narrow():
    for host in ('onfotolife.com', 'www.sampleshots.com'):
        assert tproxy.route_policy(host)['route_class'] == 'geo_exit'
    for host in ('sampleshots.com', 'notsampleshots.com', 'notonfotolife.com',
                 'www.sampleshots.com.attacker.example', 'challenges.cloudflare.com'):
        assert tproxy.route_policy(host)['route_class'] != 'geo_exit'


def test_reviewed_juniper_cdn_does_not_route_entire_store_platform():
    assert tproxy.route_policy('cdn.junipercreates.com')['route_class'] == 'geo_exit'
    for host in ('junipercreates.com', 'gorillatag.junipercreates.com',
                 'notcdn.junipercreates.com', 'cdn.junipercreates.com.attacker.example',
                 'cloudfront.net', 'discord.com', 'youtube.com'):
        assert tproxy.route_policy(host)['route_class'] != 'geo_exit'


def test_explicit_critical_image_wins_over_unrelated_and_owned_scripts(monkeypatch):
    monkeypatch.setattr(tproxy, '_auto_geph_base_host_allowed', lambda h: True)
    image = EphemeralBootstrapAsset(exact_host='images.example.net',
        host_header='images.example.net', request_target='/hero.webp', discovery_priority=1)
    script = asset('cdn.gallery.example')
    selected, cross = tproxy._select_route_preflight_bootstrap_asset(
        [script, image], 'gallery.example')
    assert selected is image and cross
    with pytest.raises(RuntimeError):
        script.build_range_request()


def test_critical_image_priority_never_overrides_protected_host(monkeypatch):
    monkeypatch.setattr(tproxy, '_auto_geph_base_host_allowed', lambda h: h != 'youtube.com')
    image = EphemeralBootstrapAsset(exact_host='youtube.com', host_header='youtube.com',
        request_target='/hero.webp', discovery_priority=1)
    script = asset('cdn.gallery.example')
    selected, _ = tproxy._select_route_preflight_bootstrap_asset(
        [image, script], 'gallery.example')
    assert selected is script
    with pytest.raises(RuntimeError):
        image.build_range_request()
