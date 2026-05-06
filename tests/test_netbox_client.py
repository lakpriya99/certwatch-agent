"""Phase 6 — NetBoxClient tests.

Monkeypatches `pynetbox.api` at the module level so each test provides
a fake api object whose `.dcim.devices.filter(**kwargs)` returns
fake-record devices. Tests focus on the transformation logic
(CIDR stripping, port resolution, tag extraction, skip-on-no-hostname)
and the error-path → NetBoxSyncError mapping.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pynetbox.core.query import ContentError, RequestError

import certwatch.netbox_client as nbc_mod
from certwatch.netbox_client import (
    DiscoveredHost,
    NetBoxClient,
    NetBoxSyncError,
    _parse_filter_expr,
    _parse_netbox_verify_ssl_env,
    _resolve_hostname,
    _resolve_port,
    _resolve_tags,
)


# ---- fake pynetbox -------------------------------------------------


class FakeIP:
    def __init__(self, address: str):
        self.address = address


class FakeTag:
    def __init__(self, name: str):
        self.name = name


def _device(
    *,
    id: int,
    name: str | None = None,
    primary_ip4: FakeIP | None = None,
    primary_ip6: FakeIP | None = None,
    custom_fields: dict | None = None,
    tags: list | None = None,
):
    """Build a fake pynetbox-Device-like object."""
    return SimpleNamespace(
        id=id,
        name=name,
        primary_ip4=primary_ip4,
        primary_ip6=primary_ip6,
        custom_fields=custom_fields if custom_fields is not None else {},
        tags=tags if tags is not None else [],
    )


class FakeDeviceEndpoint:
    def __init__(self, devices=None, *, raise_exc=None, capture_filter=None):
        self._devices = devices or []
        self._raise_exc = raise_exc
        self._capture_filter = capture_filter

    def filter(self, **kwargs):
        if self._capture_filter is not None:
            self._capture_filter.append(kwargs)
        if self._raise_exc is not None:
            raise self._raise_exc
        return list(self._devices)


class FakeDcim:
    def __init__(self, devices_endpoint):
        self.devices = devices_endpoint


class FakeApi:
    def __init__(self, devices_endpoint):
        self.dcim = FakeDcim(devices_endpoint)
        self.http_session = SimpleNamespace()  # supports timeout assignment


def _patch_api(monkeypatch, devices=None, *, raise_exc=None, capture_filter=None):
    endpoint = FakeDeviceEndpoint(
        devices=devices, raise_exc=raise_exc, capture_filter=capture_filter
    )

    def factory(url, token=None):
        return FakeApi(endpoint)

    monkeypatch.setattr(nbc_mod.pynetbox, "api", factory)
    return endpoint


# ---- happy path: transformation -------------------------------------


def test_fetch_hosts_with_full_data(monkeypatch):
    devices = [
        _device(
            id=1247,
            name="app01",
            primary_ip4=FakeIP("10.1.2.3/24"),
            custom_fields={"cert_check_port": 443},
            tags=[FakeTag("monitor-cert"), FakeTag("production")],
        ),
        _device(
            id=1248,
            name="app02",
            primary_ip4=FakeIP("192.168.1.50/24"),
            custom_fields={"cert_check_port": 8443},
            tags=[FakeTag("monitor-cert")],
        ),
    ]
    _patch_api(monkeypatch, devices)

    client = NetBoxClient(url="http://nb", token="t", filter_expr="tag=monitor-cert")
    hosts = client.fetch_hosts()

    assert len(hosts) == 2
    assert hosts[0] == DiscoveredHost(
        netbox_device_id=1247, hostname="10.1.2.3", port=443,
        display_name="app01", tags=["monitor-cert", "production"],
    )
    assert hosts[1].port == 8443
    assert hosts[1].hostname == "192.168.1.50"


def test_primary_ip4_strips_cidr_notation(monkeypatch):
    _patch_api(monkeypatch, [_device(id=1, name="x", primary_ip4=FakeIP("10.1.2.3/24"))])
    [host] = NetBoxClient(url="u", token="t", filter_expr="").fetch_hosts()
    assert host.hostname == "10.1.2.3"


def test_primary_ip4_without_cidr_works(monkeypatch):
    _patch_api(monkeypatch, [_device(id=1, name="x", primary_ip4=FakeIP("10.1.2.3"))])
    [host] = NetBoxClient(url="u", token="t", filter_expr="").fetch_hosts()
    assert host.hostname == "10.1.2.3"


def test_primary_ip6_used_when_no_ip4(monkeypatch):
    _patch_api(monkeypatch, [
        _device(id=1, name="x", primary_ip4=None,
                primary_ip6=FakeIP("2001:db8::1/64")),
    ])
    [host] = NetBoxClient(url="u", token="t", filter_expr="").fetch_hosts()
    assert host.hostname == "2001:db8::1"


def test_falls_back_to_device_name_when_no_primary_ip(monkeypatch):
    _patch_api(monkeypatch, [
        _device(id=1, name="app01.example.com", primary_ip4=None, primary_ip6=None),
    ])
    [host] = NetBoxClient(url="u", token="t", filter_expr="").fetch_hosts()
    assert host.hostname == "app01.example.com"


def test_skips_device_with_no_resolvable_hostname(monkeypatch, caplog):
    _patch_api(monkeypatch, [
        _device(id=1, name=None, primary_ip4=None, primary_ip6=None),
        _device(id=2, name="x", primary_ip4=FakeIP("10.0.0.1")),
    ])
    with caplog.at_level("INFO"):
        hosts = NetBoxClient(url="u", token="t", filter_expr="").fetch_hosts()
    assert len(hosts) == 1
    assert hosts[0].netbox_device_id == 2
    skip_logs = [r.msg for r in caplog.records
                 if isinstance(r.msg, dict) and r.msg.get("event") == "netbox_device_skipped_no_hostname"]
    assert len(skip_logs) == 1


# ---- port resolution ------------------------------------------------


def test_port_defaults_to_443_when_no_custom_field(monkeypatch):
    _patch_api(monkeypatch, [
        _device(id=1, name="x", primary_ip4=FakeIP("10.0.0.1"),
                custom_fields={}),
    ])
    [host] = NetBoxClient(url="u", token="t", filter_expr="").fetch_hosts()
    assert host.port == 443


def test_port_uses_custom_field_when_integer(monkeypatch):
    _patch_api(monkeypatch, [
        _device(id=1, name="x", primary_ip4=FakeIP("10.0.0.1"),
                custom_fields={"cert_check_port": 8443}),
    ])
    [host] = NetBoxClient(url="u", token="t", filter_expr="").fetch_hosts()
    assert host.port == 8443


def test_port_falls_back_when_custom_field_is_string_integer(monkeypatch):
    """NetBox's custom fields can come back as strings; tolerate
    integer-valued strings."""
    _patch_api(monkeypatch, [
        _device(id=1, name="x", primary_ip4=FakeIP("10.0.0.1"),
                custom_fields={"cert_check_port": "9443"}),
    ])
    [host] = NetBoxClient(url="u", token="t", filter_expr="").fetch_hosts()
    assert host.port == 9443


def test_port_falls_back_when_custom_field_invalid(monkeypatch, caplog):
    _patch_api(monkeypatch, [
        _device(id=1, name="x", primary_ip4=FakeIP("10.0.0.1"),
                custom_fields={"cert_check_port": "not-a-number"}),
    ])
    with caplog.at_level("WARNING"):
        [host] = NetBoxClient(url="u", token="t", filter_expr="").fetch_hosts()
    assert host.port == 443
    warns = [r.msg for r in caplog.records
             if isinstance(r.msg, dict) and r.msg.get("event") == "netbox_invalid_cert_check_port_using_default"]
    assert len(warns) == 1


# ---- tag handling ---------------------------------------------------


def test_empty_tags(monkeypatch):
    _patch_api(monkeypatch, [
        _device(id=1, name="x", primary_ip4=FakeIP("10.0.0.1"), tags=[]),
    ])
    [host] = NetBoxClient(url="u", token="t", filter_expr="").fetch_hosts()
    assert host.tags == []


def test_tags_preserve_order(monkeypatch):
    _patch_api(monkeypatch, [
        _device(id=1, name="x", primary_ip4=FakeIP("10.0.0.1"),
                tags=[FakeTag("alpha"), FakeTag("beta"), FakeTag("gamma")]),
    ])
    [host] = NetBoxClient(url="u", token="t", filter_expr="").fetch_hosts()
    assert host.tags == ["alpha", "beta", "gamma"]


def test_tags_strips_whitespace_and_skips_invalid(monkeypatch):
    _patch_api(monkeypatch, [
        _device(id=1, name="x", primary_ip4=FakeIP("10.0.0.1"),
                tags=[FakeTag("  good  "), FakeTag(""), SimpleNamespace(name=None)]),
    ])
    [host] = NetBoxClient(url="u", token="t", filter_expr="").fetch_hosts()
    assert host.tags == ["good"]


# ---- error mapping → NetBoxSyncError --------------------------------


def _fake_response(status_code: int, body=None):
    """Build a fake-enough requests.Response for pynetbox exceptions to
    construct themselves without crashing."""
    return SimpleNamespace(
        status_code=status_code,
        reason="Test Reason",
        url="http://nb/api/dcim/devices/",
        text=str(body or ""),
        json=lambda: body or {"detail": "test"},
        request=SimpleNamespace(body=None),
    )


def test_request_error_raises_netbox_sync_error(monkeypatch):
    _patch_api(monkeypatch, raise_exc=RequestError(_fake_response(401, {"detail": "Unauthorized"})))
    with pytest.raises(NetBoxSyncError) as exc:
        NetBoxClient(url="u", token="bad", filter_expr="").fetch_hosts()
    assert isinstance(exc.value.original_error, RequestError)


def test_content_error_raises_netbox_sync_error(monkeypatch):
    _patch_api(monkeypatch, raise_exc=ContentError(_fake_response(200)))
    with pytest.raises(NetBoxSyncError) as exc:
        NetBoxClient(url="u", token="t", filter_expr="").fetch_hosts()
    assert isinstance(exc.value.original_error, ContentError)


def test_unexpected_exception_wrapped_in_netbox_sync_error(monkeypatch):
    """pynetbox can leak underlying requests exceptions; surface them
    all as NetBoxSyncError so the caller has a single type to catch."""
    import requests
    _patch_api(monkeypatch, raise_exc=requests.ConnectionError("ECONNREFUSED"))
    with pytest.raises(NetBoxSyncError) as exc:
        NetBoxClient(url="u", token="t", filter_expr="").fetch_hosts()
    assert isinstance(exc.value.original_error, requests.ConnectionError)


# ---- filter expression parsing --------------------------------------


def test_parse_filter_expr_single_value():
    assert _parse_filter_expr("tag=monitor-cert") == {"tag": "monitor-cert"}


def test_parse_filter_expr_multiple_keys():
    parsed = _parse_filter_expr("tag=monitor-cert&role=server")
    assert parsed == {"tag": "monitor-cert", "role": "server"}


def test_parse_filter_expr_multi_value_single_key():
    """tag=a&tag=b must become tag=['a', 'b'] so pynetbox treats it as
    multiple values for the same key, not a silent overwrite."""
    parsed = _parse_filter_expr("tag=a&tag=b")
    assert parsed == {"tag": ["a", "b"]}


def test_parse_filter_expr_empty_returns_empty_dict():
    assert _parse_filter_expr("") == {}
    assert _parse_filter_expr("   ") == {}


def test_filter_passed_verbatim_to_pynetbox(monkeypatch):
    captured: list = []
    _patch_api(monkeypatch, [], capture_filter=captured)
    NetBoxClient(
        url="u", token="t", filter_expr="tag=monitor-cert&role=web"
    ).fetch_hosts()
    assert captured == [{"tag": "monitor-cert", "role": "web"}]


def test_filter_with_empty_expression_passes_no_filters(monkeypatch):
    """Empty NETBOX_FILTER means 'all devices' — pynetbox.filter()
    with no kwargs returns everything."""
    captured: list = []
    _patch_api(monkeypatch, [], capture_filter=captured)
    NetBoxClient(url="u", token="t", filter_expr="").fetch_hosts()
    assert captured == [{}]


# ---- helper unit tests ---------------------------------------------


def test_resolve_hostname_prefers_ip4_over_ip6():
    d = SimpleNamespace(
        primary_ip4=FakeIP("10.0.0.1/24"),
        primary_ip6=FakeIP("2001:db8::1"),
        name="fallback",
    )
    assert _resolve_hostname(d) == "10.0.0.1"


def test_resolve_hostname_returns_none_when_nothing_set():
    d = SimpleNamespace(primary_ip4=None, primary_ip6=None, name=None)
    assert _resolve_hostname(d) is None


def test_resolve_hostname_skips_blank_name():
    d = SimpleNamespace(primary_ip4=None, primary_ip6=None, name="   ")
    assert _resolve_hostname(d) is None


def test_resolve_port_handles_non_dict_custom_fields():
    """Defensive: custom_fields could in theory be missing or wrong type."""
    d = SimpleNamespace(custom_fields=None)
    assert _resolve_port(d, 1) == 443


def test_resolve_tags_handles_missing_attribute():
    d = SimpleNamespace()  # no tags attr at all
    assert _resolve_tags(d) == []


# ---- NETBOX_VERIFY_SSL parsing -------------------------------------


def test_parse_verify_ssl_env_default_true_when_unset(monkeypatch):
    monkeypatch.delenv("NETBOX_VERIFY_SSL", raising=False)
    assert _parse_netbox_verify_ssl_env() is True


def test_parse_verify_ssl_env_empty_string_uses_default():
    """Forgiving: empty string treated as unset, defaults to True."""
    assert _parse_netbox_verify_ssl_env({"NETBOX_VERIFY_SSL": ""}) is True
    assert _parse_netbox_verify_ssl_env({"NETBOX_VERIFY_SSL": "   "}) is True


@pytest.mark.parametrize("v", ["true", "True", "TRUE", "1", "yes", "YES", "Yes"])
def test_parse_verify_ssl_env_truthy_values(v):
    assert _parse_netbox_verify_ssl_env({"NETBOX_VERIFY_SSL": v}) is True


@pytest.mark.parametrize("v", ["false", "False", "FALSE", "0", "no", "NO", "No"])
def test_parse_verify_ssl_env_falsy_values_case_insensitive(v):
    assert _parse_netbox_verify_ssl_env({"NETBOX_VERIFY_SSL": v}) is False


def test_parse_verify_ssl_env_invalid_value_falls_back_to_true(caplog):
    """Silent bypass would be worse than explicit opt-in. Invalid →
    secure default + warning log so the operator can see they typoed."""
    with caplog.at_level("WARNING"):
        result = _parse_netbox_verify_ssl_env({"NETBOX_VERIFY_SSL": "maybe"})
    assert result is True
    msgs = [r.msg for r in caplog.records
            if isinstance(r.msg, dict) and r.msg.get("event") == "netbox_invalid_verify_ssl_value_using_default"]
    assert len(msgs) == 1
    assert msgs[0]["raw_value"] == "maybe"
    assert msgs[0]["default_used"] is True


# ---- NetBoxClient verify_ssl wiring --------------------------------


def test_netbox_client_verify_ssl_default_true(monkeypatch):
    """When env var is unset and no explicit kwarg, the client's
    underlying session has verify=True (secure by default)."""
    monkeypatch.delenv("NETBOX_VERIFY_SSL", raising=False)
    _patch_api(monkeypatch, [])
    client = NetBoxClient(url="https://nb", token="t", filter_expr="")
    assert client._api.http_session.verify is True


def test_netbox_client_verify_ssl_false_when_env_says_false(monkeypatch):
    monkeypatch.setenv("NETBOX_VERIFY_SSL", "false")
    _patch_api(monkeypatch, [])
    client = NetBoxClient(url="https://nb", token="t", filter_expr="")
    assert client._api.http_session.verify is False


def test_netbox_client_verify_ssl_invalid_value_falls_back_to_true(monkeypatch, caplog):
    monkeypatch.setenv("NETBOX_VERIFY_SSL", "definitely-maybe")
    _patch_api(monkeypatch, [])
    with caplog.at_level("WARNING"):
        client = NetBoxClient(url="https://nb", token="t", filter_expr="")
    assert client._api.http_session.verify is True
    # The parse warning fires — confirms the env-var path was exercised.
    msgs = [r.msg for r in caplog.records
            if isinstance(r.msg, dict) and r.msg.get("event") == "netbox_invalid_verify_ssl_value_using_default"]
    assert len(msgs) == 1


@pytest.mark.parametrize("v", ["FALSE", "False", "false", "0", "NO", "no"])
def test_netbox_client_verify_ssl_case_insensitive_falsy(monkeypatch, v):
    monkeypatch.setenv("NETBOX_VERIFY_SSL", v)
    _patch_api(monkeypatch, [])
    client = NetBoxClient(url="https://nb", token="t", filter_expr="")
    assert client._api.http_session.verify is False


def test_netbox_client_logs_warning_when_ssl_disabled(monkeypatch, caplog):
    """The warning is the operator's audit trail. WARNING level so it
    surfaces in default INFO+ log filtering, not buried."""
    monkeypatch.setenv("NETBOX_VERIFY_SSL", "false")
    _patch_api(monkeypatch, [])
    with caplog.at_level("WARNING"):
        NetBoxClient(url="https://netbox.lab.example", token="t", filter_expr="")
    msgs = [r.msg for r in caplog.records
            if isinstance(r.msg, dict) and r.msg.get("event") == "netbox_ssl_verification_disabled"]
    assert len(msgs) == 1
    # URL surfaced for audit visibility — operator can confirm WHICH
    # NetBox instance is using insecure TLS.
    assert msgs[0]["url"] == "https://netbox.lab.example"


def test_netbox_client_no_warning_when_ssl_enabled(monkeypatch, caplog):
    """The warning should NOT fire on the secure default path. A noisy
    warning in production logs is exactly the kind of friction that
    leads operators to suppress all warnings, masking real problems."""
    monkeypatch.delenv("NETBOX_VERIFY_SSL", raising=False)
    _patch_api(monkeypatch, [])
    with caplog.at_level("WARNING"):
        NetBoxClient(url="https://nb", token="t", filter_expr="")
    msgs = [r.msg for r in caplog.records
            if isinstance(r.msg, dict) and r.msg.get("event") == "netbox_ssl_verification_disabled"]
    assert msgs == []


def test_netbox_client_explicit_verify_ssl_overrides_env(monkeypatch):
    """If verify_ssl is passed explicitly, env var is ignored. The runner
    relies on this to read NETBOX_VERIFY_SSL from its own env Mapping
    rather than os.environ — tests with synthetic envs depend on this
    contract."""
    monkeypatch.setenv("NETBOX_VERIFY_SSL", "true")
    _patch_api(monkeypatch, [])
    client = NetBoxClient(
        url="https://nb", token="t", filter_expr="", verify_ssl=False,
    )
    assert client._api.http_session.verify is False
