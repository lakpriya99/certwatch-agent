"""Phase 6 — NetBox client.

Wraps pynetbox to fetch devices matching the operator-supplied
NETBOX_FILTER and transform them into `DiscoveredHost` records ready
for the /discovered-hosts payload.

Resolution rules per the design:
  - hostname: device.primary_ip4.address (CIDR stripped) →
              primary_ip6.address (CIDR stripped) → device.name
  - port:     device.custom_fields["cert_check_port"] (if integer-valued)
              → 443
  - display_name: device.name (or None if empty)
  - tags:     [tag.name for tag in device.tags]
  - skip:     no resolvable hostname (no primary_ip and no name)

The filter_expr is passed VERBATIM to pynetbox — operator-owned config,
not user input. urllib's parse_qs is used so multi-value filters
(tag=a&tag=b) become lists pynetbox understands.

Any failure (auth, 5xx, network, parse) raises NetBoxSyncError. The
caller (run_netbox_sync) treats this as the safety signal to NOT call
submit_discovered_hosts — the contract is "preserve last known dashboard
state when NetBox is unreachable".
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Mapping, Optional, Union
from urllib.parse import parse_qs

import pynetbox
import urllib3
from pynetbox.core.query import ContentError, RequestError

log = logging.getLogger("certwatch")


# Accepted truthy/falsy spellings for NETBOX_VERIFY_SSL — same forgiving
# convention as the rest of the agent's env-var handling. Pinned by tests.
_VERIFY_SSL_TRUE = frozenset(("true", "1", "yes"))
_VERIFY_SSL_FALSE = frozenset(("false", "0", "no"))


def _parse_netbox_verify_ssl_env(env: Optional[Mapping[str, str]] = None) -> bool:
    """Read NETBOX_VERIFY_SSL with forgiving parsing.

    Default is True (safe). Operators on lab/homelab NetBox instances
    with self-signed certs explicitly set NETBOX_VERIFY_SSL=false to
    bypass verification. Invalid values fall back to True with a
    warning — silent bypass would be worse than explicit opt-in."""
    if env is None:
        env = os.environ
    raw = env.get("NETBOX_VERIFY_SSL", "")
    normalized = raw.strip().lower()
    if not normalized:
        return True
    if normalized in _VERIFY_SSL_TRUE:
        return True
    if normalized in _VERIFY_SSL_FALSE:
        return False
    log.warning(
        {
            "event": "netbox_invalid_verify_ssl_value_using_default",
            "raw_value": raw,
            "default_used": True,
            "accepted_values": sorted(_VERIFY_SSL_TRUE | _VERIFY_SSL_FALSE),
        }
    )
    return True


@dataclass(frozen=True)
class DiscoveredHost:
    netbox_device_id: int
    hostname: str
    port: int
    display_name: Optional[str]
    tags: list[str] = field(default_factory=list)


class NetBoxSyncError(Exception):
    """Raised when fetch_hosts can't talk to NetBox or can't parse the
    response. Carries the underlying exception on `.original_error` for
    structured logging."""

    def __init__(self, message: str, original_error: Optional[BaseException] = None):
        super().__init__(message)
        self.message = message
        self.original_error = original_error


class NetBoxClient:
    def __init__(
        self,
        url: str,
        token: str,
        filter_expr: str,
        *,
        timeout: float = 30.0,
        verify_ssl: Optional[bool] = None,
    ) -> None:
        # `verify_ssl=None` means "read NETBOX_VERIFY_SSL env var" — the
        # natural default. Production passes through the runner which has
        # already parsed the env Mapping; standalone tests / direct
        # construction also work via the env-var fallback path.
        if verify_ssl is None:
            verify_ssl = _parse_netbox_verify_ssl_env()
        self.url = url
        self.token = token
        self.filter_expr = filter_expr
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._api = pynetbox.api(url, token=token)
        # pynetbox 7.x accepts a custom http_session for connection pooling
        # and timeout; we set the timeout directly on the underlying
        # requests session if available so both connect and read are bounded.
        try:
            self._api.http_session.timeout = timeout  # type: ignore[attr-defined]
        except Exception:
            # Older pynetbox or non-standard session — non-fatal; pynetbox
            # will use its own defaults.
            pass
        # Wire SSL-verify into the requests session. requests.Session.verify
        # propagates to all subsequent requests pynetbox makes via this
        # session, so this single assignment covers every endpoint.
        try:
            self._api.http_session.verify = verify_ssl  # type: ignore[attr-defined]
        except Exception:
            pass
        if not verify_ssl:
            # Without this, urllib3 emits one InsecureRequestWarning per
            # request — instant log spam in any environment hitting a
            # self-signed cert. Disable just the InsecureRequestWarning
            # category so other urllib3 warnings (DNS, version mismatches)
            # still surface.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            log.warning(
                {
                    "event": "netbox_ssl_verification_disabled",
                    "url": url,
                    "note": (
                        "TLS verification disabled for NetBox API. "
                        "Only safe for lab environments with self-signed "
                        "certificates. NEVER use in production."
                    ),
                }
            )

    def fetch_hosts(self) -> list[DiscoveredHost]:
        """Query NetBox using the configured filter; return ordered
        DiscoveredHost list. Devices that can't be resolved to a
        hostname are skipped (logged at info level).

        Raises NetBoxSyncError on any pynetbox/network/parse failure.
        """
        try:
            filter_kwargs = _parse_filter_expr(self.filter_expr)
        except Exception as e:
            raise NetBoxSyncError(
                f"could not parse NETBOX_FILTER {self.filter_expr!r}: {e}",
                original_error=e,
            ) from e

        log.info(
            {
                "event": "netbox_fetch_starting",
                "url": self.url,
                "filter": self.filter_expr,
            }
        )
        try:
            devices = list(self._api.dcim.devices.filter(**filter_kwargs))
        except RequestError as e:
            raise NetBoxSyncError(
                f"NetBox API request failed: {e}", original_error=e
            ) from e
        except ContentError as e:
            raise NetBoxSyncError(
                f"NetBox returned unparseable content: {e}", original_error=e
            ) from e
        except Exception as e:
            # pynetbox can also leak underlying requests exceptions
            # (Timeout, ConnectionError, etc.). Surface them all as
            # NetBoxSyncError so the caller has one type to catch.
            raise NetBoxSyncError(
                f"NetBox query failed ({type(e).__name__}): {e}",
                original_error=e,
            ) from e

        hosts: list[DiscoveredHost] = []
        skipped = 0
        for d in devices:
            host = _device_to_discovered_host(d)
            if host is None:
                skipped += 1
                continue
            hosts.append(host)

        log.info(
            {
                "event": "netbox_fetch_complete",
                "fetched_count": len(devices),
                "host_count": len(hosts),
                "skipped_count": skipped,
            }
        )
        return hosts


# ---- internal helpers ------------------------------------------------


def _parse_filter_expr(expr: str) -> dict:
    """Parse NETBOX_FILTER into kwargs for pynetbox's filter().

    Single-value keys → scalar; multi-value keys (tag=a&tag=b) → list.
    Empty expression → empty dict (matches all devices)."""
    if not expr or not expr.strip():
        return {}
    parsed = parse_qs(expr, keep_blank_values=False)
    out: dict = {}
    for k, vs in parsed.items():
        out[k] = vs[0] if len(vs) == 1 else vs
    return out


def _device_to_discovered_host(d) -> Optional[DiscoveredHost]:
    """Map a pynetbox Device record to DiscoveredHost. Return None if
    the device can't be resolved to a hostname."""
    device_id = _safe_int(getattr(d, "id", None))
    if device_id is None:
        log.info(
            {
                "event": "netbox_device_skipped_no_id",
                "device": getattr(d, "name", None),
            }
        )
        return None

    hostname = _resolve_hostname(d)
    if not hostname:
        log.info(
            {
                "event": "netbox_device_skipped_no_hostname",
                "device_id": device_id,
                "device_name": getattr(d, "name", None),
            }
        )
        return None

    port = _resolve_port(d, device_id)
    display = _resolve_display_name(d)
    tags = _resolve_tags(d)

    return DiscoveredHost(
        netbox_device_id=device_id,
        hostname=hostname,
        port=port,
        display_name=display,
        tags=tags,
    )


def _resolve_hostname(d) -> Optional[str]:
    for attr in ("primary_ip4", "primary_ip6"):
        ip_obj = getattr(d, attr, None)
        if ip_obj is None:
            continue
        addr = getattr(ip_obj, "address", None)
        if not addr:
            continue
        # Strip CIDR notation: "10.1.2.3/24" → "10.1.2.3"
        return str(addr).split("/", 1)[0].strip()

    name = getattr(d, "name", None)
    if name and isinstance(name, str) and name.strip():
        return name.strip()
    return None


def _resolve_port(d, device_id: int) -> int:
    cf = getattr(d, "custom_fields", None) or {}
    raw = cf.get("cert_check_port") if isinstance(cf, dict) else None
    if raw is None:
        return 443
    port = _safe_int(raw)
    if port is None:
        log.warning(
            {
                "event": "netbox_invalid_cert_check_port_using_default",
                "device_id": device_id,
                "raw_value": raw,
            }
        )
        return 443
    return port


def _resolve_display_name(d) -> Optional[str]:
    name = getattr(d, "name", None)
    if isinstance(name, str) and name.strip():
        return name.strip()
    return None


def _resolve_tags(d) -> list[str]:
    raw_tags = getattr(d, "tags", None) or []
    out: list[str] = []
    for t in raw_tags:
        n = getattr(t, "name", None)
        if isinstance(n, str) and n.strip():
            out.append(n.strip())
    return out


def _safe_int(value) -> Optional[int]:
    if isinstance(value, bool):  # bool is a subclass of int — exclude
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None
