# CertWatch Agent

Python container that monitors SSL/TLS certificates from inside a lab
network and reports to a [CertWatch](https://certwatch.lovable.app)
dashboard.

The agent runs as a pure outbound client: it initiates connections to
your dashboard over HTTPS, never accepts inbound connections, and uses
a bearer-token credential issued during one-time registration. Cert
checks happen from the agent's network position, so it sees what
clients in that network actually see.

## Quick start

```bash
docker run -d \
  --name certwatch-agent \
  --restart unless-stopped \
  -v certwatch-data:/data \
  -e DASHBOARD_URL=https://your-certwatch.example.com \
  -e REGISTRATION_TOKEN=regtok_xxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  ghcr.io/your-org/certwatch-agent:latest
```

After the agent registers, it persists credentials to
`/data/agent.json` and won't need `REGISTRATION_TOKEN` again. Restarts
are automatic via `--restart unless-stopped`.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `DASHBOARD_URL` | always | Base URL of the dashboard, e.g. `https://certwatch.lovable.app` |
| `REGISTRATION_TOKEN` | first run only | One-time `regtok_…` from the dashboard's "add agent" UI. Ignored once `/data/agent.json` exists. |
| `NETBOX_URL` | optional | If set, enables NetBox sync. Half-configured NetBox state (URL set, token or filter missing) fails fast at startup. |
| `NETBOX_TOKEN` | with NETBOX_URL | NetBox API token. |
| `NETBOX_FILTER` | with NETBOX_URL | pynetbox filter expression, e.g. `tag=monitor-cert`. |
| `NETBOX_VERIFY_SSL` | optional | `true` or `false` (case-insensitive; `1`/`0` and `yes`/`no` also accepted). Default: `true`. Set to `false` only for lab NetBox instances using self-signed certs. **Bypassing verification is insecure for production.** When disabled, the agent emits one `netbox_ssl_verification_disabled` WARNING log at startup as an audit trail. |
| `LOG_LEVEL` | optional | `DEBUG` / `INFO` / `WARNING` / `ERROR`. Default `INFO`. `DEBUG` includes full SAN arrays in cert-check log lines. |
| `AGENT_HOSTNAME` | optional | Overrides `socket.gethostname()` for register and heartbeat. Useful when container hostnames are random container IDs. |
| `INTERNAL_CA_PATTERNS` | optional | Comma-separated case-insensitive substrings that match an internal CA's DN. Replaces the default list (`kurmi`, `internal`, `lab ca`, `corporate ca`, `intermediate ca`). Empty string disables internal-CA detection. |
| `API_PATH_PREFIX` | optional | API path prefix used when calling the dashboard. Default: `/api/public/v1` (matches Lovable's runtime convention — non-`/api/public/*` paths get gated behind dashboard JWT auth that the agent doesn't have). Set to `/api/v1` if deploying against a dashboard on a different platform. Trailing slashes are stripped. |

## /data directory layout

After registration, the volume looks like:

```
/data/
├── agent.json                # mode 0600
│   {
│     "agent_id":      "<UUID v4>",
│     "agent_secret":  "agtkey_<base64url>",
│     "dashboard_url": "https://...",
│     "registered_at": "2026-...Z"
│   }
└── pending_reports/          # at-least-once delivery queue
    ├── <report_id>.json      # mode 0600; includes _persisted_at and _attempts metadata
    └── corrupt/              # quarantined files for operator inspection
        └── <report_id>.json.<timestamp>
```

The `/data` volume **must** persist across container restarts. Use a
named volume (`-v certwatch-data:/data`) or a bind mount. Without
persistence, the agent loses its identity on every restart and
re-registers, which the dashboard sees as a brand-new agent each time.

`pending_reports/` is the at-least-once delivery queue. Each cycle's
report is atomically written here before any network attempt; the file
is removed once the dashboard has it (200) or has-already-had it (409).
On agent restart, leftover files are submitted before any new cycle runs.

## Logs

Structured JSON, one event per line, on stdout:

```bash
docker logs -f certwatch-agent
```

Pipe to `jq` for readability while debugging:

```bash
docker logs certwatch-agent -f | jq .
```

Filter by event type:

```bash
docker logs certwatch-agent | jq 'select(.event == "check_cycle_summary")'
```

### Common events

| Lifecycle phase | Events |
|---|---|
| Startup | `agent_starting`, `bootstrap_complete`, `agent_starting_threads`, `agent_running` |
| Heartbeat | `heartbeat_thread_starting`, `heartbeat_thread_exiting`, `heartbeat_validation_error` (rare), `heartbeat_retriable_error` |
| Cert checks | `check_cycle_starting`, `check_cycle_summary`, `cert_check_result` |
| Reports | `report_delivered`, `report_already_received`, `report_rejected_validation`, `report_submission_retry` |
| Actions | `action_handler_starting`, `action_handler_completed`, `action_unknown_type_skipped`, `action_skipped_expired_at_pickup` |
| NetBox | `netbox_configured` / `netbox_not_configured`, `netbox_sync_complete`, `netbox_sync_netbox_error_preserving_state` |
| Shutdown | `signal_received`, `agent_shutdown_signaled`, `shutdown_complete` |
| Auth (terminal) | `heartbeat_auth_error_shutting_down`, `check_cycle_auth_error_shutting_down`, `action_handler_auth_error_shutdown_signaled` |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean shutdown via SIGTERM/SIGINT |
| 1 | Bootstrap failure (missing env var, invalid registration token, code bug) |
| 2 | Agent revoked or credentials rejected during operation |

Use these in a process supervisor / orchestrator's restart policy:
restart on 0 (heartbeat may have been blipped) and 1 (transient env
issue), do NOT restart on 2 (operator action required).

## Diagnostics: `--dry-run`

```bash
docker run --rm \
  -v certwatch-data:/data \
  -e DASHBOARD_URL=https://your-certwatch.example.com \
  -e REGISTRATION_TOKEN=regtok_… \
  ghcr.io/your-org/certwatch-agent:latest --dry-run
```

Bootstraps (register or load credentials, fetch initial config), then
exits cleanly. Useful for validating env vars and dashboard
reachability in the field without running the full loops.

## Revoking and redeploying an agent

If an agent's credentials are compromised or the agent should be
permanently removed:

1. **On the dashboard**: click *Revoke* on the agent's detail page.
   The `agent_secret` is invalidated server-side.
2. **In logs**: the next heartbeat or report submission gets a 401,
   the agent logs `*_auth_error_shutting_down` and shuts itself down
   with exit code 2.
3. **On the host**:
   ```bash
   docker stop certwatch-agent && docker rm certwatch-agent
   ```
4. **Optional, only if you don't want to reinstate the agent**:
   `docker volume rm certwatch-data`. This deletes the persisted
   identity. Skip this step if you want to redeploy with the same
   agent — the volume preserves `agent.json` across restarts.

### Redeploy as the SAME agent

Skip step 4. Use the same volume. Credentials are preserved.

```bash
docker run -d \
  --name certwatch-agent \
  --restart unless-stopped \
  -v certwatch-data:/data \
  -e DASHBOARD_URL=https://your-certwatch.example.com \
  ghcr.io/your-org/certwatch-agent:latest
# REGISTRATION_TOKEN is not needed — agent loads creds from /data/agent.json
```

This only works if the agent has not been revoked. Once revoked, the
secret is dead and you must register again.

### Redeploy as a NEW agent

Revoke the old agent → delete the volume → generate a fresh
registration token → run with that token.

## Updating the agent image

```bash
docker pull ghcr.io/your-org/certwatch-agent:latest
docker stop certwatch-agent && docker rm certwatch-agent
# Re-run the same `docker run` command — same env, same volume.
```

The volume preserves identity across upgrades. No re-registration.

## Local development

```bash
# Set up Python 3.11+ environment
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run the local YAML-driven mode (no dashboard)
python -m certwatch local --config example-config.yaml
```

### Test recipes

| Command | What it runs | Time |
|---|---|---|
| `pytest -m "not network and not e2e"` | offline unit tests only (CI default) | ~10s |
| `pytest -m "not e2e"` | unit + live badssl integration | ~25s |
| `pytest -m e2e` | end-to-end harness only (subprocess + mock servers) | ~40s |
| `pytest` | everything | ~70s |

The `network` marker covers the live badssl.com integration in
`tests/test_cert_check.py`. The `e2e` marker is auto-applied to
everything in `tests/e2e/` — those tests spawn the actual
`python -m certwatch agent` subprocess against a Flask-backed mock
dashboard and mock NetBox.

### Testing NetBox integration changes

The mock NetBox in `tests/e2e/mock_netbox.py` reproduces the API
surface (`GET /api/dcim/devices/`) but does not reproduce TLS
hostname-matching behavior on the targets the agent actually
cert-checks. Three production bugs in the NetBox path so far —
action-handler gap, cycle-iteration gap, and host-value-uses-IP TLS
mismatch — could not be reproduced by the mock harness alone because
the mock targets (`localhost`, `127.0.0.1`) don't have certs whose
CN/SAN fields are tested against the agent's chosen hostname string.

When changing how NetBox host fields flow through the cert-check
pipeline (especially anything that touches `_resolve_hostname`,
`_host_to_payload`, or the cycle's host-iteration order), verify
against a real NetBox with real-FQDN devices on a deployment host
before merging. The unit tests cover the field-extraction logic;
real-cert verification is a separate integration concern.

## Security notes

- `agent_secret` lives in `/data/agent.json` with mode `0600`. The
  agent runs as UID 10001 inside the container. Mount the volume with
  appropriately-restrictive host permissions if using a bind mount.
- Bearer tokens are sent only over HTTPS to `DASHBOARD_URL`. The agent
  never accepts inbound connections.
- The image runs as a non-root user with no shell. There's no `bash`,
  `sh`, or login capability beyond what `python -m certwatch agent`
  needs.
- Build tools (`gcc`, headers) are present only in the builder stage
  and don't ship in the runtime image.

## License

MIT
