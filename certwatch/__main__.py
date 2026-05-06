"""CLI entry.

Two subcommands:
  - local : Phase 3 — run cert checks against a YAML host list (no dashboard)
  - agent : Phase 5 — dashboard-connected agent. Bare `agent` runs the
            full runner (Phase 5f); `agent --dry-run` bootstraps then
            exits (Phase 5a behavior, useful for in-field diagnostics).
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from certwatch._version import __version__
from certwatch.bootstrap import BootstrapError, bootstrap
from certwatch.check_loop import StopSignal, install_signal_handlers, run_loop
from certwatch.config import load_config
from certwatch.logging_setup import configure_logging


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="certwatch")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    local = sub.add_parser(
        "local",
        help="Run the local check loop against a YAML config (no dashboard).",
    )
    local.add_argument("--config", required=True, help="Path to config.yaml")

    agent = sub.add_parser(
        "agent",
        help="Run the dashboard-connected agent (env-driven configuration).",
    )
    agent.add_argument(
        "--data-dir",
        default="/data",
        help="Directory for agent.json and pending_reports/ (default: /data).",
    )
    agent.add_argument(
        "--dry-run",
        action="store_true",
        help="Bootstrap (load or register credentials, fetch initial config), "
        "then exit before starting any loops. Useful for validating env vars "
        "and dashboard reachability in the field.",
    )

    args = parser.parse_args(argv)

    if args.cmd == "local":
        return _run_local(args)
    if args.cmd == "agent":
        return _run_agent(args)
    return 1


def _run_local(args) -> int:
    config = load_config(args.config)
    log_level = os.environ.get("LOG_LEVEL", config.log_level)
    configure_logging(log_level)
    stop = StopSignal()
    install_signal_handlers(stop)
    run_loop(config, stop=stop)
    return 0


def _run_agent(args) -> int:
    log_level = os.environ.get("LOG_LEVEL", "INFO")
    configure_logging(log_level)
    log = logging.getLogger("certwatch")

    if args.dry_run:
        # Diagnostic bootstrap then exit — Phase 5a behavior preserved.
        log.info(
            {
                "event": "agent_dry_run_starting",
                "agent_version": __version__,
                "data_dir": args.data_dir,
            }
        )
        try:
            result = bootstrap(env=os.environ, data_dir=args.data_dir)
        except BootstrapError as e:
            log.error({"event": "bootstrap_failed", "error": str(e)})
            return 2
        log.info(
            {
                "event": "bootstrap_complete",
                "agent_id": result.agent_id,
                "dashboard_url": result.dashboard_url,
                "config_version": result.initial_config.get("config_version"),
                "manual_hosts_count": len(
                    result.initial_config.get("manual_hosts", []) or []
                ),
            }
        )
        log.info({"event": "dry_run_complete"})
        return 0

    # Full runner — Phase 5f. The runner handles bootstrap itself with
    # the same logging, so we don't pre-bootstrap here.
    from certwatch.runner import AgentRunner

    runner = AgentRunner(env=os.environ, data_dir=args.data_dir)
    return runner.run()


if __name__ == "__main__":
    sys.exit(main())
