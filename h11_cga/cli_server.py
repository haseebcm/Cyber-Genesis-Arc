"""
H¹¹-CGA Command Line Interface — Server Daemon Launcher
=========================================================

Command-line entry point (`h11-server`) to launch the Control Plane REST API Server
and embedded Web Dashboard daemon.
"""

from __future__ import annotations

import argparse
import sys

from h11_cga.server import ControlPlaneServer


def main() -> None:
    """CLI Server Daemon Entrypoint."""
    parser = argparse.ArgumentParser(
        description="H11-CGA Control Plane REST API & Web Dashboard Server Daemon."
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Server host address (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Server HTTP port (default: 8080).",
    )
    parser.add_argument("--demo", action="store_true", help="Enable isolated simulation controls; no host enforcement")
    parser.add_argument("--allow-pid", type=int, action="append", default=[], help="Explicitly permit real suspension of this PID (repeatable)")
    parser.add_argument("--audit-path", help="Durable SQLite response journal")
    parser.add_argument("--max-hold", type=float, default=30, help="Automatic rollback deadline, 1–300 seconds")
    parser.add_argument("--require-dimension", action="append", help="Dimension required for readiness (repeatable; default: eight host dimensions)")
    args = parser.parse_args()

    options = dict(host=args.host, port=args.port, demo=args.demo)
    if args.require_dimension:
        options["required_dimensions"] = args.require_dimension
    if args.allow_pid:
        options.update(allowed_pids=args.allow_pid, audit_path=args.audit_path, max_hold_seconds=args.max_hold)
    server = ControlPlaneServer(**options)
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n* Control Plane Server stopped by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
