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
        default="0.0.0.0",
        help="Server host address (default: 0.0.0.0).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Server HTTP port (default: 8080).",
    )
    args = parser.parse_args()

    server = ControlPlaneServer(host=args.host, port=args.port)
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n* Control Plane Server stopped by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
