#!/usr/bin/env python3
"""
Cyber Incident Timeline Generator & Forensic Hub
Unified Server Runner
"""

import sys
import os
import socket
from pathlib import Path
import uvicorn

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from backend.database import init_db


def find_available_port(host: str = "127.0.0.1", preferred_port: int = 8000) -> int:
    port = preferred_port
    while port <= 65535:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
                return port
            except OSError:
                port += 1
    raise RuntimeError("No free port available in the 8000-65535 range.")


def main():
    print("=" * 70)
    print("      CYBER INCIDENT TIMELINE GENERATOR & FORENSIC INVESTIGATION HUB")
    print("=" * 70)
    print("Initializing Database and Schema...")
    init_db()
    print("Database ready.")

    host = os.environ.get("HOST", "0.0.0.0")
    configured_port = os.environ.get("PORT")
    if configured_port:
        port = int(configured_port)
    else:
        preferred_port = 8000
        port = find_available_port(host, preferred_port)
        if port != preferred_port:
            print(f"[!] Port {preferred_port} is busy; using free port {port} instead.")

    print(f"\n[+] Private Web Application URL: http://{host}:{port}")
    print(f"[+] API Documentation:           http://{host}:{port}/docs")
    print(f"[+] Health Endpoint:             http://{host}:{port}/api/health")
    print("\nPress Ctrl+C to stop the server.\n" + "=" * 70)

    uvicorn.run("backend.main:app", host=host, port=port, reload=False, log_level="info")

if __name__ == "__main__":
    main()
