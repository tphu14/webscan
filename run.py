#!/usr/bin/env python3
"""
run.py - Khởi động WebVulnScanner Dashboard Server

Usage:
    python run.py              # Default: localhost:8000
    python run.py --port 9000  # Custom port
    python run.py --reload     # Dev mode with auto-reload
"""
import sys, os, argparse, subprocess

def main():
    parser = argparse.ArgumentParser(description="WebVulnScanner Dashboard Server")
    parser.add_argument("--host",   default="127.0.0.1", help="Host (default: 127.0.0.1)")
    parser.add_argument("--port",   default=8000, type=int, help="Port (default: 8000)")
    parser.add_argument("--reload", action="store_true",   help="Auto-reload on file change")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════╗
║   WebVulnScanner Dashboard — Starting    ║
╚══════════════════════════════════════════╝

  Dashboard: http://{args.host}:{args.port}
  New Scan : http://{args.host}:{args.port}/scan
  History  : http://{args.host}:{args.port}/history
  API Docs : http://{args.host}:{args.port}/docs

  Press Ctrl+C to stop
""")

    cmd = [
        sys.executable, "-m", "uvicorn",
        "api.main:app",
        "--host", args.host,
        "--port", str(args.port),
    ]
    if args.reload:
        cmd.append("--reload")

    subprocess.run(cmd, cwd=os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    main()