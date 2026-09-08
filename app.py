#!/usr/bin/env python3
"""Start EVulnTasker. After the venv is active:

    python3 -m venv venv && source venv/bin/activate
    python3 app.py
"""

from __future__ import annotations

import importlib.util
import os
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _load_app_package() -> None:
    """Load the app/ package even though this launcher is named app.py."""
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    sys.modules.pop("app", None)
    init_py = ROOT / "app" / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        "app",
        init_py,
        submodule_search_locations=[str(ROOT / "app")],
    )
    if spec is None or spec.loader is None:
        sys.stderr.write("Cannot load the app/ package. Is app/__init__.py present?\n")
        sys.exit(1)
    module = importlib.util.module_from_spec(spec)
    sys.modules["app"] = module
    spec.loader.exec_module(module)


def _lan_ip() -> str | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        return None
    return None


def main() -> None:
    if sys.version_info < (3, 11):
        sys.stderr.write(
            "EVulnTasker requires Python 3.11+ inside the venv.\n"
            "On RHEL create the venv with python3.11, then the same commands work:\n"
            "  python3.11 -m venv venv && source venv/bin/activate\n"
            "  pip install -r requirements.txt\n"
            "  python3 app.py\n"
        )
        sys.exit(1)

    _load_app_package()

    import uvicorn

    from app.config import get_settings

    settings = get_settings()
    host = settings.host
    port = settings.port

    print(" * Serving Flask app 'app'")
    print(f" * Environment: {settings.env}")
    print(" * Debug mode: off")
    print(f" * Running on all addresses ({host})")
    print(f" * Running on http://127.0.0.1:{port}")
    lan = _lan_ip()
    if lan:
        print(f" * Running on http://{lan}:{port}")
    print("Press CTRL+C to quit")

    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        log_level=settings.log_level.lower(),
        reload=False,
    )


if __name__ == "__main__":
    main()
