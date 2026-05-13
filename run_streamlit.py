"""Safe Streamlit launcher for Windows + Python 3.14 WMI issue.

This monkeypatches platform.system() very early so Streamlit does not
trigger platform.uname()/WMI during import on affected environments.
"""

import os
import platform
import sys


_original_platform_system = platform.system


def _safe_platform_system():
    try:
        return _original_platform_system()
    except Exception:
        # Streamlit only needs coarse OS detection here.
        return "Windows"


platform.system = _safe_platform_system

# Optional: make startup behavior deterministic for this workspace.
os.environ.setdefault("STREAMLIT_SERVER_FILE_WATCHER_TYPE", "none")
os.environ.setdefault("STREAMLIT_SERVER_RUN_ON_SAVE", "false")

from streamlit.web.cli import main


if __name__ == "__main__":
    # Behave like: streamlit run app.py
    if len(sys.argv) == 1:
        sys.argv = ["streamlit", "run", "app.py"]
    elif len(sys.argv) >= 2 and sys.argv[1] != "run":
        # Allow custom subcommands, e.g. --version, hello, etc.
        sys.argv = ["streamlit", *sys.argv[1:]]
    else:
        sys.argv = ["streamlit", *sys.argv[1:]]

    raise SystemExit(main())
