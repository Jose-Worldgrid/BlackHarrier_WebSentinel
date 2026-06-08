# Modulo lanzador para iniciar Streamlit con parametros estables en este entorno.

"""Safe Streamlit launcher for Windows + Python 3.14 WMI issue.

This monkeypatches platform.system() very early so Streamlit does not
trigger platform.uname()/WMI during import on affected environments.
"""

import os
import platform
import sys


def _safe_platform_system():


    return "Windows"


platform.system = _safe_platform_system


def _safe_win32_ver(*_args, **_kwargs):
    return ("Windows", "", "", "")


platform.win32_ver = _safe_win32_ver


os.environ.setdefault("STREAMLIT_SERVER_FILE_WATCHER_TYPE", "none")
os.environ.setdefault("STREAMLIT_SERVER_RUN_ON_SAVE", "false")

from streamlit.web.cli import main


if __name__ == "__main__":

    if len(sys.argv) == 1:
        sys.argv = ["streamlit", "run", "app.py"]
    elif len(sys.argv) >= 2 and sys.argv[1] != "run":

        sys.argv = ["streamlit", *sys.argv[1:]]
    else:
        sys.argv = ["streamlit", *sys.argv[1:]]

    raise SystemExit(main())
