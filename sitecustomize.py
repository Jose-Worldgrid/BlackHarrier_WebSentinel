import os
import platform


if os.name == "nt":
    # Python 3.14 on some Windows setups can block in WMI during
    # platform.system()/platform.win32_ver(), and Streamlit imports this very early.
    platform.system = lambda: "Windows"  # type: ignore[assignment]
    platform.win32_ver = lambda *args, **kwargs: ("Windows", "", "", "")  # type: ignore[assignment]
