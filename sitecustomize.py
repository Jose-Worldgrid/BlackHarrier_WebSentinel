# Modulo de ajustes de entorno Python para mejorar compatibilidad en Windows.

import os
import platform


if os.name == "nt":


    platform.system = lambda: "Windows"
    platform.win32_ver = lambda *args, **kwargs: ("Windows", "", "", "")
