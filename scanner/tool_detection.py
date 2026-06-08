# Modulo de escaneo y analisis para tool detection.

import os
import shutil


def _tool_env_var_names(tool_name: str):
    base = str(tool_name or "").strip().upper().replace("-", "_")
    return [f"{base}_PATH", f"PD_{base}_PATH"]


def _windows_tool_candidates(tool_name: str):
    exe_name = f"{tool_name}.exe"
    user_profile = os.getenv("USERPROFILE", "")
    local_app_data = os.getenv("LOCALAPPDATA", "")
    program_files = os.getenv("ProgramFiles", r"C:\Program Files")
    candidates = [
        os.path.join(user_profile, "go", "bin", exe_name),
        os.path.join(user_profile, "scoop", "shims", exe_name),
        os.path.join(local_app_data, "Microsoft", "WinGet", "Links", exe_name),
        os.path.join(local_app_data, "Programs", tool_name, exe_name),
        os.path.join(program_files, tool_name, exe_name),
        os.path.join(r"C:\tools", tool_name, exe_name),
    ]
    return [p for p in candidates if p]


def resolve_binary(tool_name: str, explicit_candidates=None):
    explicit_candidates = list(explicit_candidates or [])
    tool_name = str(tool_name or "").strip()
    if not tool_name:
        return "", ""

    for env_var in _tool_env_var_names(tool_name):
        env_value = str(os.getenv(env_var, "") or "").strip().strip('"')
        if env_value and os.path.isfile(env_value):
            return env_value, env_var

    for candidate in [tool_name, f"{tool_name}.exe"]:
        found = shutil.which(candidate)
        if found:
            return found, "PATH"

    for candidate in explicit_candidates + _windows_tool_candidates(tool_name):
        text = str(candidate or "").strip().strip('"')
        if text and os.path.isfile(text):
            return text, "fallback"

    return "", ""


def detect_external_web_tools():
    tools = {}
    for tool_name, candidates in {
        "katana": [r"C:\Program Files\katana\katana.exe"],
        "httpx": [r"C:\Program Files\httpx\httpx.exe"],
        "nuclei": [r"C:\Program Files\nuclei\nuclei.exe"],
    }.items():
        path, source = resolve_binary(tool_name, explicit_candidates=candidates)
        tools[tool_name] = {
            "available": bool(path),
            "path": path,
            "source": source,
        }
    return tools
