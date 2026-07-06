"""
launcher.py -- plug-and-play bootstrapper for Icarus Un-follower.

Double-click "Start Icarus Unfollower.vbs" (or run this with pythonw) and it will:
  1. make sure frida + msgpack are installed (pip-installing them if not),
  2. open the Icarus Un-follower dashboard,
all without you touching a command prompt. Any problem is shown in a small
Windows dialog instead of a console you can't see.

This is the "I have Python but don't want to use cmd" path. For someone who
doesn't have Python at all, build the standalone exe instead (build_exe.bat).
"""

import importlib
import os
import subprocess
import sys

# import name -> pip install spec
REQUIRED = {
    "frida": "frida",
    "msgpack": "msgpack",
    "curl_cffi": "curl_cffi",
    "Crypto": "pycryptodome",
}


def _dialog(text, title="Icarus Un-follower", icon=0x40):
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, text, title, icon)
    except Exception:
        print(text)


def ensure_deps():
    missing = []
    for mod, spec in REQUIRED.items():
        try:
            importlib.import_module(mod)
        except ImportError:
            missing.append(spec)
    if not missing:
        return
    _dialog("First run: installing " + ", ".join(missing) +
            ".\nThis takes a minute; the app opens when it's done.",
            "Icarus Un-follower setup", 0x40)
    cmd = [sys.executable, "-m", "pip", "install", "--user", *missing]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            "Could not install dependencies automatically.\n\n"
            "Open a terminal in this folder and run:\n"
            "    pip install -r requirements.txt\n\n"
            + (proc.stderr or proc.stdout or "")[-800:])
    importlib.invalidate_caches()
    for p in (__import__("site").getusersitepackages(),):
        if p not in sys.path:
            sys.path.insert(0, p)


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    try:
        ensure_deps()
    except Exception as e:
        _dialog(str(e), "Icarus Un-follower setup failed", 0x10)
        return
    try:
        import unfollower_bot as app
        app.run_ui()
    except Exception as e:
        import traceback
        _dialog("Icarus Un-follower crashed on startup:\n\n" + "".join(
            traceback.format_exception(type(e), e, e.__traceback__))[-1500:],
            "Icarus Un-follower error", 0x10)


if __name__ == "__main__":
    main()
