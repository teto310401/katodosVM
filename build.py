from pathlib import Path
import os
import subprocess
import sys

ROOT = Path(__file__).parent.resolve()
VENV_SITE = Path(r"C:\Users\Administrator\.workbuddy\binaries\python\envs\default\Lib\site-packages")
PYTHON = Path(r"C:\Users\Administrator\.workbuddy\binaries\python\versions\3.13.12\python.exe")

cmd = [
    str(PYTHON), "-m", "PyInstaller",
    "main.py",
    "--onefile", "--windowed",
    "--name", "katodos",
    "--icon", "assets/icon.ico",
    "--add-data", "assets;assets",
    "--hidden-import", "clr",
    "--hidden-import", "clr_loader",
    "--hidden-import", "pythonnet",
    "--hidden-import", "webview",
    "--hidden-import", "webview.platforms.edgechromium",
    "--hidden-import", "webview.platforms.mshtml",
    "--hidden-import", "asm",
    "--hidden-import", "cinterp",
    "--hidden-import", "vfs",
    "--hidden-import", "kernel",
    "--hidden-import", "machine",
    "--hidden-import", "PIL",
    "--exclude-module", "setuptools",
    "--collect-all", "pythonnet",
    "--collect-all", "clr_loader",
    "--collect-all", "webview",
]

home = os.environ.get("USERPROFILE") or os.environ.get("HOME") or r"C:\Users\Administrator"
# IMPORTANT: never pass a fresh dict as env — that wipes PATH and breaks
# PyInstaller's ctypes scanning (KeyError: 'PATH'). Always copy os.environ.
env = os.environ.copy()
env["PYTHONPATH"] = str(VENV_SITE)
env["USERPROFILE"] = home
env["HOME"] = home
env.setdefault("PATH", r"C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem")
print("打包命令:", " ".join(cmd))
subprocess.run(cmd, cwd=ROOT, env=env, check=True)
print("完成: dist/katodos.exe")
