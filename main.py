"""katoDoS 桌面入口

用系统 Edge WebView2 在原生窗口里渲染网页 UI，不是浏览器标签页。
后端是 Python 内核（VFS + 统一 Shell + katoASM/katoC）。
"""

import sys
import os
import tempfile
import shutil
from pathlib import Path

# 让未激活 venv 的 Python 也能找到已安装的包
VENV_SITE = Path(r"C:\Users\Administrator\.workbuddy\binaries\python\envs\default\Lib\site-packages")
if str(VENV_SITE) not in sys.path:
    sys.path.insert(0, str(VENV_SITE))

import base64
import json
import webview
from vfs import VFS
from kernel import Shell
from machine import Machine

# PyInstaller 单文件运行时资源路径
if getattr(sys, "frozen", False):
    BASE = Path(sys._MEIPASS)
else:
    BASE = Path(__file__).parent.resolve()

ASSETS = BASE / "assets"
window = None


class Api:
    def __init__(self):
        self.vfs = VFS()
        self.shell = Shell(self.vfs, self._printer)
        self.out = []
        self.bios = self._load_bios()
        # 不自动恢复快照：关闭进程再打开 = 一台全新的电脑（默认状态）。
        # 用户可手动用 SAVE / LOAD 管理快照。

    # ---------------- BIOS 设置（会话内持久，可写盘） ----------------
    def _bios_path(self):
        try:
            d = Path(os.path.expanduser("~")) / ".katodos"
            d.mkdir(parents=True, exist_ok=True)
            return d / "bios.json"
        except Exception:
            return None

    def _default_bios(self):
        return {
            "boot_order": "C: A: D:",
            "xms": "Auto",
            "threads": "Auto",
            "sound": True,
            "network": True,
            "mouse": True,
            "quickboot": True,
        }

    def _load_bios(self):
        default = self._default_bios()
        p = self._bios_path()
        if p and p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                default.update(data)
            except Exception:
                pass
        return default

    def _save_bios(self, bios):
        p = self._bios_path()
        if p:
            try:
                p.write_text(json.dumps(bios, ensure_ascii=False), encoding="utf-8")
            except Exception:
                pass

    def getBios(self):
        return dict(self.bios)

    def setBios(self, bios):
        if isinstance(bios, dict):
            self.bios.update(bios)
            self._save_bios(self.bios)
        return dict(self.bios)

    def _printer(self, text, kind):
        self.out.append({"kind": kind, "text": text})

    def _critical_file_missing(self):
        for name in ["IO.SYS", "MSDOS.SYS", "COMMAND.COM"]:
            if not self.vfs.is_file(("C", [name])):
                return name
        return None

    def boot(self):
        # 每次开机（含 REBOOT）重置运行时内存映射：新一次自检，内存重新分配
        self.shell.reset_runtime()
        logo = ASSETS / "bootlogo.png"
        img = ""
        if logo.exists():
            with open(logo, "rb") as f:
                img = "data:image/png;base64," + base64.b64encode(f.read()).decode("ascii")
        machine = Machine(bios=self.bios, fail_chance=0.12)
        # 让内核使用与本次 POST 同一份 Machine（含 BIOS 设置决定的扩展内存大小）
        self.shell.machine = machine
        # 应用 BIOS 设备开关：关闭的板载设备加入 kernel 禁用集合
        self.shell.bios_disabled = set()
        if not self.bios.get("network", True):
            self.shell.bios_disabled.add("network")
        if not self.bios.get("sound", True):
            self.shell.bios_disabled.add("sound")
        if not self.bios.get("mouse", True):
            self.shell.bios_disabled.add("mouse")
        if not self.bios.get("keyboard", True):
            self.shell.bios_disabled.add("keyboard")
        # 检测并自动挂载 U 盘（只读沙箱镜像；无 U 盘则为空列表）
        usb = self.vfs.auto_mount_usb()
        missing = self._critical_file_missing()
        if missing:
            failure = (
                "Non-System disk or disk error",
                [
                    "Non-System disk or disk error",
                    "",
                    "Replace and press any key when ready",
                    "",
                    "(缺失系统文件: %s)" % missing,
                ],
                False,
            )
        else:
            failure = machine.boot_failure()
        return {
            "image": img,
            "header": machine.post_header(),
            "mem_total_k": machine.ram_total_k,
            "footer": machine.post_footer(self.vfs),
            "failure": failure,
            "cpu": machine.cpu_str(),
            "ram_mb": machine.ram_total_k // 1024,
            "usb": usb,
        }

    def execute(self, line):
        self.out = []
        self.shell.execute(line)
        return {"lines": self.out, "prompt": self.shell.prompt_str()}

    def displayMode(self):
        """返回当前显示模式：VGA.DRV 存在则正常，缺失则故障（前端据此渲染 glitch）。"""
        ok = self.vfs.is_file(("C", ["DRIVERS", "VGA.DRV"]))
        return {"mode": "vga-ok" if ok else "vga-broken"}

    def free_game(self):
        """前端游戏退出时调用，释放该游戏占用的内存。"""
        self.shell.free_game()
        return True

    def readFile(self, path):
        ref = self.shell.resolve(path or ".")
        if ref and self.vfs.is_file(ref):
            return self.vfs.read_file(ref) or ""
        return ""

    def writeFile(self, path, content):
        ref = self.shell.resolve(path or ".")
        if ref:
            return self.vfs.write_file(ref, content)
        return False

    def import_file(self, host_path=None):
        """从宿主机只读导入文件到 VM 沙箱 C:\\IMPORT。
        所有操作限制在沙箱内部：只读取宿主文件、复制进 VM，绝不回写宿主机。
        返回 {ok, files:[{name,size,vmpath}], error}。"""
        files = []
        try:
            if host_path:
                paths = [host_path]
            else:
                dlg = webview.windows[0].create_file_dialog(
                    webview.OPEN_DIALOG, allow_multiple=True)
                paths = dlg or []
        except Exception as e:
            return {"ok": False, "error": "打开文件对话框失败: %s" % e}
        for p in paths:
            try:
                with open(p, "rb") as f:
                    data = f.read()
            except Exception as e:
                return {"ok": False, "error": "无法读取 %s: %s" % (p, e)}
            name = os.path.basename(p)
            ref = ("C", ["IMPORT", name])
            # 字节级保真：用 latin-1 编码存为字符串，避免破坏二进制
            if not self.vfs.write_file(ref, data.decode("latin-1")):
                return {"ok": False, "error": "写入 VM 失败: %s" % name}
            files.append({"name": name, "size": len(data), "vmpath": "C:\\IMPORT\\" + name})
        return {"ok": True, "files": files}

    def exit(self):
        # 退出时清理临时缓存文件
        try:
            cache_dir = os.path.join(tempfile.gettempdir(), "katodos")
            if os.path.isdir(cache_dir):
                shutil.rmtree(cache_dir, ignore_errors=True)
        except Exception:
            pass
        global window
        if window is not None:
            window.destroy()


def main():
    global window
    api = Api()
    window = webview.create_window(
        "katoDoS",
        url=str(ASSETS / "term.html"),
        js_api=api,
        width=1024,
        height=768,
        resizable=True,
        text_select=True,
        min_size=(800, 600),
    )
    webview.start()


if __name__ == "__main__":
    main()
