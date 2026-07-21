"""katoDoS 内核：统一命令解释器

katoDoS 本身同时包含 MS-DOS / FreeDOS / Windows CMD / Windows PowerShell
多种命令格式，无需切换模式。所有命令只操作沙箱虚拟文件系统 (VFS)，
不触碰宿主机。
"""

import os
import re
import json
import socket
import subprocess
import datetime
from pathlib import Path
from typing import List, Optional, Tuple, Callable

from vfs import VFS, fmt_path, Ref
from machine import Machine

UNIFIED = {
    "label": "katoDoS",
    "banner": [
        "katoDoS 1.0 [Unified Shell]",
        "Copyright (C) kato. All rights reserved.",
        "",
        "本系统同时兼容 MS-DOS / FreeDOS / Windows CMD / PowerShell 命令语法。",
        "",
    ],
    "sysname": "katoDoS",
}

VOLUMES = {"C": "KATODOS", "D": "KATODOS_BOOT", "A": "", "Z": "NETHOME"}

# 各类“进程”在 DOS 中运行时占用的内存（单位 KB）。
# 游戏在运行期间占用、退出后释放；ASM/katoC 加载后作为驻留模块（重启才释放）；
# 网络命令与外部 .COM/.EXE 为瞬态占用（执行完即释放）。
PROCESS_COST = {
    "snake": 48, "guess": 40, "tetris": 80, "mines": 72, "matrix": 64,
    "win3": 128,
    "asm": 64, "c": 64, "bat": 32, "com": 40, "exe": 40,
    "ping": 24, "tracert": 24, "ipconfig": 24, "netstat": 24, "nslookup": 24,
}

# 系统文件分级：删这些会有不同后果
KERNEL_FILES = {"IO.SYS", "MSDOS.SYS"}          # DOS 内核，删除即崩溃
INTERPRETER_FILES = {"COMMAND.COM"}             # 命令解释器，删除即崩溃
# 系统盘（承载 IO.SYS 等的启动盘）。sys_transfer / FORMAT 以此为系统盘。
SYSTEM_DRIVE = "C"


def _now():
    return datetime.datetime.now()


def _fmt_date():
    d = _now()
    return "%02d-%02d-%02d" % (d.month, d.day, d.year % 100)


def _fmt_time():
    d = _now()
    return "%02d:%02d" % (d.hour, d.minute)


def _wildcard_match(name, pattern):
    pat = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.match(pat, name, re.IGNORECASE) is not None


class Shell:
    def __init__(self, vfs: VFS, printer: Callable[[str, str], None]):
        self.vfs = vfs
        self.print = printer
        self.drive = "C"
        self.segs: List[str] = []
        self.env = {
            "PATH": "C:\\DOS;C:\\UTIL;C:\\GAMES;C:\\IMPORT",
            "PROMPT": "$P$G",
            "COMSPEC": "C:\\COMMAND.COM",
            "TEMP": "C:\\TEMP",
            "USER": "HACKER",
            "OS": "katoDoS",
        }
        self.title = "katoDoS"
        self.color = "07"
        self.history: List[str] = []
        self.persist_cb = None
        self._batch_depth = 0
        self.machine = Machine()
        self.bios_disabled = set()  # BIOS 中关闭的板载设备 drv_type
        self.health = "ok"          # ok | crashed
        self.unbootable = False     # 系统盘已被格式化/系统文件缺失，重启不可引导
        self.crashed_msg = ""
        # 内存管理：已加载/运行的进程占用（name#seq -> KB）
        self.processes = {}
        self._proc_seq = 0
        self._active_game_key = None

    # ---------------- 快照 ----------------
    def snapshot_dir(self) -> Path:
        base = Path(__file__).parent / "disk" / "snapshots"
        base.mkdir(parents=True, exist_ok=True)
        return base

    def snapshot_path(self, name: str) -> Path:
        return self.snapshot_dir() / (name + ".json")

    def save_snapshot(self, name: str) -> None:
        path = self.snapshot_path(name)
        data = {
            "version": 1,
            "shell": {
                "drive": self.drive,
                "segs": self.segs,
                "env": self.env,
                "title": self.title,
                "color": self.color,
            },
            "vfs": json.loads(self.vfs.serialize()),
        }
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)

    def load_snapshot(self, name: str) -> bool:
        path = self.snapshot_path(name)
        if not path.exists():
            return False
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            sh = data.get("shell", {})
            self.drive = sh.get("drive", "C")
            self.segs = sh.get("segs", [])
            self.env = sh.get("env", self.env)
            self.title = sh.get("title", "katoDoS")
            self.color = sh.get("color", "07")
            self.vfs.drives = json.loads(json.dumps(data.get("vfs", {}).get("drives", {})))
            return True
        except Exception as e:
            self.print("读档失败: %s" % e, "err")
            return False

    # ---------------- 路径 / 提示符 ----------------
    def cwd(self) -> Ref:
        return (self.drive, list(self.segs))

    def resolve(self, path: str) -> Optional[Ref]:
        return self.vfs.resolve(path, self.drive, self.segs)

    def expand_vars(self, text: str) -> str:
        # 同时支持 %VAR% 和 $env:VAR / ${env:VAR}
        def repl_perc(m):
            return self.env.get(m.group(1).upper(), "")
        text = re.sub(r"%([A-Za-z0-9_]+)%", repl_perc, text)
        def repl_env(m):
            return self.env.get(m.group(1).upper(), "")
        text = re.sub(r"\$\{?env:([A-Za-z0-9_]+)\}?", repl_env, text)
        return text

    def expand_prompt(self, fmt: str) -> str:
        d = _now()
        p = (lambda x: str(x).zfill(2))
        return (fmt
                .replace("$P", fmt_path(self.cwd()))
                .replace("$G", ">")
                .replace("$L", "<")
                .replace("$N", self.drive)
                .replace("$D", "%02d/%02d/%04d" % (d.month, d.day, d.year))
                .replace("$T", "%02d:%02d:%02d" % (d.hour, d.minute, d.second))
                .replace("$V", "katoDoS 1.0")
                .replace("$$", "$")
                .replace("$H", ""))

    def prompt_str(self) -> str:
        return self.expand_prompt(self.env.get("PROMPT", "$P$G")).rstrip()

    def banner(self) -> None:
        for line in UNIFIED["banner"]:
            self.print(line, "accent")
        self.print("%s  [C:\\] 提示符就绪。" % UNIFIED["label"], "dim")

    def _has_driver(self, drv_type: str) -> bool:
        """检查指定类型驱动是否还存在于 DRIVERS 目录且未被 BIOS 禁用。"""
        if drv_type in self.bios_disabled:
            return False
        d = self.vfs.drives.get("C", {}).get("root", {})
        children = d.get("children", {})
        drivers = children.get("DRIVERS", {}).get("children", {})
        for node in drivers.values():
            if node.get("driver") and node.get("drv_type") == drv_type:
                return True
        return False

    def _require_driver(self, drv_type: str, feature: str) -> bool:
        if not self._has_driver(drv_type):
            self.print("无法使用 %s：%s 驱动已被删除或缺失。" % (feature, drv_type), "err")
            return False
        return True

    # ---------------- 内存管理（进程占用 / Out of Memory / 删驱动崩溃） ----------------
    def mem_total_k(self) -> int:
        """可用总内存：内存管理驱动 (HIMEM.SYS/EMM386.EXE) 在则含扩展内存；删则仅常规 640K。"""
        has_mgr = self._has_driver("memory")
        return self.machine.ram_total_k if has_mgr else self.machine.ram_conventional_k

    def mem_baseline_k(self) -> int:
        """系统 / 常驻驱动固定占用的内存（不会随命令释放）。"""
        has_mgr = self._has_driver("memory")
        base = 95  # DOS 内核 + COMMAND.COM 常驻
        if has_mgr:
            base += 48  # HIMEM.SYS + EMM386.EXE 常驻
        # 其它设备驱动：无内存管理器时被迫挤进常规内存
        for dt, kb in (("network", 16), ("sound", 12), ("video", 20), ("mouse", 8)):
            if self._has_driver(dt):
                base += kb
        # 常驻 TSR（DOSKEY / SMARTDRV / MSCDEX 之类）
        base += 8 + 32 + 24
        return base

    def mem_used_k(self) -> int:
        return self.mem_baseline_k() + sum(self.processes.values())

    def mem_available_k(self) -> int:
        return max(0, self.mem_total_k() - self.mem_used_k())

    def _mem_alloc(self, cost: int, name: str):
        """为进程分配内存；空间不足打印 Out of memory（彻底耗尽则崩溃），返回 key 或 None。"""
        if cost > self.mem_available_k():
            if self.mem_available_k() <= 0:
                self._crash("Out of memory",
                            "系统可用内存已耗尽，无法为 %s 分配 %dK 运行空间。" % (name, cost))
                return None
            self.print("Out of memory", "err")
            self.print("无法为 %s 分配 %dK 内存（可用内存仅 %dK）。请退出其它程序或重启系统。"
                       % (name, cost, self.mem_available_k()), "err")
            return None
        self._proc_seq += 1
        key = "%s#%d" % (name, self._proc_seq)
        self.processes[key] = cost
        return key

    def mem_free_key(self, key) -> None:
        if key:
            self.processes.pop(key, None)

    def free_game(self) -> None:
        """前端游戏退出时调用，释放其占用。"""
        key = getattr(self, "_active_game_key", None)
        if key:
            self.processes.pop(key, None)
            self._active_game_key = None

    def reset_runtime(self) -> None:
        """每次开机（含 REBOOT）重置运行时内存映射（新一次自检，内存重新分配）。"""
        self.processes = {}
        self._active_game_key = None
        self.health = "ok"
        self.unbootable = False
        self.crashed_msg = ""
    def execute(self, raw: str) -> None:
        line = raw.strip()
        if not line:
            return
        # 系统已崩溃：仅允许紧急恢复命令，其余一律拒绝
        if self.health == "crashed":
            name = line.split()[0].lower()
            if name in ("reboot", "sys"):
                pass  # 允许重启 / 恢复系统
            else:
                self.print("*** 系统已崩溃 (System halted) ***", "err")
                self.print("输入 SYS %s: 恢复系统文件，或 REBOOT 重新开机。" % SYSTEM_DRIVE, "err")
                return
        self.history.append(line)
        # 切换盘符:  D:
        m = re.match(r"^([A-Za-z]):$", line)
        if m:
            self._switch_drive(m.group(1).upper())
            return
        # 统一支持管道
        if "|" in line:
            self._pipeline(line)
            return
        self._dispatch(line)

    def _switch_drive(self, letter: str) -> None:
        d = self.vfs.drives.get(letter)
        if not d:
            self.print("无效盘符", "err")
            return
        if not d["formatted"]:
            self.print("驱动器 %s 中的磁盘未格式化。使用 FORMAT %s: 格式化。" % (letter, letter), "err")
            return
        self.drive = letter
        self.segs = []

    def _dispatch(self, line: str) -> None:
        parts = line.split()
        name = parts[0].lower()
        args = parts[1:]
        handler = COMMANDS.get(name)
        if handler:
            try:
                handler(self, args, line)
            except Exception as e:
                self.print("错误: %s" % e, "err")
            return
        # 尝试可执行文件 (.BAT / .COM / .EXE)
        # 先尝试路径解析（支持 C:\DOS\FORMAT.COM 全路径）
        exe = None
        if "\\" in name or "/" in name:
            ref = self.resolve(name)
            if ref and self.vfs.is_file(ref):
                fname = ref[1][-1]
                if fname.upper().endswith((".BAT", ".COM", ".EXE")):
                    exe = (ref, self.vfs.get_node(ref))
        if not exe:
            exe = self._find_executable(name)
        if exe:
            ref, node = exe
            fname = ref[1][-1].upper()  # 文件名（不含路径）
            ext = "bat" if fname.endswith(".BAT") else ("com" if fname.endswith(".COM") else "exe")
            key = self._mem_alloc(PROCESS_COST.get(ext, 40), fname)
            if key is None:
                return
            try:
                if fname.endswith(".BAT"):
                    self._run_batch(node.get("content", "") or "", args)
                else:
                    # .COM / .EXE: 去掉扩展名后当内部命令执行
                    base = fname
                    for e in (".COM", ".EXE"):
                        if base.endswith(e):
                            base = base[:-len(e)]
                            break
                    cmd = base + (" " + " ".join(args) if args else "")
                    self.execute(cmd)
            finally:
                self.mem_free_key(key)
            return
        self.print("'%s' 不是内部或外部命令，也不是可运行的程序。" % name, "err")

    def _find_executable(self, name: str):
        candidates = [name.upper()] if "." in name else \
            [name.upper() + e for e in (".BAT", ".COM", ".EXE")]
        search = [self.cwd()]
        for p in self.env.get("PATH", "").split(";"):
            r = self.vfs.resolve(p.strip(), self.drive, self.segs)
            if r and self.vfs.is_formatted(r[0]):
                search.append(r)
        for d in search:
            for c in candidates:
                ref = (d[0], d[1] + [c])
                node = self.vfs.get_node(ref)
                if node and node.get("type") == "file":
                    return (ref, node)
        return None

    # ---------------- PowerShell 管道 ----------------
    def _pipeline(self, line: str) -> None:
        segs = [s.strip() for s in line.split("|")]
        lines: List[str] = []
        try:
            for i, seg in enumerate(segs):
                if i == 0:
                    lines = self._capture(seg)
                else:
                    lines = self._apply_filter(seg, lines)
            for l in lines:
                self.print(l, "out")
        except Exception as e:
            self.print("管道错误: %s" % e, "err")

    def _capture(self, seg: str) -> List[str]:
        buf: List[str] = []
        old = self.print
        self.print = lambda t, k: buf.append(t)
        try:
            self._dispatch(seg)
        finally:
            self.print = old
        return buf

    def _apply_filter(self, seg: str, lines: List[str]) -> List[str]:
        parts = seg.split()
        cmd = parts[0].lower()
        rest = " ".join(parts[1:])
        if cmd in ("where-object", "where"):
            m = re.search(r"\{\s*\$_*\s*-like\s*'([^']*)'", rest)
            if m:
                pat = m.group(1).replace("*", ".*").replace("?", ".")
                return [l for l in lines if re.search(pat, l, re.IGNORECASE)]
            return lines
        if cmd in ("select-object", "select"):
            mm = re.search(r"-first\s+(\d+)", rest)
            if mm:
                return lines[:int(mm.group(1))]
            ml = re.search(r"-last\s+(\d+)", rest)
            if ml:
                return lines[-int(ml.group(1)):]
            return lines
        if cmd in ("sort-object", "sort"):
            return sorted(lines)
        if cmd in ("measure-object", "measure"):
            return ["Count: %d" % len(lines)]
        if cmd in ("get-content", "cat", "type"):
            return lines
        # 其它命令：忽略输入，重新运行
        return self._capture(seg)

    # ---------------- 批处理 ----------------
    def _run_batch(self, content: str, args: List[str]) -> None:
        if self._batch_depth > 8:
            self.print("批处理嵌套过深。", "err")
            return
        self._batch_depth += 1
        lines = content.replace("\r\n", "\n").split("\n")
        # 预处理 %0..%9
        def sub_args(text):
            for i, a in enumerate(args):
                text = text.replace("%%%d" % i, a)
            text = re.sub(r"%%\d", "", text)
            return text
        ip = 0
        labels = {}
        for idx, ln in enumerate(lines):
            s = ln.strip()
            if s.startswith(":"):
                labels[s[1:].lower()] = idx
        try:
            while ip < len(lines):
                raw = lines[ip]
                line = raw.strip()
                ip += 1
                if not line or line.startswith("rem "):
                    continue
                if line.startswith("::"):
                    continue
                if line.startswith(":"):
                    continue
                if line.lower().startswith("echo "):
                    msg = line[5:].strip()
                    if msg.upper() == "OFF" or msg.upper() == "ON":
                        continue
                    self.print(self.expand_vars(sub_args(msg)), "out")
                    continue
                if line.lower() == "pause":
                    self.print("按任意键继续. . .", "dim")
                    continue
                if line.lower().startswith("goto "):
                    tgt = line[5:].strip().lower()
                    if tgt in labels:
                        ip = labels[tgt]
                    continue
                if line.lower().startswith("if "):
                    # 简单: IF ERRORLEVEL / IF EXIST / IF str==str
                    body = line[3:].strip()
                    run = True
                    if body.lower().startswith("errorlevel"):
                        # 忽略，视为 false
                        run = False
                        body = body[len("errorlevel"):].strip()
                    m = re.match(r"\"?([^\"]*?)\"?==\"?([^\"]*?)\"?\s+(.*)", body)
                    if m:
                        run = (m.group(1) == m.group(2))
                        body = m.group(3)
                    if run:
                        self._dispatch(sub_args(body))
                    continue
                # 普通命令
                self._dispatch(sub_args(line))
        finally:
            self._batch_depth -= 1

    # ================= 命令实现 =================
    def _cmd_help(self, args, raw):
        self.print("katoDoS 可用命令 (统一兼容 DOS / CMD / PowerShell 语法)", "accent")
        rows = [
            ("HELP/?", "显示本帮助"),
            ("DIR / LS / GCI", "列目录"),
            ("CD / CHDIR / SL", "切换目录"),
            ("MD / MKDIR / NI", "新建目录"),
            ("RD / RMDIR", "删除目录"),
            ("COPY / CP / COPY-ITEM", "复制文件"),
            ("DEL / ERASE / RM", "删除文件 (DEL /S 强制删系统文件)"),
            ("REN / MOVE / MV", "重命名 / 移动"),
            ("TYPE / CAT / GET-CONTENT", "显示文件内容"),
            ("ECHO / WRITE-OUTPUT", "回显文本 / 环境变量"),
            ("SET", "设置或显示环境变量"),
            ("PATH / PROMPT", "显示或设置路径 / 提示符"),
            ("CLS / CLEAR", "清屏"),
            ("VER", "显示系统版本"),
            ("DATE / TIME", "显示日期 / 时间"),
            ("VOL", "显示卷标"),
            ("MEM", "显示内存（含进程占用；删内存驱动可用内存缩减为 640K）"),
            ("FORMAT", "格式化驱动器 (FORMAT C: 清空系统盘会崩溃; /S 传系统文件)"),
            ("SYS", "把系统文件写回驱动器 (崩溃/格式化后恢复引导)"),
            ("TREE", "以树形显示目录"),
            ("FIND / FINDSTR", "在文件中查找字符串"),
            ("PING", "真实网络 ping（查询宿主机网络栈）"),
            ("TRACERT", "真实跟踪路由"),
            ("IPCONFIG", "查看宿主机真实网络配置 (/all 详细)"),
            ("NETSTAT", "查看宿主机真实连接表 (-r 路由表)"),
            ("NSLOOKUP", "真实域名 DNS 解析"),
            ("SYSTEMINFO", "显示模拟系统信息"),
            ("IMPORT", "从宿主机导入文件到 C:\\IMPORT (沙箱内运行)"),
            ("MOUNT", "检测并挂载 U 盘为只读沙箱镜像 (MOUNT LIST 查看)"),
            ("UNMOUNT", "卸载外部卷 (UNMOUNT U:)"),
            ("TASKMAN", "任务管理器：显示所有进程/内存占用，TASKMAN /K <进程名> 终止进程"),
            ("KILL", "终止指定进程：KILL <进程名> (如 KILL snake#1)"),
            ("SAVE / LOAD", "保存 / 读取虚拟机快照"),
            ("ASM", "运行 .asm 文件 (katoASM 汇编器)"),
            ("C", "运行 .c 文件 (katoC 解释器)"),
            ("EDIT / ED", "打开内置编辑器"),
            ("WIN", "启动 Windows 3.x 字符桌面环境"),
            ("SNAKE / TETRIS / MINES", "内置小游戏 (回车启动, Q 退出)"),
            ("GUESS / MATRIX", "内置小游戏 (回车启动, Q 退出)"),
            ("EXIT / QUIT", "退出 katoDoS"),
            ("REBOOT", "重新开机自检"),
        ]
        for k, v in rows:
            self.print("  %-22s %s" % (k, v), "out")
        self.print("", "out")
        self.print("PowerShell 管道示例：dir | Where-Object { $_ -like '*TXT' }", "dim")

    def _cmd_ver(self, args, raw):
        for b in UNIFIED["banner"][:2]:
            self.print(b, "accent")
        self.print("katoDoS 1.0 - 统一 DOS 模拟器 (沙箱)", "out")

    def _cmd_cls(self, args, raw):
        self.print("", "clear")

    def _cmd_dir(self, args, raw):
        target = args[0] if args else "."
        ref = self.resolve(target)
        if not ref:
            self.print("找不到路径: %s" % target, "err")
            return
        if self.vfs.is_file(ref):
            self._print_file_info(ref)
            return
        if not self.vfs.is_dir(ref):
            self.print("找不到路径: %s" % target, "err")
            return
        items = self.vfs.list(ref) or []
        # 过滤通配
        if args and ("*" in args[0] or "?" in args[0]):
            base = self.resolve(".")
            items = [it for it in (self.vfs.list(base) or []) if _wildcard_match(it[0], args[0].upper())]
        label = self.vfs.volume_label(ref[0]) or VOLUMES.get(ref[0], "")
        self.print(" 驱动器 %s 中的卷是 %s" % (ref[0], label), "out")
        self.print(" %s 的目录\n" % fmt_path(ref), "out")
        fcount = dcount = 0
        total = 0
        for name, node in items:
            if node["type"] == "dir":
                dcount += 1
                self.print("%s    <DIR>         %s" % (_fmt_date(), name), "out")
            else:
                if self.vfs.is_mounted(ref[0]) and node.get("lazy"):
                    sz = self.vfs.real_size((ref[0], ref[1] + [name]))  # 取文件的真实大小
                else:
                    sz = len(node.get("content", ""))
                fcount += 1
                total += sz
                self.print("%s  %02d:%02d       %8d  %s" % (_fmt_date(), _now().hour, _now().minute, sz, name), "out")
        self.print("        %d 个文件 %18d 字节" % (fcount, total), "out")
        self.print("        %d 个目录" % dcount, "out")
        dv = self.machine.drives.get(ref[0])
        if dv:
            cap = self.machine.drive_capacity_bytes(ref[0])
            used = self.vfs.disk_usage_bytes(ref[0])
            free = max(0, cap - used)
            self.print("        %d 字节可用 (约 %.2f MB / 容量 %.2f MB)"
                       % (free, free / 1048576.0, cap / 1048576.0), "dim")
        elif self.vfs.is_mounted(ref[0]):
            info = self.vfs.mount_real_usage(ref[0])
            if info:
                used, cap = info
                free = max(0, cap - used)
                self.print("        %d 字节可用 (约 %.2f MB / 容量 %.2f MB)  [外部卷/只读镜像]"
                           % (free, free / 1048576.0, cap / 1048576.0), "dim")

    def _print_file_info(self, ref):
        node = self.vfs.get_node(ref)
        self.print("%s  %d 字节" % (fmt_path(ref), len(node.get("content", ""))), "out")

    def _cmd_pwd(self, args, raw):
        self.print(fmt_path(self.cwd()), "out")

    def _cmd_touch(self, args, raw):
        """TOUCH — 创建空文件或更新文件时间戳。"""
        if not args:
            self.print("语法: TOUCH <文件名>", "err")
            return
        for a in args:
            ref = self.resolve(a)
            if ref and self.vfs.is_file(ref):
                self.print("已更新: %s" % fmt_path(ref), "out")
            elif ref and self.vfs.is_dir(ref):
                self.print("路径已存在但不是文件: %s" % a, "err")
            else:
                # 新建空文件：检查父目录是否存在
                p = Path(a.replace("\\", "/"))
                parent = str(p.parent) if str(p.parent) != "." else "."
                pref = self.resolve(parent)
                if pref and self.vfs.is_dir(pref):
                    fname = p.name.upper()
                    if self.vfs.write_file((pref[0], pref[1] + [fname]), "", system=False):
                        self.print("已创建: %s" % fmt_path((pref[0], pref[1] + [fname])), "out")
                    else:
                        self.print("创建失败: %s" % a, "err")
                else:
                    self.print("无法找到路径: %s" % a, "err")

    def _cmd_cd(self, args, raw):
        if not args:
            self.print(fmt_path(self.cwd()), "out")
            return
        if args[0].lower() in ("..",):
            if self.segs:
                self.segs.pop()
            return
        if args[0] in ("\\", "/"):
            self.segs = []
            return
        ref = self.resolve(args[0])
        if not ref or not self.vfs.is_dir(ref):
            self.print("系统找不到指定的路径。", "err")
            return
        self.drive, self.segs = ref[0], ref[1]

    def _cmd_md(self, args, raw):
        if not args:
            self.print("语法: MD <目录名>", "err")
            return
        for a in args:
            ref = self.resolve(a)
            if not ref:
                self.print("无效路径: %s" % a, "err")
                continue
            if self.vfs.is_mounted(ref[0]):
                self.print("外部卷 %s 为只读沙箱镜像，无法创建目录。" % ref[0], "err")
                continue
            if self.vfs.exists(ref):
                self.print("目录已存在: %s" % fmt_path(ref), "err")
                continue
            if self.vfs.mkdir(ref):
                self.print("已创建 %s" % fmt_path(ref), "out")
            else:
                self.print("创建失败: %s" % a, "err")

    def _cmd_rd(self, args, raw):
        if not args:
            self.print("语法: RD <目录名>", "err")
            return
        for a in args:
            ref = self.resolve(a)
            if not ref or not self.vfs.is_dir(ref):
                self.print("找不到目录: %s" % a, "err")
                continue
            if self.vfs.is_mounted(ref[0]):
                self.print("外部卷 %s 为只读沙箱镜像，无法删除目录。" % ref[0], "err")
                continue
            if (ref[0], ref[1]) == self.cwd() or ref[1] == []:
                self.print("无法删除当前目录或根目录。", "err")
                continue
            items = self.vfs.list(ref)
            if items:
                self.print("目录非空: %s" % fmt_path(ref), "err")
                continue
            self.vfs.delete(ref)
            self.print("已删除 %s" % fmt_path(ref), "out")

    def _cmd_copy(self, args, raw):
        if len(args) < 2:
            self.print("语法: COPY <源> <目标>", "err")
            return
        src = self.resolve(args[0])
        if not src or not self.vfs.is_file(src):
            self.print("找不到源文件: %s" % args[0], "err")
            return
        dst = self.resolve(args[1])
        if dst and self.vfs.is_dir(dst):
            name = src[1][-1]
            dst = (dst[0], dst[1] + [name])
        if self.vfs.is_mounted(dst[0]):
            self.print("外部卷 %s 为只读沙箱镜像，无法写入文件。" % dst[0], "err")
            return
        content = self.vfs.read_file(src)
        if self.vfs.write_file(dst, content):
            self.print("已复制 1 个文件。", "out")
        else:
            self.print("复制失败。", "err")

    def _cmd_del(self, args, raw):
        if not args:
            self.print("语法: DEL <文件>  或 DEL /S <文件> (强制删除系统文件)", "err")
            return
        force_sys = False
        targets = []
        for a in args:
            if a.upper() == "/S":
                force_sys = True
            else:
                targets.append(a)
        if not targets:
            self.print("未指定文件。", "err")
            return
        for a in targets:
            if "*" in a.upper() or "?" in a.upper():
                base = self.resolve(".")
                for name, node in (self.vfs.list(base) or []):
                    if node["type"] == "file" and _wildcard_match(name, a.upper()):
                        ref = (base[0], base[1] + [name])
                        self._delete_one(ref, force_sys)
                continue
            ref = self.resolve(a)
            if not ref or not self.vfs.is_file(ref):
                self.print("找不到文件: %s" % a, "err")
                continue
            self._delete_one(ref, force_sys)

    def _delete_one(self, ref, force_sys):
        if self.vfs.is_mounted(ref[0]):
            self.print("外部卷 %s: 为只读沙箱镜像，不支持删除真实文件。" % ref[0], "err")
            self.print("如需移除请物理拔出 U 盘，或在沙箱内用 UNMOUNT %s: 卸载。" % ref[0], "err")
            return
        name = ref[1][-1].upper()
        # 1) DOS 内核文件：删除即系统崩溃
        if name in KERNEL_FILES:
            if not force_sys:
                self.print("警告: %s 是 DOS 内核文件，删除将导致系统崩溃。使用 DEL /S 强制删除。" % fmt_path(ref), "err")
                return
            self.print("正在删除 DOS 内核文件 %s ..." % fmt_path(ref), "err")
            self.vfs.delete(ref)
            self._crash("System crash", "DOS 内核文件 %s 已丢失，系统无法继续运行。" % name)
            return
        # 2) 命令解释器：删除即所有命令失效、系统崩溃
        if name in INTERPRETER_FILES:
            if not force_sys:
                self.print("警告: %s 是命令解释器，删除将导致所有命令失效、系统崩溃。使用 DEL /S 强制删除。" % fmt_path(ref), "err")
                return
            self.print("正在删除命令解释器 %s ..." % fmt_path(ref), "err")
            self.vfs.delete(ref)
            self._crash("System crash", "命令解释器 %s 已丢失，命令无法被解释，系统停止。" % name)
            return
        # 3) 其它系统文件（AUTOEXEC.BAT / CONFIG.SYS 等启动配置）
        if self.vfs.is_system(ref):
            if not force_sys:
                self.print("警告: %s 是系统文件，删除可能导致启动异常。使用 DEL /S 强制删除。" % fmt_path(ref), "err")
                return
            self.print("警告: 已删除系统文件 %s。" % fmt_path(ref), "err")
            if name == "AUTOEXEC.BAT":
                self.print("下次开机将不执行自动批处理 (PATH/提示符等设置失效)。", "err")
            elif name == "CONFIG.SYS":
                self.print("下次开机将不加载 CONFIG.SYS 中的设备驱动。", "err")
            self.vfs.delete(ref)
            self.print("已删除 %s" % fmt_path(ref), "out")
            return
        # 4) 驱动文件：删除对应功能真实禁用
        drv = self.vfs.is_driver(ref)
        if drv == "memory":
            self.vfs.delete(ref)
            self.print("已删除内存管理驱动 %s。" % fmt_path(ref), "out")
            if not self._has_driver("memory"):
                # 最后一个内存管理驱动被删：扩展内存消失，可用内存缩减为常规 640K
                if self.mem_used_k() > self.mem_total_k():
                    self._crash(
                        "Out of memory",
                        "内存管理驱动 (HIMEM.SYS / EMM386.EXE) 已全部删除，扩展内存不可用，"
                        "可用内存缩减为常规 640K。但当前已加载的程序 / 驱动共占用 %dK，"
                        "超过可用 %dK，操作系统已无可用内存空间，无法继续运行。"
                        % (self.mem_used_k(), self.mem_total_k()),
                    )
                    return
                self.print("警告: HIMEM.SYS / EMM386.EXE 已全部删除，XMS/EMS 扩展内存不可用。", "err")
                self.print("可用内存已缩减为常规 640K；需要扩展内存的程序将报 Out of memory。", "err")
            return
        if drv:
            self.vfs.delete(ref)
            self.print("已删除驱动 %s (%s)。" % (fmt_path(ref), drv), "out")
            msg = {
                "network": "网络功能 (PING/TRACERT/IPCONFIG/NETSTAT/NSLOOKUP) 已禁用。",
                "sound":   "声卡驱动已删除，系统音效将完全静音。",
                "mouse":   "鼠标驱动已删除，鼠标指针与点击将无法响应。",
                "keyboard":"键盘驱动已删除，键盘输入将产生异常字符。",
                "video":   "显示适配器驱动已删除：显示器仍亮，但画面显示已损坏（色彩/分辨率/同步异常）。",
                "memory":  "XMS/EMS 内存驱动已删除，MEM 扩展内存不可用。",
            }.get(drv, "相关功能可能不可用。")
            self.print(msg, "err")
            if drv == "video":
                self.print("vga-broken", "mode")
            elif drv == "sound":
                self.print("sound-off", "sound-off")
            elif drv == "mouse":
                self.print("mouse-broken", "mouse-broken")
            elif drv == "keyboard":
                self.print("keyboard-broken", "keyboard-broken")
            return
        # 5) 普通文件
        if not self.vfs.delete(ref):
            self.print("删除失败: %s" % fmt_path(ref), "err")
            return
        self.print("已删除 %s" % fmt_path(ref), "out")

    def _cmd_sys(self, args, raw):
        """SYS <盘符>:  把系统启动文件与驱动写回指定盘（恢复可引导状态）。"""
        letter = SYSTEM_DRIVE
        for a in args:
            if a.upper().endswith(":"):
                letter = a[0].upper()
        if letter not in self.vfs.drives:
            self.print("无效盘符: %s" % letter, "err")
            return
        if not self.vfs.is_formatted(letter):
            self.print("驱动器 %s 未格式化，无法传输系统文件。" % letter, "err")
            return
        if self.vfs.is_mounted(letter):
            self.print("外部卷 %s: 为只读沙箱镜像，不支持传输系统文件。" % letter, "err")
            return
            return
        self.vfs.sys_transfer(letter)
        self.health = "ok"
        self.unbootable = False
        self.crashed_msg = ""
        self.print("系统文件已传输到 %s: 。" % letter, "out")
        self.print("%s: 现在可引导启动。" % letter, "accent")
        self.print("vga-ok", "mode")
        self.print("sound-on", "sound-on")
        self.print("mouse-ok", "mouse-ok")
        self.print("keyboard-ok", "keyboard-ok")

    def _cmd_move(self, args, raw):
        if len(args) < 2:
            self.print("语法: REN <旧名> <新名>   或   MOVE <源> <目标>", "err")
            return
        src = self.resolve(args[0])
        if not src or not self.vfs.exists(src):
            self.print("找不到: %s" % args[0], "err")
            return
        dst = self.resolve(args[1])
        if self.vfs.is_dir(dst):
            dst = (dst[0], dst[1] + [src[1][-1]])
        # 重命名/移动
        name = dst[1][-1]
        if src[0] != dst[0] or src[1][:-1] != dst[1][:-1]:
            # 跨目录移动
            if self.vfs.is_file(src):
                content = self.vfs.read_file(src)
                if self.vfs.write_file(dst, content):
                    self.vfs.delete(src)
                    self.print("已移动。", "out")
                else:
                    self.print("移动失败。", "err")
            else:
                self.print("仅支持移动文件。", "err")
        else:
            if self.vfs.rename(src, name):
                self.print("已重命名。", "out")
            else:
                self.print("重命名失败。", "err")

    def _cmd_type(self, args, raw):
        if not args:
            self.print("语法: TYPE <文件>", "err")
            return
        ref = self.resolve(args[0])
        if not ref or not self.vfs.is_file(ref):
            self.print("找不到文件: %s" % args[0], "err")
            return
        content = self.vfs.read_file(ref) or ""
        for ln in content.split("\n"):
            self.print(ln, "out")

    def _cmd_echo(self, args, raw):
        if not args:
            self.print("ECHO 处于打开状态。", "out")
            return
        text = " ".join(args)
        if text.upper() == "OFF" or text.upper() == "ON":
            return
        self.print(self.expand_vars(text), "out")

    def _cmd_set(self, args, raw):
        if not args:
            for k, v in sorted(self.env.items()):
                self.print("%s=%s" % (k, v), "out")
            return
        s = " ".join(args)
        if "=" in s:
            k, _, v = s.partition("=")
            self.env[k.strip().upper()] = self.expand_vars(v.strip())
            if self.persist_cb:
                self.persist_cb()
        else:
            key = s.strip().upper()
            self.print("%s=%s" % (key, self.env.get(key, "")), "out")

    def _cmd_path(self, args, raw):
        if not args:
            self.print("PATH=%s" % self.env.get("PATH", ""), "out")
            return
        self.env["PATH"] = self.expand_vars(" ".join(args))

    def _cmd_prompt(self, args, raw):
        if not args:
            self.print("PROMPT=%s" % self.env.get("PROMPT", ""), "out")
            return
        self.env["PROMPT"] = " ".join(args)

    def _cmd_date(self, args, raw):
        self.print("当前日期: %s" % _fmt_date(), "out")

    def _cmd_time(self, args, raw):
        self.print("当前时间: %s" % _fmt_time(), "out")

    def _cmd_vol(self, args, raw):
        d = (args[0][0].upper() if args else self.drive)
        label = self.vfs.volume_label(d) or self.machine.drive_label(d) or VOLUMES.get(d, "")
        self.print("驱动器 %s 中的卷是 %s" % (d, label), "out")
        dv = self.machine.drives.get(d)
        if dv:
            cap = self.machine.drive_capacity_bytes(d)
            used = self.vfs.disk_usage_bytes(d)
            free = max(0, cap - used)
            self.print("  类型: %s   容量: %.2f MB   已用: %.2f MB   剩余: %.2f MB"
                       % (dv["type"], cap / 1048576.0, used / 1048576.0, free / 1048576.0), "dim")
        elif self.vfs.is_mounted(d):
            info = self.vfs.mount_real_usage(d)
            if info:
                used, cap = info
                free = max(0, cap - used)
                self.print("  类型: 可移动磁盘(只读镜像)   容量: %.2f MB   已用: %.2f MB   剩余: %.2f MB"
                           % (cap / 1048576.0, used / 1048576.0, free / 1048576.0), "dim")

    def _cmd_df(self, args, raw):
        """DF — 显示所有驱动器的磁盘使用情况 (Linux df 风格)。"""
        self.print("文件系统      1K-块    已用    可用  使用%%  挂载点", "out")
        for d in sorted(self.vfs.drive_list()):
            if d == "A" and not self.vfs.is_formatted(d):
                continue
            try:
                used = self.vfs.disk_usage_bytes(d)
                cap = self.machine.drive_capacity_bytes(d) if self.machine.drives.get(d) else used
                free = max(0, cap - used)
                pct = 100 * used // cap if cap else 0
                label = (self.vfs.volume_label(d) or VOLUMES.get(d, d))[:10]
                self.print("%-5s  %9d  %8d  %8d  %3d%%  %s:" % (label, cap//1024, used//1024, free//1024, pct, d), "out")
            except Exception:
                pass

    def _cmd_which(self, args, raw):
        """WHICH — 显示命令的完整路径。"""
        if not args:
            self.print("语法: WHICH <命令名>", "err")
            return
        name = args[0]
        if name.lower() in COMMANDS:
            self.print("%s: 内部命令 (katoDoS 内核)" % name, "out")
            return
        exe = self._find_executable(name)
        if exe:
            ref = exe[0]
            self.print("%s: %s" % (name, fmt_path(ref)), "out")
        else:
            self.print("%s: 未找到" % name, "err")

    def _cmd_mem(self, args, raw):
        m = self.machine
        has_mgr = self._has_driver("memory")
        total = self.mem_total_k()
        base = self.mem_baseline_k()
        used_proc = sum(self.processes.values())
        used = base + used_proc
        free = max(0, total - used)
        conv = m.ram_conventional_k
        ext = m.ram_extended_k if has_mgr else 0
        upper = m.ram_upper_k if has_mgr else 0
        conv_used = min(conv, base)
        self.print("          Memory Type        Total    Used    Free", "out")
        self.print("          ----------------  -------  ------- -------", "out")
        self.print("          Conventional        %6dK  %6dK  %6dK" % (conv, conv_used, max(0, conv - conv_used)), "out")
        self.print("          Upper Memory        %6dK  %6dK  %6dK" % (upper, 0, upper), "out")
        self.print("          Extended (XMS)      %6dK  %6dK  %6dK" % (ext, 0, ext), "out")
        self.print("", "out")
        self.print("          总内存: %dK (%.0f MB)   已用: %dK   可用: %dK"
                   % (total, total / 1024.0, used, free), "out")
        if self.processes:
            self.print("", "out")
            self.print("          驻留程序 / 进程 (共 %d 个, %dK):" % (len(self.processes), used_proc), "out")
            for k, kb in self.processes.items():
                self.print("            %-20s %6dK" % (k, kb), "dim")
        self.print("          CPU 线程: %d   缓存: %dK" % (m.cpu["threads"], m.cpu["cache_k"]), "dim")
        if not has_mgr:
            self.print("          警告: 内存管理驱动 (HIMEM.SYS / EMM386.EXE) 缺失，"
                       "扩展内存不可用，可用内存已缩减为常规 640K。", "err")

    def _cmd_format(self, args, raw):
        if not args:
            self.print("语法: FORMAT <盘符>:  [/S]", "err")
            return
        letter = args[0][0].upper()
        sys_flag = any(a.upper() == "/S" for a in args[1:])
        if letter not in self.vfs.drives:
            self.print("无效盘符: %s" % letter, "err")
            return
        if self.vfs.is_mounted(letter):
            self.print("无法格式化外部卷 %s: — 它是只读沙箱镜像，不会触碰真实 U 盘。" % letter, "err")
            return
        # 格式化系统启动盘：清空所有文件，系统将失去可引导能力
        if letter == SYSTEM_DRIVE:
            self.vfs.drives[letter] = {"formatted": True, "root": {"type": "dir", "children": {}}}
            self.print("警告: %s: 是系统启动盘！所有系统文件将被清除。" % letter, "err")
            self.print("正在格式化 %s: ..." % letter, "dim")
            self.print("格式化完成。", "out")
            if sys_flag:
                # FORMAT /S：格式化并同时传系统文件，磁盘仍可引导
                self.vfs.sys_transfer(letter)
                self.unbootable = False
                self.health = "ok"
                self.crashed_msg = ""
                self.print("系统文件已随盘传输 (FORMAT /S)。%s: 仍可引导。" % letter, "out")
            else:
                # 普通格式化系统盘：IO.SYS/MSDOS.SYS/COMMAND.COM 全失 -> 系统崩溃
                self._crash(
                    "Non-System disk",
                    "系统盘 %s: 已被格式化，IO.SYS / MSDOS.SYS / COMMAND.COM 全部丢失，" % letter
                    + "操作系统无法继续运行。",
                )
            return
        # 其它盘：正常清空
        self.vfs.drives[letter] = {"formatted": True, "root": {"type": "dir", "children": {}}}
        self.print("正在格式化 %s: ..." % letter, "dim")
        self.print("格式化完成。卷标: %s" % VOLUMES.get(letter, "KATODOS"), "out")

    def _crash(self, title: str, detail: str) -> None:
        """系统崩溃：标记为 crashed，输出致命信息，并向前端请求停机画面。"""
        self.health = "crashed"
        self.unbootable = True
        self.crashed_msg = detail
        self.print("*** 致命错误 (FATAL) ***", "err")
        self.print(detail, "err")
        self.print("操作系统已停止运行 (System halted)。", "err")
        self.print(
            "%s\n\n%s\n\nSystem halted.\n输入 SYS %s: 恢复系统，或 REBOOT 重启。"
            % (title, detail, SYSTEM_DRIVE),
            "crash",
        )

    def _cmd_tree(self, args, raw):
        ref = self.resolve(args[0]) if args else self.cwd()
        if not ref or not self.vfs.is_dir(ref):
            self.print("无效目录。", "err")
            return
        self.print(fmt_path(ref), "out")
        self._tree_walk(ref, "")

    def _tree_walk(self, ref, prefix):
        items = self.vfs.list(ref) or []
        dirs = [it for it in items if it[1]["type"] == "dir"]
        files = [it for it in items if it[1]["type"] == "file"]
        for i, (name, node) in enumerate(dirs):
            last = (i == len(dirs) - 1 and not files)
            self.print(prefix + ("└── " if last else "├── ") + name + "\\", "out")
            self._tree_walk((ref[0], ref[1] + [name]), prefix + ("    " if last else "│   "))
        for i, (name, node) in enumerate(files):
            last = (i == len(files) - 1)
            self.print(prefix + ("└── " if last else "├── ") + name, "out")

    def _cmd_find(self, args, raw):
        # FINDSTR "text" file
        if len(args) < 2:
            self.print("语法: FINDSTR \"字符串\" <文件>", "err")
            return
        needle = args[0].strip('"')
        ref = self.resolve(args[1])
        if not ref or not self.vfs.is_file(ref):
            self.print("找不到文件: %s" % args[1], "err")
            return
        for i, ln in enumerate(self.vfs.read_file(ref).split("\n"), 1):
            if needle.lower() in ln.lower():
                self.print("%s:%d:%s" % (fmt_path(ref), i, ln), "out")

    # ---------------- 真实（只读）网络命令 ----------------
    # 以下命令会真正查询宿主机的网络栈（ICMP / DNS / 网卡 / 连接表），
    # 但全部只读：不向宿主机写入任何数据，VM 内部状态也不会回泄宿主机，
    # 因此仍在沙箱限制之内。删除 NE2000.DRV 后这些命令会被禁用。

    def _real_shell(self, cmd: List[str], timeout: int = 20) -> Optional[str]:
        """在宿主机上运行只读命令并返回其输出；失败返回 None。
        以字节捕获后手动解码：中文 Windows 的网络命令输出为 GBK 编码，
        直接 text=True 会因 UTF-8 解码失败而崩溃。"""
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                                  creationflags=0x08000000)
            out = b""
            for b in (proc.stdout, proc.stderr):
                if b:
                    out += b
            try:
                return out.decode("gbk", "replace")
            except Exception:
                return out.decode("utf-8", "replace")
        except Exception:
            return None

    def _cmd_ping(self, args, raw):
        if not args:
            self.print("语法: PING <主机>", "err")
            return
        if not self._require_driver("network", "PING"):
            return
        host = args[0]
        key = self._mem_alloc(PROCESS_COST.get("ping", 24), "PING")
        if key is None:
            return
        try:
            self.print("正在 Ping %s 具有 32 字节的数据:" % host, "out")
            out = self._real_shell(["ping", "-n", "4", host])
            if out is None:
                self.print("PING: 无法完成对 %s 的请求（网络不可达或命令不可用）。" % host, "err")
                return
            for line in out.splitlines():
                s = line.strip()
                if s:
                    self.print(s, "out")
        finally:
            self.mem_free_key(key)

    def _cmd_tracert(self, args, raw):
        if not args:
            self.print("语法: TRACERT <主机>", "err")
            return
        if not self._require_driver("network", "TRACERT"):
            return
        host = args[0]
        key = self._mem_alloc(PROCESS_COST.get("tracert", 24), "TRACERT")
        if key is None:
            return
        try:
            self.print("通过最多 20 个跃点跟踪到 %s 的路由:" % host, "out")
            out = self._real_shell(["tracert", "-d", "-h", "20", "-w", "1500", host], timeout=45)
            if out is None:
                self.print("TRACERT: 无法完成对 %s 的跟踪。" % host, "err")
                return
            for line in out.splitlines():
                s = line.strip()
                if s:
                    self.print(s, "out")
        finally:
            self.mem_free_key(key)

    def _cmd_ipconfig(self, args, raw):
        if not self._require_driver("network", "IPCONFIG"):
            return
        key = self._mem_alloc(PROCESS_COST.get("ipconfig", 24), "IPCONFIG")
        if key is None:
            return
        try:
            flag = "/all" if ("all" in [a.lower() for a in args]) else ""
            out = self._real_shell(["ipconfig", flag] if flag else ["ipconfig"])
            if out is None:
                self.print("IPCONFIG: 无法读取宿主机网络配置。", "err")
                return
            for line in out.splitlines():
                self.print(line.rstrip(), "out")
        finally:
            self.mem_free_key(key)

    def _cmd_netstat(self, args, raw):
        if not self._require_driver("network", "NETSTAT"):
            return
        key = self._mem_alloc(PROCESS_COST.get("netstat", 24), "NETSTAT")
        if key is None:
            return
        try:
            opts = ["-an"]
            if any(a.lower() in ("-r", "route") for a in args):
                opts = ["-r"]
            out = self._real_shell(["netstat"] + opts)
            if out is None:
                self.print("NETSTAT: 无法读取宿主机连接表。", "err")
                return
            for line in out.splitlines():
                self.print(line.rstrip(), "out")
        finally:
            self.mem_free_key(key)

    def _cmd_nslookup(self, args, raw):
        if not self._require_driver("network", "NSLOOKUP"):
            return
        key = self._mem_alloc(PROCESS_COST.get("nslookup", 24), "NSLOOKUP")
        if key is None:
            return
        try:
            host = args[0] if args else "localhost"
            self.print("正在解析 %s ..." % host, "out")
            try:
                infos = socket.getaddrinfo(host, None)
                seen = []
                for fam, _, _, _, sockaddr in infos:
                    ip = sockaddr[0]
                    if ip not in seen:
                        seen.append(ip)
                if seen:
                    self.print("名称:    %s" % host, "out")
                    self.print("Addresses:", "out")
                    for ip in seen:
                        self.print("    %s" % ip, "out")
                else:
                    self.print("*** 找不到 %s 的地址" % host, "err")
            except Exception as e:
                self.print("*** 解析失败: %s" % e, "err")
        finally:
            self.mem_free_key(key)

    def _cmd_import(self, args, raw):
        """从宿主机导入文件到 VM 沙箱（只读复制，不回写宿主机）。
        不带参数时由前端打开宿主文件选择对话框；带参数时按给定宿主路径导入。
        """
        host_path = args[0] if args else ""
        self.print(host_path, "import")

    def _cmd_systeminfo(self, args, raw):
        m = self.machine
        info = [
            ("主机名", "KATODOS-PC"),
            ("OS 名称", UNIFIED["sysname"]),
            ("OS 版本", "1.0 (katoDoS sandbox)"),
            ("系统制造商", "KATO"),
            ("系统型号", "KATO-486DX2"),
            ("处理器", m.cpu_str()),
            ("BIOS 版本", m.bios),
            ("内存", "%dK (%.0f MB)" % (m.ram_total_k, m.ram_total_k / 1024.0)),
            ("常规内存", "%dK" % m.ram_conventional_k),
            ("扩展内存", "%dK (XMS)" % m.ram_extended_k),
            ("驱动器", "C: HDD %dMB / D: CDROM %dMB / A: FDD 1.44MB / Z: NET %dMB"
                % (m.drives["C"]["capacity_mb"], m.drives["D"]["capacity_mb"], m.drives["Z"]["capacity_mb"])),
        ]
        for k, v in info:
            self.print("%-12s %s" % (k, v), "out")

    def _cmd_whoami(self, args, raw):
        self.print("%s\\%s" % (VOLUMES.get(self.drive, "KATODOS"), self.env.get("USER", "HACKER")), "out")

    def _cmd_hostname(self, args, raw):
        self.print("KATODOS-PC", "out")

    def _cmd_title(self, args, raw):
        if args:
            self.title = " ".join(args)
            if self.persist_cb:
                self.persist_cb()
        else:
            self.print(self.title, "out")

    def _cmd_color(self, args, raw):
        if args:
            self.color = args[0]
            if self.persist_cb:
                self.persist_cb()
        else:
            self.print("当前颜色: %s" % self.color, "out")

    def _cmd_shell(self, args, raw):
        self.print("katoDoS 已处于统一模式。", "accent")
        self.print("支持的命令语法包括：", "out")
        self.print("  MS-DOS 风格:  DIR / CD / MD / COPY / DEL / TYPE", "out")
        self.print("  FreeDOS 风格:  LS / CAT / RM", "out")
        self.print("  CMD 风格:      CHDIR / MKDIR / RMDIR / ECHO", "out")
        self.print("  PowerShell 风格:  Get-ChildItem / Set-Location / Where-Object", "out")
        self.print("无需切换，直接输入即可。", "dim")

    def _cmd_save(self, args, raw):
        name = args[0] if args else "autosave"
        try:
            self.save_snapshot(name)
            self.print("虚拟机快照已保存: %s" % name, "out")
        except Exception as e:
            self.print("保存失败: %s" % e, "err")

    def _cmd_load(self, args, raw):
        name = args[0] if args else "autosave"
        if self.load_snapshot(name):
            self.print("虚拟机快照已读取: %s" % name, "out")
            self.print("当前位置: %s" % fmt_path(self.cwd()), "dim")
        else:
            self.print("找不到快照: %s" % name, "err")

    def _cmd_asm(self, args, raw):
        if not args:
            self.print("katoASM 汇编器 — 用法: ASM <文件.asm>", "accent")
            self.print("示例: ASM C:\\SRC\\HELLO.ASM", "dim")
            return
        ref = self.resolve(args[0])
        if not ref or not self.vfs.is_file(ref):
            self.print("找不到汇编源文件: %s" % args[0], "err")
            return
        src = self.vfs.read_file(ref) or ""
        # 可选输入重定向: ASM file.asm < input.txt
        stdin = ""
        if len(args) > 2 and args[1] == "<":
            iref = self.resolve(args[2])
            if iref and self.vfs.is_file(iref):
                stdin = self.vfs.read_file(iref) or ""
        # 加载 katoASM 程序需要占用内存（驻留模块，重启后才释放）；空间不足则 Out of memory
        _key = self._mem_alloc(PROCESS_COST["asm"], "ASM")
        if _key is None:
            return
        try:
            import asm
            out, code = asm.assemble_and_run(src, stdin)
            if out:
                for ln in out.split("\n"):
                    self.print(ln, "out")
            self.print("[katoASM] 程序结束，返回码 %d" % code, "dim")
        except asm.AsmError as e:
            self.print(str(e), "err")
        except Exception as e:
            self.print("汇编/运行错误: %s" % e, "err")

    def _cmd_c(self, args, raw):
        if not args:
            self.print("katoC 解释器 — 用法: C <文件.c>", "accent")
            self.print("示例: C C:\\SRC\\HELLO.C", "dim")
            return
        ref = self.resolve(args[0])
        if not ref or not self.vfs.is_file(ref):
            self.print("找不到 C 源文件: %s" % args[0], "err")
            return
        src = self.vfs.read_file(ref) or ""
        stdin = ""
        if len(args) > 2 and args[1] == "<":
            iref = self.resolve(args[2])
            if iref and self.vfs.is_file(iref):
                stdin = self.vfs.read_file(iref) or ""
        # 加载 katoC 程序需要占用内存（驻留模块，重启后才释放）；空间不足则 Out of memory
        _key = self._mem_alloc(PROCESS_COST["c"], "C")
        if _key is None:
            return
        try:
            import cinterp
            out = cinterp.run_c(src, stdin)
            if out:
                for ln in out.split("\n"):
                    self.print(ln, "out")
            self.print("[katoC] 执行完毕。", "dim")
        except cinterp.CError as e:
            self.print(str(e), "err")
        except Exception as e:
            self.print("运行错误: %s" % e, "err")

    def _cmd_edit(self, args, raw):
        if args:
            ref = self.resolve(args[0])
            if ref:
                self.print(fmt_path(ref), "edit")
                return
        self.print("", "edit")

    def _cmd_exit(self, args, raw):
        self.print("", "exit")

    def _cmd_reboot(self, args, raw):
        self.print("", "reboot")

    def _cmd_pause(self, args, raw):
        self.print("按任意键继续. . .", "dim")

    def _cmd_mount(self, args, raw):
        if args and args[0].lower() in ("list", "/list", "-l"):
            mounted = [L for L, d in self.vfs.drives.items() if d.get("mounted")]
            if mounted:
                self.print("已挂载的外部卷:", "out")
                for L in mounted:
                    self.print("  %s:  %s  (只读镜像)" % (L, self.vfs.volume_label(L) or ""), "out")
            else:
                self.print("当前没有已挂载的外部卷。", "dim")
            return
        mounted = self.vfs.auto_mount_usb()
        if not mounted:
            self.print("未检测到可移动磁盘 (U 盘)。请插入 U 盘后重试 MOUNT。", "err")
            return
        for info in mounted:
            self.print("检测到可移动磁盘 %s: (卷标: %s)" % (info["root"], info["label"] or "(无)"), "out")
            self.print("已挂载为 %s: (只读沙箱镜像；目录随浏览懒加载、TYPE 文件才载入内容)。"
                       % info["letter"], "out")
        self.print("提示: 进入 %s: 浏览；TYPE <文件> 把内容载入沙箱；FORMAT/DEL/MD 不会触碰真实 U 盘。"
                   % mounted[0]["letter"], "dim")

    def _cmd_unmount(self, args, raw):
        letter = args[0][0].upper() if args else "U"
        if self.vfs.unmount_usb(letter):
            self.print("已卸载 %s: (临时缓存文件仍保留在宿主机，下次插入可复用)。" % letter, "out")
        else:
            self.print("未挂载外部卷 %s: 或盘符无效。" % letter, "err")

    # ---------------- 任务管理器 / 进程管理 ----------------
    def _cmd_taskman(self, args, raw):
        """TASKMAN — 任务管理器，显示进程列表与内存占用。
           TASKMAN /K 或 TASKMAN /KILL <进程名> 终止进程。"""
        # 解析参数
        kill_mode = False
        target = None
        for a in args:
            if a.lower() in ("/k", "/kill"):
                kill_mode = True
            elif not a.startswith("/"):
                target = a
        if kill_mode:
            if target:
                self._cmd_kill_process(target)
            else:
                self.print("用法: TASKMAN /K <进程名>  或  KILL <进程名>", "err")
                self.print("进程名: %s" % ", ".join(sorted(self.processes.keys())) if self.processes else "(无进程)", "dim")
            return

        # 显示任务管理器画面
        total = self.mem_total_k()
        used = self.mem_used_k()
        free = self.mem_available_k()
        base = self.mem_baseline_k()
        proc_used = sum(self.processes.values())

        self.print("", "out")
        self.print("  katoDoS 任务管理器  v1.0", "accent")
        self.print("  ───────────────────────────────────────", "out")
        self.print("  总内存:       %8d K  (%5.0f MB)" % (total, total / 1024.0), "out")
        self.print("  系统占用:     %8d K" % base, "out")
        if self.processes:
            self.print("  进程占用:     %8d K  (%d 个进程)" % (proc_used, len(self.processes)), "out")
        self.print("  可用内存:     %8d K" % free, "out")
        self.print("  内存使用率:   %5.1f%%" % (100.0 * used / total if total else 0), "out")
        self.print("  CPU 线程:     %8d" % self.machine.cpu["threads"], "out")
        self.print("  ───────────────────────────────────────", "out")

        if self.processes:
            self.print("  进程列表:", "accent")
            self.print("    %-24s %7s" % ("进程名 (PID)", "内存"), "out")
            self.print("    %-24s %7s" % ("─" * 24, "───────"), "out")
            for k in sorted(self.processes.keys(), key=lambda x: self.processes[x], reverse=True):
                kb = self.processes[k]
                # 判断进程类别
                name = k.split("#")[0]
                if name in ("snake", "tetris", "mines", "guess", "matrix"):
                    cat = "游戏"
                elif name in ("asm",):
                    cat = "汇编"
                elif name in ("c",):
                    cat = "C程序"
                elif name in ("ping", "tracert", "ipconfig", "netstat", "nslookup"):
                    cat = "网络"
                elif name in ("bat", "com", "exe"):
                    cat = "脚本"
                else:
                    cat = "程序"
                bar_len = max(1, kb * 16 // (total if total else 640))
                bar = "█" * min(bar_len, 16)
                self.print("    %-24s %6dK [%-16s] %s" % (k, kb, bar, cat), "out")
            self.print("", "out")
        else:
            self.print("  当前无活跃进程。运行 ASM / C / 游戏以创建进程。", "dim")
            self.print("", "out")
        self.print("  使用 TASKMAN /K <进程名> 或 KILL <进程名> 终止进程。", "dim")

    def _cmd_kill(self, args, raw):
        """KILL <进程名> — 终止指定进程。进程名见 TASKMAN 或 MEM 输出。"""
        if not args:
            self.print("语法: KILL <进程名>  (如 KILL snake#1)", "err")
            self.print("当前进程: %s" % ", ".join(sorted(self.processes.keys())) if self.processes else "(无进程)", "dim")
            return
        target = args[0]
        self._cmd_kill_process(target)

    def _cmd_kill_process(self, target: str):
        """内部：按进程名终止进程。"""
        # 精确匹配
        if target in self.processes:
            kb = self.processes.pop(target)
            if self._active_game_key == target:
                self._active_game_key = None
            self.print("进程 %s 已终止 (释放 %dK)。" % (target, kb), "out")
            return
        # 前缀匹配（如 KILL snake 终止所有 snake 进程）
        matched = [k for k in self.processes if k.startswith(target + "#") or k == target or k.lower() == target.lower()]
        if not matched:
            # 尝试不分大小写匹配
            matched = [k for k in self.processes if k.lower() == target.lower()]
        if not matched:
            # 通配匹配
            import fnmatch
            matched = [k for k in self.processes if fnmatch.fnmatch(k.lower(), target.lower())]
        if not matched:
            self.print("未找到进程: %s" % target, "err")
            self.print("当前进程: %s" % ", ".join(sorted(self.processes.keys())), "dim")
            return
        total_freed = 0
        for k in matched:
            kb = self.processes.pop(k)
            total_freed += kb
            if self._active_game_key == k:
                self._active_game_key = None
            self.print("  进程 %s 已终止 (释放 %dK)。" % (k, kb), "out")
        self.print("共终止 %d 个进程，释放 %dK 内存。" % (len(matched), total_freed), "out")

    # ---------------- 小游戏 ----------------
    def _cmd_game(self, args, raw, name=None):
        name = name or "game"
        # 运行游戏需要占用内存，且运行期间一直占用（退出后才释放）
        cost = PROCESS_COST.get(name, 64)
        if cost > self.mem_available_k():
            if self.mem_available_k() <= 0:
                self._crash("Out of memory",
                            "系统可用内存已耗尽，无法为 %s 分配运行空间。" % name)
                return
            self.print("Out of memory", "err")
            self.print("无法为 %s 分配 %dK 内存（可用内存仅 %dK）。请退出其它程序或重启系统。"
                       % (name, cost, self.mem_available_k()), "err")
            return
        key = self._mem_alloc(cost, name)
        if key is None:
            return
        self._active_game_key = key
        # name 由下面的闭包绑定；前端收到 kind="game" 后打开对应游戏
        self.print(name, "game")

    # ---------------- Windows 3.x 字符桌面 ----------------
    def _cmd_win(self, args, raw):
        """WIN — 启动 Windows 3.x 风格的字符桌面环境。"""
        name = "win3"
        cost = 128  # Windows 比较吃内存
        if cost > self.mem_available_k():
            if self.mem_available_k() <= 0:
                self._crash("Out of memory",
                            "系统可用内存已耗尽，无法启动 Windows。")
                return
            self.print("Out of memory", "err")
            self.print("无法为 Windows 分配 %dK 内存。" % cost, "err")
            return
        key = self._mem_alloc(cost, name)
        if key is None:
            return
        self._active_game_key = key
        self.print("win", "win")


# ---------------- 命令表（含别名）----------------
def _mk(*aliases):
    def deco(fn):
        for a in aliases:
            COMMANDS[a.lower()] = fn
        return fn
    return deco


COMMANDS = {}


@_mk("help", "?", "man")
def _(sh, a, r): sh._cmd_help(a, r)
@_mk("cls", "clear")
def _(sh, a, r): sh._cmd_cls(a, r)
@_mk("ver", "uname")
def _(sh, a, r): sh._cmd_ver(a, r)
@_mk("dir", "ls", "gci", "get-childitem", "get-childitems")
def _(sh, a, r): sh._cmd_dir(a, r)
@_mk("cd", "chdir", "sl", "set-location")
def _(sh, a, r): sh._cmd_cd(a, r)
@_mk("pwd")
def _(sh, a, r): sh._cmd_pwd(a, r)
@_mk("md", "mkdir", "ni")
def _(sh, a, r): sh._cmd_md(a, r)
@_mk("rd", "rmdir")
def _(sh, a, r): sh._cmd_rd(a, r)
@_mk("copy", "cp", "copy-item")
def _(sh, a, r): sh._cmd_copy(a, r)
@_mk("del", "erase", "rm", "remove-item", "ri")
def _(sh, a, r): sh._cmd_del(a, r)
@_mk("ren", "move", "mv")
def _(sh, a, r): sh._cmd_move(a, r)
@_mk("type", "cat", "get-content")
def _(sh, a, r): sh._cmd_type(a, r)
@_mk("echo", "write-output")
def _(sh, a, r): sh._cmd_echo(a, r)
@_mk("set")
def _(sh, a, r): sh._cmd_set(a, r)
@_mk("path")
def _(sh, a, r): sh._cmd_path(a, r)
@_mk("prompt")
def _(sh, a, r): sh._cmd_prompt(a, r)
@_mk("date")
def _(sh, a, r): sh._cmd_date(a, r)
@_mk("time")
def _(sh, a, r): sh._cmd_time(a, r)
@_mk("vol")
def _(sh, a, r): sh._cmd_vol(a, r)
@_mk("mem", "free")
def _(sh, a, r): sh._cmd_mem(a, r)
@_mk("format")
def _(sh, a, r): sh._cmd_format(a, r)
@_mk("sys")
def _(sh, a, r): sh._cmd_sys(a, r)
@_mk("tree")
def _(sh, a, r): sh._cmd_tree(a, r)
@_mk("find", "findstr", "grep")
def _(sh, a, r): sh._cmd_find(a, r)
@_mk("touch")
def _(sh, a, r): sh._cmd_touch(a, r)
@_mk("ask", "which")
def _(sh, a, r): sh._cmd_which(a, r)
@_mk("ping")
def _(sh, a, r): sh._cmd_ping(a, r)
@_mk("tracert")
def _(sh, a, r): sh._cmd_tracert(a, r)
@_mk("ipconfig")
def _(sh, a, r): sh._cmd_ipconfig(a, r)
@_mk("netstat")
def _(sh, a, r): sh._cmd_netstat(a, r)
@_mk("nslookup")
def _(sh, a, r): sh._cmd_nslookup(a, r)
@_mk("import")
def _(sh, a, r): sh._cmd_import(a, r)
@_mk("systeminfo")
def _(sh, a, r): sh._cmd_systeminfo(a, r)
@_mk("whoami")
def _(sh, a, r): sh._cmd_whoami(a, r)
@_mk("hostname")
def _(sh, a, r): sh._cmd_hostname(a, r)
@_mk("title")
def _(sh, a, r): sh._cmd_title(a, r)
@_mk("color")
def _(sh, a, r): sh._cmd_color(a, r)
@_mk("shell")
def _(sh, a, r): sh._cmd_shell(a, r)
@_mk("asm")
def _(sh, a, r): sh._cmd_asm(a, r)
@_mk("c")
def _(sh, a, r): sh._cmd_c(a, r)
@_mk("edit", "ed")
def _(sh, a, r): sh._cmd_edit(a, r)
@_mk("win")
def _(sh, a, r): sh._cmd_win(a, r)
@_mk("exit", "quit")
def _(sh, a, r): sh._cmd_exit(a, r)
@_mk("reboot")
def _(sh, a, r): sh._cmd_reboot(a, r)
@_mk("pause")
def _(sh, a, r): sh._cmd_pause(a, r)
@_mk("mount")
def _(sh, a, r): sh._cmd_mount(a, r)
@_mk("unmount", "umount")
def _(sh, a, r): sh._cmd_unmount(a, r)
@_mk("taskman", "taskmgr", "ps")
def _(sh, a, r): sh._cmd_taskman(a, r)
@_mk("kill")
def _(sh, a, r): sh._cmd_kill(a, r)
@_mk("df")
def _(sh, a, r): sh._cmd_df(a, r)
@_mk("save")
def _(sh, a, r): sh._cmd_save(a, r)
@_mk("load")
def _(sh, a, r): sh._cmd_load(a, r)


# ---------------- 内置小游戏（前端 canvas 实现，后端仅发出启动信号）----------------
for _g in ("snake", "tetris", "mines", "guess", "matrix"):
    def _game_factory(name):
        def _run(sh, a, r, _n=name):
            sh._cmd_game(a, r, _n)
        return _run
    COMMANDS[_g] = _game_factory(_g)
