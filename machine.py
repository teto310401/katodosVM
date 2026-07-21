"""katoDoS 虚拟机硬件模型

根据宿主机的 CPU 与内存动态为虚拟机分配资源：
- CPU 型号 / 频率 / 核心 / 线程随宿主核心数变化；
- 内存保留 640K 常规内存，扩展内存按宿主机物理内存的一定比例划分；
- 各驱动器容量亦随宿主机资源微调；
- 开机自检 (POST) 偶尔会遇到 90 年代 PC 常见的软/硬件故障。

所有资源数值仅用于模拟与展示，虚拟机仍然是纯沙箱，不会占用宿主机的真实内存。
"""

import os
import random
import ctypes
from ctypes import wintypes
from typing import Dict, List, Any, Tuple, Optional


class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", wintypes.ULARGE_INTEGER),
        ("ullAvailPhys", wintypes.ULARGE_INTEGER),
        ("ullTotalPageFile", wintypes.ULARGE_INTEGER),
        ("ullAvailPageFile", wintypes.ULARGE_INTEGER),
        ("ullTotalVirtual", wintypes.ULARGE_INTEGER),
        ("ullAvailVirtual", wintypes.ULARGE_INTEGER),
        ("ullAvailExtendedVirtual", wintypes.ULARGE_INTEGER),
    ]


def _host_total_ram_bytes() -> int:
    """尽量使用 Windows API 获取物理内存总量；失败则回退到 8GB。"""
    try:
        kernel32 = ctypes.windll.kernel32
        status = _MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
        if kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.ullTotalPhys)
    except Exception:
        pass
    return 8 * 1024 * 1024 * 1024  # 8GB fallback


def _host_cpu_cores() -> int:
    return os.cpu_count() or 4


class Machine:
    def __init__(self, bios: Optional[Dict[str, Any]] = None, fail_chance: float = 0.08) -> None:
        self.bios_settings = bios or {}
        self.bios = "Award Modular BIOS v4.51PG, An Energy Star Ally"
        self.bios_copyright = "Copyright (C) 1984-94, Award Software, Inc."
        self.mainboard = "katoTRONIX P5-90 SOCKET-7 MAINBOARD"

        host_cores = _host_cpu_cores()
        host_ram_b = _host_total_ram_bytes()
        host_ram_mb = host_ram_b // (1024 * 1024)

        # 根据宿主机核心数选择 CPU 模型
        if host_cores >= 16:
            model, mhz, cache = "katoPENTIUM-PRO-200", 200, 512
        elif host_cores >= 8:
            model, mhz, cache = "katoPENTIUM-166", 166, 256
        elif host_cores >= 4:
            model, mhz, cache = "kato486DX4-100", 100, 256
        else:
            model, mhz, cache = "kato486DX2-66", 66, 128

        self.cpu = {
            "vendor": "kato",
            "model": model,
            "mhz": mhz,
            "fpu": "integrated",
            "cores": max(1, host_cores // 2),
            "threads": host_cores,
            "cache_k": cache,
        }

        # 内存：常规 640K 固定；扩展内存按宿主机 RAM 的 1/128 取整，最小 4MB，最大 128MB
        ext_mb = max(4, min(128, host_ram_mb // 128))
        # BIOS 可覆盖扩展内存
        xms = self.bios_settings.get("xms", "Auto")
        if isinstance(xms, str) and xms not in ("Auto", "", None):
            try:
                ext_mb = int(xms.replace("MB", "").strip())
            except ValueError:
                pass
        # BIOS 可覆盖 CPU 线程数
        thr = self.bios_settings.get("threads", "Auto")
        if isinstance(thr, str) and thr not in ("Auto", "", None):
            try:
                self.cpu["threads"] = int(thr)
                self.cpu["cores"] = max(1, self.cpu["threads"] // 2)
            except ValueError:
                pass

        self.ram_conventional_k = 640
        self.ram_upper_k = 384
        self.ram_extended_k = ext_mb * 1024
        self.ram_total_k = self.ram_conventional_k + self.ram_upper_k + self.ram_extended_k

        # 驱动器容量也随宿主机内存微调（假装硬盘/光盘/网络盘）
        hdd_mb = max(128, min(8192, host_ram_mb // 8))
        cd_mb = 700
        net_mb = max(256, min(4096, host_ram_mb // 16))
        self.drives: Dict[str, Dict[str, Any]] = {
            "C": {"type": "HDD",   "label": "QUANTUM FIREBALL", "capacity_mb": hdd_mb, "readonly": False},
            "D": {"type": "CDROM", "label": "KATODOS_BOOT",     "capacity_mb": cd_mb,  "readonly": True},
            "A": {"type": "FDD",   "label": "",                 "capacity_mb": 1.44,   "readonly": False},
            "Z": {"type": "NET",   "label": "NETSHARE",         "capacity_mb": net_mb, "readonly": False},
        }

        self._fail_chance = fail_chance
        self._last_failure: Optional[Tuple[str, List[str]]] = None

    # ---------------- 派生信息 ----------------
    def cpu_str(self) -> str:
        return "%s @ %dMHz (%d 核心 / %d 线程, %dK 缓存)" % (
            self.cpu["model"], self.cpu["mhz"], self.cpu["cores"],
            self.cpu["threads"], self.cpu["cache_k"],
        )

    def drive_label(self, letter: str) -> str:
        d = self.drives.get(letter.upper())
        return d["label"] if d else ""

    def drive_capacity_bytes(self, letter: str) -> int:
        d = self.drives.get(letter.upper())
        if not d:
            return 0
        return int(d["capacity_mb"] * 1024 * 1024)

    def drive_free_bytes(self, letter: str, used_bytes: int) -> int:
        return max(0, self.drive_capacity_bytes(letter) - used_bytes)

    # ---------------- 开机自检 (POST) 文本 ----------------
    def post_header(self) -> List[str]:
        """内存自检之前显示的 BIOS 头几行（与原版 Award BIOS 对齐）。"""
        return [self.bios, self.bios_copyright, "", self.mainboard, "CPU  : %s" % self.cpu_str()]

    def post_footer(self, vfs) -> List[str]:
        """内存自检完成之后显示的硬件检测/启动行。"""
        c = self.drives["C"]
        used_c = vfs.disk_usage_bytes("C") if vfs else 0
        used_mb = used_c / (1024 * 1024)
        bs = self.bios_settings
        net_on = bs.get("network", True)
        sound_on = bs.get("sound", True)
        mouse_on = bs.get("mouse", True)
        vga_on = vfs.is_file(("C", ["DRIVERS", "VGA.DRV"])) if vfs else True
        boot_order = bs.get("boot_order", "C: A: D:")
        return [
            "FPU  : %s .............. OK" % self.cpu["fpu"],
            "",
            "Detecting HDD  : IDE Primary Master ... %s %dMB (%.1f MB used)" % (c["label"], c["capacity_mb"], used_mb),
            "Detecting FDD  : 1.44MB 3.5\" .......... OK",
            "Keyboard ..... OK    Mouse (PS/2) ..... %s" % ("OK" if mouse_on else "DISABLED"),
            "Video  : Cirrus Logic GD5446 VGA ..... %s" % ("OK" if vga_on else "DISABLED"),
            "Sound  : Sound Blaster 16 (DSP v4.05)  %s" % ("OK" if sound_on else "DISABLED"),
            "Network: NE2000 packet driver ......... %s" % ("OK" if net_on else "DISABLED"),
            "",
            "Boot Order: %s" % boot_order,
            "Booting from C:\\ ...",
            "Starting katoDoS ...",
            "",
            "HIMEM.SYS loaded.   EMM386.EXE loaded." if (vfs and (vfs.is_file(("C", ["DRIVERS", "HIMEM.SYS"])) or vfs.is_file(("C", ["DRIVERS", "EMM386.EXE"])))) else "Warning: HIMEM.SYS / EMM386.EXE not loaded - XMS/EMS disabled",
            "C:\\>AUTOEXEC.BAT",
        ]

    # ---------------- 开机故障模拟 ----------------
    def boot_failure(self) -> Optional[Tuple[str, List[str], bool]]:
        """按概率模拟开机失败。返回 (标题, 错误行列表, 是否可恢复) 或 None。
        可恢复错误：按任意键继续启动；致命错误：停住并重启。"""
        if random.random() > self._fail_chance:
            return None
        failures = [
            (
                "Divide overflow",
                [
                    "Divide overflow",
                    "",
                    "System halted.",
                    "",
                    "Press Ctrl+Alt+Del to restart",
                ],
                False,
            ),
            (
                "Memory parity error",
                [
                    "Memory parity error ???",
                    "",
                    "Check SIMM/DIMM installation.",
                    "",
                    "Press Ctrl+Alt+Del to restart",
                ],
                False,
            ),
            (
                "Disk boot failure",
                [
                    "Disk boot failure",
                    "",
                    "Insert system disk and press Enter",
                ],
                False,
            ),
            (
                "Keyboard error or no keyboard present",
                [
                    "Keyboard error or no keyboard present",
                    "",
                    "Press F1 to continue, DEL to enter SETUP",
                ],
                True,
            ),
            (
                "CMOS battery failed",
                [
                    "CMOS battery failed",
                    "",
                    "Run Setup and reload default values.",
                    "",
                    "Press F1 to continue",
                ],
                True,
            ),
            (
                "Secondary master hard disk error",
                [
                    "Secondary master hard disk error",
                    "Press F1 to resume, F2 to Setup",
                ],
                True,
            ),
        ]
        self._last_failure = random.choice(failures)
        return self._last_failure

    def last_failure(self) -> Optional[Tuple[str, List[str]]]:
        return self._last_failure
