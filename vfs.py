"""katoDoS 虚拟文件系统 (VFS)

一个完全沙箱化的内存磁盘：多驱动器 (C:/A:/D:)、目录树、文件读写、
路径解析（支持盘符、绝对/相对路径、. 与 ..）。状态可序列化为 JSON 持久化。
不会触碰宿主机的真实文件系统（除把整个磁盘快照写到工作区一个 json 文件外）。
"""

import json
import os
import ctypes
import tempfile
from typing import Optional, Tuple, List, Dict, Any

DriveLetter = str  # "C"
PathSegs = List[str]  # ["DOS", "EDIT.COM"]
Ref = Tuple[DriveLetter, PathSegs]


def _dir_node() -> Dict[str, Any]:
    return {"type": "dir", "children": {}}


def _file_node(content: str = "", protected: bool = False, system: bool = False,
               driver: bool = False, drv_type: str = "", lazy: bool = False) -> Dict[str, Any]:
    node = {"type": "file", "content": content}
    if lazy:
        node["lazy"] = True
    if protected:
        node["protected"] = True
    if system:
        node["system"] = True
    if driver:
        node["driver"] = True
        if drv_type:
            node["drv_type"] = drv_type
    return node


def detect_removable_drives() -> List[Dict[str, str]]:
    """检测宿主机上的可移动磁盘（U 盘）。返回 [{letter, root, label}]。

    仅读取信息、不触碰任何文件；非 Windows 或检测失败返回空列表。
    """
    try:
        kernel32 = ctypes.windll.kernel32
        drives = kernel32.GetLogicalDrives()
        result = []
        for i in range(26):
            if not (drives & (1 << i)):
                continue
            letter = chr(ord("A") + i)
            root = letter + ":\\"
            try:
                dtype = kernel32.GetDriveTypeW(root)
            except Exception:
                continue
            if dtype != 2:  # DRIVE_REMOVABLE
                continue
            label = ""
            try:
                buf = ctypes.create_unicode_buffer(256)
                kernel32.GetVolumeInformationW(root, buf, 256, None, None, None, None, 0)
                label = buf.value
            except Exception:
                pass
            result.append({"letter": letter, "root": root, "label": label})
        return result
    except Exception:
        return []


class UsbMount:
    """外接 U 盘的懒加载镜像（只读沙箱）。

    - 进入某目录时，只把该目录的【子目录名与文件名】记入临时缓存文件，不读文件内容；
    - 只有真正“点开/读取”某个文件时，才把其内容读入缓存，从而可在沙箱里使用；
    - 整个过程只读真实 U 盘，绝不回写，保持沙箱安全。
    缓存文件位于 %TEMP%/katodos/usb_<盘符>.cache.json。
    """

    def __init__(self, real_root: str, cache_path: str, label: str = "") -> None:
        self.real_root = real_root
        self.cache_path = cache_path
        self.label = label
        self.cache = self._load_cache()

    def _load_cache(self) -> Dict[str, Any]:
        try:
            if os.path.exists(self.cache_path):
                with open(self.cache_path, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and "dirs" in data:
                    data.setdefault("files", {})
                    return data
        except Exception:
            pass
        return {"dirs": {}, "files": {}}

    def _save_cache(self) -> None:
        try:
            d = os.path.dirname(self.cache_path)
            if d:
                os.makedirs(d, exist_ok=True)
            tmp = self.cache_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, ensure_ascii=False)
            os.replace(tmp, self.cache_path)
        except Exception:
            pass

    def _real_list(self, rel: str):
        ap = os.path.join(self.real_root, rel) if rel else self.real_root
        try:
            entries = os.listdir(ap)
        except Exception:
            return ([], [])
        subdirs, files = [], []
        for e in entries:
            full = os.path.join(ap, e)
            try:
                if os.path.isdir(full):
                    subdirs.append(e)
                else:
                    files.append(e)
            except Exception:
                files.append(e)
        return (subdirs, files)

    def ensure_dir(self, rel: str) -> Dict[str, Any]:
        """首次访问某目录：把子目录名与文件名记入缓存（不读文件内容）。"""
        if rel not in self.cache["dirs"]:
            subdirs, files = self._real_list(rel)
            self.cache["dirs"][rel] = {"dirs": subdirs, "files": files}
            self._save_cache()
        return self.cache["dirs"][rel]

    def read_file(self, rel: str) -> Optional[str]:
        """点开文件才读内容并写入缓存；之后可在沙箱里使用。"""
        if rel not in self.cache["files"]:
            ap = os.path.join(self.real_root, rel) if rel else self.real_root
            try:
                with open(ap, "rb") as f:
                    data = f.read()
                try:
                    content = data.decode("utf-8")
                except Exception:
                    try:
                        content = data.decode("gbk", errors="replace")
                    except Exception:
                        content = data.decode("latin-1", errors="replace")
            except Exception:
                return None
            self.cache["files"][rel] = content
            # 确保该文件出现在父目录的 files 列表里
            d = os.path.dirname(rel)
            if d not in self.cache["dirs"]:
                self.ensure_dir(d)
            base = os.path.basename(rel)
            if base not in self.cache["dirs"][d]["files"]:
                self.cache["dirs"][d]["files"].append(base)
            self._save_cache()  # 无条件落盘：点开文件即把内容写入临时缓存文件
        return self.cache["files"][rel]

    def file_size(self, rel: str) -> int:
        ap = os.path.join(self.real_root, rel) if rel else self.real_root
        try:
            return os.path.getsize(ap)
        except Exception:
            return 0


class VFS:
    def __init__(self) -> None:
        self.drives: Dict[str, Dict[str, Any]] = {}
        self.mount_labels: Dict[str, str] = {}
        self._init_drives()

    # ---------- 初始化默认磁盘 ----------
    def _init_drives(self) -> None:
        self.drives["C"] = {"formatted": True, "root": _dir_node()}
        self.drives["D"] = {"formatted": True, "root": _dir_node()}
        self.drives["A"] = {"formatted": False, "root": _dir_node()}
        self.drives["Z"] = {"formatted": True, "root": _dir_node()}

        # 系统目录树
        for d in ["DOS", "WINDOWS", "DRIVERS", "UTIL", "GAMES", "TEMP", "USERS", "SRC", "NET", "IMPORT"]:
            self._mkdir_node(self.drives["C"]["root"], d)

        # 核心系统文件（删除会导致无法启动）— 伪源码：TYPE 可见真实感汇编源码
        self.write_file(("C", ["IO.SYS"]),
                        "; katoDoS IO.SYS — DOS 输入输出核心 (v1.0)\n"
                        "; 伪源码：系统 BIOS 中断封装与设备初始化\n"
                        "; 反汇编 kato.IO 2026\n"
                        ";\n"
                        "SEGMENT _TEXT PARA PUBLIC 'CODE'\n"
                        "  ASSUME CS:_TEXT, DS:_TEXT, ES:_TEXT\n"
                        ";\n"
                        "; ---- 版本签名与历史 ----\n"
                        "  ORG 0000h\n"
                        "  DB 'katoDoS IO.SYS 1.0'\n"
                        "  DB 0Dh, 0Ah\n"
                        "  DB 'Copyright (C) 2026 kato. All rights reserved.'\n"
                        "  DB 0Dh, 0Ah\n"
                        "  DB 'Build: 2026-07-18 17:42:00'\n"
                        "  DB 0Dh, 0Ah\n"
                        "  DB 'Changelog:'\n"
                        "  DB 0Dh, 0Ah\n"
                        "  DB '  v1.0  Initial IO.SYS release with full INT 13h support'\n"
                        "  DB 0Dh, 0Ah\n"
                        ";\n"
                        "; ---- 初始化入口 (被 BIOS 启动扇区调用) ----\n"
                        "SYSINIT:\n"
                        "  CLI                             ; 关中断\n"
                        "  MOV AX, CS\n"
                        "  MOV DS, AX\n"
                        "  MOV ES, AX\n"
                        "  MOV SS, AX\n"
                        "  MOV SP, 0400h                  ; 堆栈指针(1K)\n"
                        ";\n"
                        "; ---- 第 1 阶段: 最小硬件初始化 ----\n"
                        "  CALL INIT_PIC                   ; 初始化中断控制器 8259A\n"
                        "  CALL INIT_TIMER                 ; 初始化系统定时器 8253 (INT 08h)\n"
                        "  CALL INIT_KBD                   ; 初始化键盘控制器 8042 (INT 09h)\n"
                        "  CALL INIT_DISK                  ; 初始化磁盘系统 BIOS (INT 13h)\n"
                        "  CALL INIT_CON                   ; 初始化控制台视频/键盘 BIOS\n"
                        "  CALL INIT_PRN                   ; 初始化并行口 (INT 17h)\n"
                        "  CALL INIT_COM                   ; 初始化串行口 (INT 14h)\n"
                        ";\n"
                        "; ---- 第 2 阶段: 建立中断向量表 ----\n"
                        "  XOR AX, AX\n"
                        "  MOV ES, AX\n"
                        ";\n"
                        "; ---- 硬件中断 (8259A IRQ 0-7) ----\n"
                        "  MOV WORD PTR ES:[0020h], INT_08  ; IRQ0: 时钟\n"
                        "  MOV WORD PTR ES:[0024h], INT_09  ; IRQ1: 键盘\n"
                        "  MOV WORD PTR ES:[0028h], INT_0A  ; IRQ2: 从片\n"
                        "  MOV WORD PTR ES:[002Ch], INT_0B  ; IRQ3: COM2\n"
                        "  MOV WORD PTR ES:[0030h], INT_0C  ; IRQ4: COM1\n"
                        "  MOV WORD PTR ES:[0034h], INT_0D  ; IRQ5: LPT2\n"
                        "  MOV WORD PTR ES:[0038h], INT_0E  ; IRQ6: 软盘\n"
                        "  MOV WORD PTR ES:[003Ch], INT_0F  ; IRQ7: LPT1\n"
                        ";\n"
                        "; ---- BIOS 软件中断 ----\n"
                        "  MOV WORD PTR ES:[0040h], INT_10  ; 视频服务\n"
                        "  MOV WORD PTR ES:[0044h], INT_11  ; 设备检测\n"
                        "  MOV WORD PTR ES:[0048h], INT_12  ; 内存检测\n"
                        "  MOV WORD PTR ES:[004Ch], INT_13  ; 磁盘 I/O\n"
                        "  MOV WORD PTR ES:[0050h], INT_14  ; 串行通信\n"
                        "  MOV WORD PTR ES:[0054h], INT_15  ; 系统服务\n"
                        "  MOV WORD PTR ES:[0058h], INT_16  ; 键盘 I/O\n"
                        "  MOV WORD PTR ES:[005Ch], INT_17  ; 并行打印\n"
                        "  MOV WORD PTR ES:[0060h], INT_18  ; ROM BASIC\n"
                        "  MOV WORD PTR ES:[0064h], INT_19  ; 启动加载\n"
                        ";\n"
                        "; ---- 第 3 阶段: 硬件检测 ----\n"
                        "  CALL DETECT_MEMORY              ; 返回 AX = 连续 KB\n"
                        "  MOV [SYSMEM_K], AX\n"
                        "  CALL DETECT_EQUIP               ; 返回 BX = 设备标志字\n"
                        "  MOV [EQUIP_FLAG], BX\n"
                        "  CALL DETECT_DISK                ; 检测硬盘数量\n"
                        "  MOV [DISK_COUNT], AL\n"
                        ";\n"
                        "; ---- 第 4 阶段: 初始化 BIOS 数据区 (40:00h) ----\n"
                        "  MOV AX, 0040h\n"
                        "  MOV ES, AX\n"
                        "  MOV WORD PTR ES:[0010h], [EQUIP_FLAG]  ; 设备标志\n"
                        "  MOV WORD PTR ES:[0013h], [SYSMEM_K]     ; 内存大小\n"
                        "  MOV BYTE PTR ES:[0049h], 03h            ; 视频模式 80x25\n"
                        "  MOV WORD PTR ES:[004Ah], 3D4h           ; CRTC 端口\n"
                        "  MOV BYTE PTR ES:[0065h], 0              ; 键盘 LED\n"
                        "  MOV BYTE PTR ES:[006Ch], 0              ; 定时器低\n"
                        "  MOV BYTE PTR ES:[0070h], 0              ; 定时器高\n"
                        "  MOV BYTE PTR ES:[0071h], 0              ; 24h 溢出\n"
                        ";\n"
                        "; ---- 第 5 阶段: 加载 MSDOS.SYS ----\n"
                        "  MOV DX, 0002h                          ; 逻辑扇区 2 (根目录后)\n"
                        "  MOV CX, 0020h                          ; 32 个扇区 (16KB)\n"
                        "  MOV BX, 0700h                          ; 加载地址 0700:0000\n"
                        "  CALL READ_SECTORS\n"
                        "  JC LOAD_ERR\n"
                        "  CALL FAR PTR 0700h:0000h               ; 跳转到 MSDOS.SYS 入口\n"
                        ";\n"
                        "LOAD_ERR:\n"
                        "  MOV SI, OFFSET ERR_MSG\n"
                        "  CALL PRINT_STR\n"
                        "  INT 18h                                ; 进入 ROM BASIC\n"
                        ";\n"
                        "ERR_MSG DB 'DISK BOOT FAILURE - INSERT SYSTEM DISK$'\n"
                        ";\n"
                        "; ======== INT 08h: 系统定时器 (18.2Hz) ========\n"
                        "INT_08:\n"
                        "  STI\n"
                        "  PUSH AX\n"
                        "  PUSH DS\n"
                        "  MOV AX, 0040h\n"
                        "  MOV DS, AX\n"
                        "  ADD WORD PTR DS:[006Ch], 1             ; 滴答加 1\n"
                        "  ADC WORD PTR DS:[006Eh], 0\n"
                        "  CMP WORD PTR DS:[006Ch], 4C4h          ; 约 1/18.2 秒\n"
                        "  JNZ TICK_DONE\n"
                        "  INC BYTE PTR DS:[0070h]                ; 24h 计数器\n"
                        "TICK_DONE:\n"
                        "  MOV AL, 20h\n"
                        "  OUT 20h, AL                            ; EOI\n"
                        "  POP DS\n"
                        "  POP AX\n"
                        "  IRET\n"
                        ";\n"
                        "; ======== INT 10h: 视频服务 (部分功能) ========\n"
                        "INT_10:\n"
                        "  STI\n"
                        "  CMP AH, 00h          ; 设置视频模式\n"
                        "  JZ  SET_MODE\n"
                        "  CMP AH, 01h          ; 设置光标形状\n"
                        "  JZ  SET_CURSOR\n"
                        "  CMP AH, 02h          ; 设置光标位置\n"
                        "  JZ  SET_CURSOR_POS\n"
                        "  CMP AH, 03h          ; 读取光标位置\n"
                        "  JZ  GET_CURSOR_POS\n"
                        "  CMP AH, 06h          ; 滚动窗口上\n"
                        "  JZ  SCROLL_UP\n"
                        "  CMP AH, 07h          ; 滚动窗口下\n"
                        "  JZ  SCROLL_DN\n"
                        "  CMP AH, 09h          ; 写字符+属性\n"
                        "  JZ  WRITE_CHAR_ATTR\n"
                        "  CMP AH, 0Ah          ; 写字符仅\n"
                        "  JZ  WRITE_CHAR_ONLY\n"
                        "  CMP AH, 0Eh          ; TTY 写字符\n"
                        "  JZ  TTY_WRITE\n"
                        "  CMP AH, 0Fh          ; 获取当前模式\n"
                        "  JZ  GET_MODE\n"
                        "  CMP AH, 13h          ; 写字符串\n"
                        "  JZ  WRITE_STRING\n"
                        "  IRET\n"
                        ";\n"
                        "SET_MODE:\n"
                        "  CMP AL, 03h\n"
                        "  JNZ NOT_MODE3\n"
                        "  MOV [CRT_MODE], AL\n"
                        "NOT_MODE3:\n"
                        "  IRET\n"
                        "SET_CURSOR:\n"
                        "  MOV [CURSOR_SLINE], CH\n"
                        "  MOV [CURSOR_ELINE], CL\n"
                        "  IRET\n"
                        "SET_CURSOR_POS:\n"
                        "  MOV [CURSOR_X], DL\n"
                        "  MOV [CURSOR_Y], DH\n"
                        "  IRET\n"
                        "GET_CURSOR_POS:\n"
                        "  MOV DL, [CURSOR_X]\n"
                        "  MOV DH, [CURSOR_Y]\n"
                        "  MOV CX, [CURSOR_START]\n"
                        "  IRET\n"
                        "GET_MODE:\n"
                        "  MOV AL, [CRT_MODE]\n"
                        "  MOV AH, 50h           ; 80 列\n"
                        "  IRET\n"
                        "TTY_WRITE:\n"
                        "  CMP AL, 0Dh\n"
                        "  JZ  TTY_CR\n"
                        "  CMP AL, 0Ah\n"
                        "  JZ  TTY_LF\n"
                        "  CMP AL, 07h\n"
                        "  JZ  TTY_BELL\n"
                        "  MOV AH, 09h\n"
                        "  MOV CX, 0001h\n"
                        "  MOV BL, 07h\n"
                        "  INT 10h\n"
                        "  INC BYTE PTR [CURSOR_X]\n"
                        "  IRET\n"
                        "TTY_CR:\n"
                        "  MOV [CURSOR_X], 0\n"
                        "  IRET\n"
                        "TTY_LF:\n"
                        "  INC BYTE PTR [CURSOR_Y]\n"
                        "  IRET\n"
                        "TTY_BELL:\n"
                        "  PUSH BX\n"
                        "  MOV BX, 2000\n"
                        "  MOV AL, 0B6h\n"
                        "  OUT 43h, AL\n"
                        "  MOV AX, BX\n"
                        "  OUT 42h, AL\n"
                        "  MOV AL, AH\n"
                        "  OUT 42h, AL\n"
                        "  IN  AL, 61h\n"
                        "  OR  AL, 03h\n"
                        "  OUT 61h, AL\n"
                        "  POP BX\n"
                        "  IRET\n"
                        "WRITE_CHAR_ATTR:\n"
                        "  IRET\n"
                        "WRITE_CHAR_ONLY:\n"
                        "  IRET\n"
                        "SCROLL_UP:\n"
                        "  IRET\n"
                        "SCROLL_DN:\n"
                        "  IRET\n"
                        "WRITE_STRING:\n"
                        "  IRET\n"
                        ";\n"
                        "; ======== INT 12h: 检测内存大小 ========\n"
                        "INT_12:\n"
                        "  PUSH DS\n"
                        "  MOV AX, 0040h\n"
                        "  MOV DS, AX\n"
                        "  MOV AX, DS:[0013h]    ; 从 BIOS 数据区读\n"
                        "  POP DS\n"
                        "  IRET\n"
                        ";\n"
                        "; ======== INT 13h: 磁盘 I/O (完整调度) ========\n"
                        "INT_13:\n"
                        "  STI\n"
                        "  CMP AH, 00h           ; 复位磁盘系统\n"
                        "  JZ  DISK_RESET\n"
                        "  CMP AH, 01h           ; 读磁盘状态\n"
                        "  JZ  DISK_STATUS\n"
                        "  CMP AH, 02h           ; 读扇区\n"
                        "  JZ  DISK_READ\n"
                        "  CMP AH, 03h           ; 写扇区\n"
                        "  JZ  DISK_WRITE\n"
                        "  CMP AH, 04h           ; 校验扇区\n"
                        "  JZ  DISK_VERIFY\n"
                        "  CMP AH, 05h           ; 格式化磁道\n"
                        "  JZ  DISK_FORMAT\n"
                        "  CMP AH, 08h           ; 读取驱动器参数\n"
                        "  JZ  DISK_PARAM\n"
                        "  CMP AH, 09h           ; 初始化双驱动器\n"
                        "  JZ  DISK_INIT_PAIR\n"
                        "  CMP AH, 0Ch           ; 寻道\n"
                        "  JZ  DISK_SEEK\n"
                        "  CMP AH, 10h           ; 检测驱动器就绪\n"
                        "  JZ  DISK_READY\n"
                        "  CMP AH, 11h           ; 重新校准\n"
                        "  JZ  DISK_RECAL\n"
                        "  CMP AH, 15h           ; 读取 DASD 类型\n"
                        "  JZ  DISK_DASD\n"
                        "  STC                    ; 未知功能\n"
                        "  RETF 2\n"
                        ";\n"
                        "DISK_RESET:\n"
                        "  XOR AH, AH\n"
                        "  MOV [DISK_STATUS], 0\n"
                        "  RETF 2\n"
                        "DISK_STATUS:\n"
                        "  MOV AH, [DISK_STATUS]\n"
                        "  RETF 2\n"
                        "DISK_READ:\n"
                        "  PUSH DI\n"
                        "  PUSH BP\n"
                        "  MOV [DISK_STATUS], 0\n"
                        "  MOV DI, 0003h         ; 重试 3 次\n"
                        "DR_RETRY:\n"
                        "  CALL LBA_TO_CHS       ; 转换 LBA->CHS\n"
                        "  CALL ATA_READ\n"
                        "  JNC DR_OK\n"
                        "  DEC DI\n"
                        "  JNZ DR_RETRY\n"
                        "  MOV [DISK_STATUS], 10h\n"
                        "  STC\n"
                        "  POP BP\n"
                        "  POP DI\n"
                        "  RETF 2\n"
                        "DR_OK:\n"
                        "  MOV CX, [SEC_CNT]\n"
                        "  XOR AH, AH\n"
                        "  POP BP\n"
                        "  POP DI\n"
                        "  RETF 2\n"
                        ";\n"
                        "DISK_WRITE:\n"
                        "  PUSH DI\n"
                        "  MOV [DISK_STATUS], 0\n"
                        "  MOV DI, 0003h\n"
                        "DW_RETRY:\n"
                        "  CALL LBA_TO_CHS\n"
                        "  CALL ATA_WRITE\n"
                        "  JNC DW_OK\n"
                        "  DEC DI\n"
                        "  JNZ DW_RETRY\n"
                        "  MOV [DISK_STATUS], 0Ch\n"
                        "  STC\n"
                        "  POP DI\n"
                        "  RETF 2\n"
                        "DW_OK:\n"
                        "  XOR AH, AH\n"
                        "  POP DI\n"
                        "  RETF 2\n"
                        ";\n"
                        "DISK_VERIFY:\n"
                        "  RETF 2\n"
                        "DISK_FORMAT:\n"
                        "  RETF 2\n"
                        "DISK_INIT_PAIR:\n"
                        "  RETF 2\n"
                        "DISK_SEEK:\n"
                        "  RETF 2\n"
                        "DISK_READY:\n"
                        "  XOR AH, AH\n"
                        "  RETF 2\n"
                        "DISK_RECAL:\n"
                        "  RETF 2\n"
                        "DISK_DASD:\n"
                        "  CMP DL, 80h\n"
                        "  JB  FLOPPY_DASD\n"
                        "  MOV BL, 03h           ; 硬盘 DASD\n"
                        "  MOV CX, [DISK_SECTORS]\n"
                        "  RETF 2\n"
                        "FLOPPY_DASD:\n"
                        "  MOV BL, 04h           ; 1.44M 软盘\n"
                        "  MOV CX, 0B40h         ; 2880 扇区\n"
                        "  RETF 2\n"
                        ";\n"
                        "DISK_PARAM:\n"
                        "  MOV DL, 80h\n"
                        "  MOV DH, 0Fh           ; 16 磁头\n"
                        "  MOV CH, 03FFh         ; 1024 柱面\n"
                        "  MOV CL, 3Fh           ; 63 扇区/磁道\n"
                        "  XOR AH, AH\n"
                        "  RETF 2\n"
                        ";\n"
                        "; ======== INT 19h: 启动加载 ========\n"
                        "INT_19:\n"
                        "  STI\n"
                        "  MOV AX, 0000h\n"
                        "  MOV ES, AX\n"
                        "  MOV BX, 7C00h        ; 加载地址\n"
                        "  MOV CX, 0001h        ; 1 个扇区\n"
                        "  MOV DX, 0080h        ; 第一个硬盘\n"
                        "  MOV AH, 02h\n"
                        "  INT 13h\n"
                        "  JC  BOOT_FAIL\n"
                        "  JMP 0000h:7C00h      ; 跳转引导\n"
                        "BOOT_FAIL:\n"
                        "  INT 18h              ; ROM BASIC\n"
                        ";\n"
                        "; ======== 辅助子程序 ========\n"
                        "PRINT_STR:\n"
                        "  PUSH AX\n"
                        "  PUSH BX\n"
                        "  PUSH SI\n"
                        "  MOV AH, 0Eh\n"
                        "  MOV BX, 0007h        ; 灰色\n"
                        "PS_LOOP:\n"
                        "  LODSB\n"
                        "  CMP AL, '$'\n"
                        "  JZ  PS_DONE\n"
                        "  INT 10h\n"
                        "  JMP PS_LOOP\n"
                        "PS_DONE:\n"
                        "  POP SI\n"
                        "  POP BX\n"
                        "  POP AX\n"
                        "  RET\n"
                        ";\n"
                        "LBA_TO_CHS:\n"
                        "; 入口: AX = LBA, 出口: CH=柱面, CL=扇区, DH=磁头\n"
                        "  PUSH BX\n"
                        "  PUSH CX\n"
                        "  PUSH DX\n"
                        "  DIV BYTE PTR [SEC_PER_TRK]\n"
                        "  MOV CL, AH\n"
                        "  INC CL\n"
                        "  XOR AH, AH\n"
                        "  DIV BYTE PTR [HEADS]\n"
                        "  MOV DH, AH\n"
                        "  MOV CH, AL\n"
                        "  POP DX\n"
                        "  POP CX\n"
                        "  POP BX\n"
                        "  RET\n"
                        ";\n"
                        "ATA_READ:\n"
                        "  RET\n"
                        "ATA_WRITE:\n"
                        "  RET\n"
                        "READ_SECTORS:\n"
                        "  RET\n"
                        ";\n"
                        "INIT_PIC:\n"
                        "  MOV AL, 11h           ; ICW1: 边沿触发\n"
                        "  OUT 20h, AL\n"
                        "  MOV AL, 08h           ; ICW2: 中断基址 08h\n"
                        "  OUT 21h, AL\n"
                        "  MOV AL, 04h           ; ICW3: 从片在 IRQ2\n"
                        "  OUT 21h, AL\n"
                        "  MOV AL, 01h           ; ICW4: 8086 模式\n"
                        "  OUT 21h, AL\n"
                        "  MOV AL, 0FFh          ; 屏蔽所有 (之后逐位开启)\n"
                        "  OUT 21h, AL\n"
                        "  RET\n"
                        "INIT_TIMER:\n"
                        "  MOV AL, 36h           ; 计数器 0, 16位, 方波\n"
                        "  OUT 43h, AL\n"
                        "  MOV AX, 0000h         ; 65536 分频 (18.2Hz)\n"
                        "  OUT 40h, AL\n"
                        "  MOV AL, AH\n"
                        "  OUT 40h, AL\n"
                        "  RET\n"
                        "INIT_KBD:\n"
                        "  MOV AL, 0AEh          ; 启用键盘\n"
                        "  OUT 64h, AL\n"
                        "  RET\n"
                        "INIT_DISK:\n"
                        "  RET\n"
                        "INIT_CON:\n"
                        "  RET\n"
                        "INIT_PRN:\n"
                        "  RET\n"
                        "INIT_COM:\n"
                        "  RET\n"
                        "DETECT_MEMORY:\n"
                        "  INT 12h\n"
                        "  RET\n"
                        "DETECT_EQUIP:\n"
                        "  INT 11h\n"
                        "  RET\n"
                        "DETECT_DISK:\n"
                        "  MOV AH, 08h\n"
                        "  MOV DL, 80h\n"
                        "  INT 13h\n"
                        "  MOV AL, DL\n"
                        "  RET\n"
                        ";\n"
                        "; ---- BIOS 数据 ----\n"
                        "SYSMEM_K      DW 0640h        ; 常规内存 640K\n"
                        "EQUIP_FLAG    DW 0\n"
                        "DISK_COUNT    DB 0\n"
                        "DISK_STATUS   DB 0\n"
                        "DISK_SECTORS  DW 0\n"
                        "CRT_MODE      DB 03h\n"
                        "CURSOR_SLINE  DB 0\n"
                        "CURSOR_ELINE  DB 07h\n"
                        "CURSOR_X      DB 0\n"
                        "CURSOR_Y      DB 0\n"
                        "CURSOR_START  DW 0707h\n"
                        "SEC_PER_TRK   DB 3Fh\n"
                        "HEADS         DB 10h\n"
                        "SEC_CNT       DW 0001h\n"
                        "DISK_BUF      DB 512 DUP (?)\n"
                        ";\n"
                        "SEGMENT ENDS\n"
                        "END SYSINIT\n",
                        system=True, protected=True)
        self.write_file(("C", ["MSDOS.SYS"]),
                        "; katoDoS MSDOS.SYS — DOS 内核 (v1.0)\n"
                        "; 伪源码：文件系统 / 进程管理 / DOS API 中断\n"
                        "; 反汇编 kato 2026\n"
                        ";\n"
                        "SEGMENT _TEXT PARA PUBLIC 'CODE'\n"
                        "  ASSUME CS:_TEXT, DS:_TEXT, ES:_TEXT\n"
                        ";\n"
                        "  ORG 0000h\n"
                        "  DB 'katoDoS MSDOS.SYS 1.0'\n"
                        "  DB 0Dh, 0Ah\n"
                        "  DB 'Copyright (C) 2026 kato'\n"
                        "  DB 0Dh, 0Ah\n"
                        "  DB 'Kernel build: 2026-07-18'\n"
                        "  DB 0Dh, 0Ah\n"
                        ";\n"
                        "; ---- DOS 内核主入口 (由 IO.SYS 调用) ----\n"
                        "MSDOS_INIT:\n"
                        "  MOV AX, CS\n"
                        "  MOV DS, AX\n"
                        "  MOV ES, AX\n"
                        ";\n"
                        "; ---- 初始化 DOS 内核数据结构 ----\n"
                        "  CALL INIT_CDS            ; 初始化当前目录结构 (CDS)\n"
                        "  CALL INIT_SFT            ; 初始化系统文件表 (SFT)\n"
                        "  CALL INIT_DPB            ; 初始化磁盘参数块 (DPB)\n"
                        "  CALL INIT_FCB            ; 初始化文件控制块 (FCB)\n"
                        "  CALL INIT_PSP            ; 初始化程序段前缀 (PSP)\n"
                        "  CALL INIT_ENV            ; 初始化环境字符串\n"
                        ";\n"
                        "; ---- 建立 DOS 中断 ----\n"
                        "  PUSH DS\n"
                        "  XOR AX, AX\n"
                        "  MOV DS, AX\n"
                        "  MOV WORD PTR DS:[0084h], INT_21  ; INT 21h - DOS API 主入口\n"
                        "  MOV WORD PTR DS:[0088h], INT_22  ; INT 22h - 程序终止退出\n"
                        "  MOV WORD PTR DS:[008Ch], INT_23  ; INT 23h - Ctrl-C 处理\n"
                        "  MOV WORD PTR DS:[0090h], INT_24  ; INT 24h - 致命错误处理\n"
                        "  MOV WORD PTR DS:[0014h], INT_25  ; INT 25h - 绝对磁盘读\n"
                        "  MOV WORD PTR DS:[0018h], INT_26  ; INT 26h - 绝对磁盘写\n"
                        "  MOV WORD PTR DS:[001Ch], INT_27  ; INT 27h - 终止并驻留\n"
                        "  MOV WORD PTR DS:[0020h], INT_28  ; INT 28h - 空闲中断\n"
                        "  MOV WORD PTR DS:[0024h], INT_29  ; INT 29h - 快速控制台\n"
                        "  MOV WORD PTR DS:[0028h], INT_2A  ; INT 2Ah - 网络重定向\n"
                        "  MOV WORD PTR DS:[002Ch], INT_2E  ; INT 2Eh - 命令执行\n"
                        "  MOV AX, CS\n"
                        "  MOV DS:[0086h], AX\n"
                        "  MOV DS:[008Ah], AX\n"
                        "  MOV DS:[008Eh], AX\n"
                        "  MOV DS:[0092h], AX\n"
                        "  POP DS\n"
                        ";\n"
                        "; ---- 建立标准文件句柄 ----\n"
                        "  MOV CX, 0005h            ; STDIN / STDOUT / STDERR / AUX / PRN\n"
                        "  MOV SI, OFFSET CON_HDR\n"
                        "HANDLE_LOOP:\n"
                        "  CALL SFT_INSTALL         ; 安装句柄\n"
                        "  LOOP HANDLE_LOOP\n"
                        ";\n"
                        "  MOV DX, OFFSET COPY_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h                  ; 打印启动信息\n"
                        ";\n"
                        "  MOV AH, 4Ah              ; 调整内存块\n"
                        "  MOV BX, 0FFFFh\n"
                        "  INT 21h\n"
                        "  SUB BX, 0200h            ; 保留 512 字节\n"
                        "  MOV AH, 4Ah\n"
                        "  INT 21h\n"
                        ";\n"
                        "; 加载 COMMAND.COM 暂驻部分\n"
                        "  MOV DX, OFFSET CMD_SPEC\n"
                        "  MOV AX, 3D00h\n"
                        "  INT 21h\n"
                        "  JC  CMD_ERR\n"
                        "  MOV BX, AX\n"
                        "  MOV CX, 2000h\n"
                        "  MOV DX, 8000h\n"
                        "  MOV AH, 3Fh\n"
                        "  INT 21h\n"
                        "  MOV AH, 3Eh\n"
                        "  INT 21h\n"
                        "  CALL 8000h               ; 执行 COMMAND.COM\n"
                        "CMD_ERR:\n"
                        "  MOV DX, OFFSET CMD_FAIL\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  STI\n"
                        "  JMP $\n"
                        ";\n"
                        "; ======== INT 21h: DOS API 主调度 (功能号表) ========\n"
                        "INT_21:\n"
                        "  STI\n"
                        "  PUSH SI\n"
                        "  PUSH DI\n"
                        "  PUSH BP\n"
                        ";\n"
                        "; ---- 功能号 00h-0Fh: 传统 DOS 1.x ----\n"
                        "  CMP AH, 00h           ; 程序终止 (同 INT 20h)\n"
                        "  JZ  FUNC_00\n"
                        "  CMP AH, 01h           ; 从 STDIN 读字符并回显\n"
                        "  JZ  FUNC_01\n"
                        "  CMP AH, 02h           ; 写字符到 STDOUT\n"
                        "  JZ  FUNC_02\n"
                        "  CMP AH, 03h           ; 从 AUX 读字符\n"
                        "  JZ  FUNC_03\n"
                        "  CMP AH, 04h           ; 写字符到 AUX\n"
                        "  JZ  FUNC_04\n"
                        "  CMP AH, 05h           ; 写字符到 PRN\n"
                        "  JZ  FUNC_05\n"
                        "  CMP AH, 06h           ; 直接控制台 I/O\n"
                        "  JZ  FUNC_06\n"
                        "  CMP AH, 07h           ; 从 STDIN 读字符 (无回显)\n"
                        "  JZ  FUNC_07\n"
                        "  CMP AH, 08h           ; 读字符 (无回显, 检测 Ctrl-C)\n"
                        "  JZ  FUNC_08\n"
                        "  CMP AH, 09h           ; 写字符串 (以 $ 结尾)\n"
                        "  JZ  FUNC_09\n"
                        "  CMP AH, 0Ah           ; 缓冲行输入\n"
                        "  JZ  FUNC_0A\n"
                        "  CMP AH, 0Bh           ; 检查 STDIN 状态\n"
                        "  JZ  FUNC_0B\n"
                        "  CMP AH, 0Ch           ; 清缓冲并读\n"
                        "  JZ  FUNC_0C\n"
                        "  CMP AH, 0Dh           ; 磁盘复位\n"
                        "  JZ  FUNC_0D\n"
                        "  CMP AH, 0Eh           ; 设置默认驱动器\n"
                        "  JZ  FUNC_0E\n"
                        "  CMP AH, 0Fh           ; 打开文件 (FCB)\n"
                        "  JZ  FUNC_0F\n"
                        ";\n"
                        "; ---- 功能号 19h-2Ch: DOS 2.x ----\n"
                        "  CMP AH, 19h           ; 获取当前驱动器\n"
                        "  JZ  FUNC_19\n"
                        "  CMP AH, 1Ah           ; 设置 DTA\n"
                        "  JZ  FUNC_1A\n"
                        "  CMP AH, 25h           ; 设置中断向量\n"
                        "  JZ  FUNC_25\n"
                        "  CMP AH, 26h           ; 创建新的 PSP\n"
                        "  JZ  FUNC_26\n"
                        "  CMP AH, 2Ah           ; 获取系统日期\n"
                        "  JZ  FUNC_2A\n"
                        "  CMP AH, 2Bh           ; 设置系统日期\n"
                        "  JZ  FUNC_2B\n"
                        "  CMP AH, 2Ch           ; 获取系统时间\n"
                        "  JZ  FUNC_2C\n"
                        "  CMP AH, 2Dh           ; 设置系统时间\n"
                        "  JZ  FUNC_2D\n"
                        "  CMP AH, 2Eh           ; 设置验证标志\n"
                        "  JZ  FUNC_2E\n"
                        ";\n"
                        "; ---- 功能号 30h-44h: DOS 3.x 文件句柄 API ----\n"
                        "  CMP AH, 30h           ; 获取 DOS 版本\n"
                        "  JZ  FUNC_30\n"
                        "  CMP AH, 31h           ; 终止并驻留 (TSR)\n"
                        "  JZ  FUNC_31\n"
                        "  CMP AH, 33h           ; Ctrl-Break 检测\n"
                        "  JZ  FUNC_33\n"
                        "  CMP AH, 35h           ; 获取中断向量\n"
                        "  JZ  FUNC_35\n"
                        "  CMP AH, 36h           ; 获取磁盘空闲空间\n"
                        "  JZ  FUNC_36\n"
                        "  CMP AH, 38h           ; 获取国家信息\n"
                        "  JZ  FUNC_38\n"
                        "  CMP AH, 39h           ; 创建目录 (MKDIR)\n"
                        "  JZ  FUNC_39\n"
                        "  CMP AH, 3Ah           ; 删除目录 (RMDIR)\n"
                        "  JZ  FUNC_3A\n"
                        "  CMP AH, 3Bh           ; 改变当前目录 (CHDIR)\n"
                        "  JZ  FUNC_3B\n"
                        "  CMP AH, 3Ch           ; 创建文件 (CREATE)\n"
                        "  JZ  FUNC_3C\n"
                        "  CMP AH, 3Dh           ; 打开文件 (OPEN)\n"
                        "  JZ  FUNC_3D\n"
                        "  CMP AH, 3Eh           ; 关闭文件 (CLOSE)\n"
                        "  JZ  FUNC_3E\n"
                        "  CMP AH, 3Fh           ; 读文件 (READ)\n"
                        "  JZ  FUNC_3F\n"
                        "  CMP AH, 40h           ; 写文件 (WRITE)\n"
                        "  JZ  FUNC_40\n"
                        "  CMP AH, 41h           ; 删除文件 (UNLINK)\n"
                        "  JZ  FUNC_41\n"
                        "  CMP AH, 42h           ; 移动文件指针 (LSEEK)\n"
                        "  JZ  FUNC_42\n"
                        "  CMP AH, 43h           ; 获取/设置文件属性\n"
                        "  JZ  FUNC_43\n"
                        "  CMP AH, 44h           ; IOCTL 控制\n"
                        "  JZ  FUNC_44\n"
                        ";\n"
                        "; ---- 功能号 45h-4Ch: DOS 3.x+ ----\n"
                        "  CMP AH, 45h           ; 复制句柄 (DUP)\n"
                        "  JZ  FUNC_45\n"
                        "  CMP AH, 46h           ; 强制复制句柄 (DUP2)\n"
                        "  JZ  FUNC_46\n"
                        "  CMP AH, 47h           ; 获取当前目录\n"
                        "  JZ  FUNC_47\n"
                        "  CMP AH, 48h           ; 分配内存 (ALLOC)\n"
                        "  JZ  FUNC_48\n"
                        "  CMP AH, 49h           ; 释放内存 (FREE)\n"
                        "  JZ  FUNC_49\n"
                        "  CMP AH, 4Ah           ; 调整内存块 (REALLOC)\n"
                        "  JZ  FUNC_4A\n"
                        "  CMP AH, 4Bh           ; 加载并执行 (EXEC)\n"
                        "  JZ  FUNC_4B\n"
                        "  CMP AH, 4Ch           ; 带返回码退出\n"
                        "  JZ  FUNC_4C\n"
                        "  CMP AH, 4Dh           ; 获取子进程返回码\n"
                        "  JZ  FUNC_4D\n"
                        "  CMP AH, 4Eh           ; 查找第一个匹配 (FINDFIRST)\n"
                        "  JZ  FUNC_4E\n"
                        "  CMP AH, 4Fh           ; 查找下一个匹配 (FINDNEXT)\n"
                        "  JZ  FUNC_4F\n"
                        "  CMP AH, 54h           ; 获取验证标志\n"
                        "  JZ  FUNC_54\n"
                        "  CMP AH, 56h           ; 重命名文件 (RENAME)\n"
                        "  JZ  FUNC_56\n"
                        "  CMP AH, 57h           ; 获取/设置文件日期与时间\n"
                        "  JZ  FUNC_57\n"
                        "  CMP AH, 58h           ; 获取/设置分配策略\n"
                        "  JZ  FUNC_58\n"
                        "  CMP AH, 59h           ; 获取扩展错误\n"
                        "  JZ  FUNC_59\n"
                        "  CMP AH, 5Ah           ; 创建临时文件\n"
                        "  JZ  FUNC_5A\n"
                        "  CMP AH, 5Bh           ; 创建新文件 (排他)\n"
                        "  JZ  FUNC_5B\n"
                        "  CMP AH, 5Ch           ; 文件区域锁定\n"
                        "  JZ  FUNC_5C\n"
                        "  CMP AH, 5Dh           ; 系统调用\n"
                        "  JZ  FUNC_5D\n"
                        "  CMP AH, 5Eh           ; 网络/打印机重定向\n"
                        "  JZ  FUNC_5E\n"
                        "  CMP AH, 5Fh           ; 获取/设置重定向列表\n"
                        "  JZ  FUNC_5F\n"
                        "  CMP AH, 62h           ; 获取 PSP 地址\n"
                        "  JZ  FUNC_62\n"
                        "  CMP AH, 65h           ; 获取扩展国家信息\n"
                        "  JZ  FUNC_65\n"
                        "  CMP AH, 66h           ; 获取/设置代码页\n"
                        "  JZ  FUNC_66\n"
                        "  CMP AH, 67h           ; 设置句柄数量\n"
                        "  JZ  FUNC_67\n"
                        "  CMP AH, 68h           ; 提交文件 (COMMIT)\n"
                        "  JZ  FUNC_68\n"
                        "  CMP AH, 6Ch           ; 扩展打开 (OPEN/CREATE)\n"
                        "  JZ  FUNC_6C\n"
                        "  MOV AL, 00h            ; 未知功能: 返回 0\n"
                        "  JMP FUNC_EXIT\n"
                        ";\n"
                        "; ---- 功能实现 (桩) ----\n"
                        "FUNC_00: JMP TERMINATE\n"
                        "FUNC_01: MOV AH, 01h\n"
                        "         INT 16h\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_02: PUSH BX\n"
                        "         MOV BX, 0007h\n"
                        "         MOV AH, 0Eh\n"
                        "         INT 10h\n"
                        "         POP BX\n"
                        "         XOR AX, AX\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_09: PUSH AX\n"
                        "         PUSH BX\n"
                        "         PUSH SI\n"
                        "         MOV SI, DX\n"
                        "F9_LOOP: LODSB\n"
                        "         CMP AL, '$'\n"
                        "         JZ  F9_DONE\n"
                        "         MOV BX, 0007h\n"
                        "         MOV AH, 0Eh\n"
                        "         INT 10h\n"
                        "         JMP F9_LOOP\n"
                        "F9_DONE:\n"
                        "         POP SI\n"
                        "         POP BX\n"
                        "         POP AX\n"
                        "         XOR AX, AX\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_0A: RETF 2\n"
                        "FUNC_0B: MOV AL, 00h\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_0C: RETF 2\n"
                        "FUNC_0D: RETF 2\n"
                        "FUNC_0E: RETF 2\n"
                        "FUNC_0F: RETF 2\n"
                        "FUNC_19: MOV AL, [DEFAULT_DRV]\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_1A: MOV [DTA_ADDR], DX\n"
                        "         XOR AX, AX\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_25: PUSH ES\n"
                        "         XOR AX, AX\n"
                        "         MOV ES, AX\n"
                        "         SHL BX, 2\n"
                        "         MOV ES:[BX], DX\n"
                        "         MOV ES:[BX+2], DS\n"
                        "         POP ES\n"
                        "         XOR AX, AX\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_26: RETF 2\n"
                        "FUNC_2A: MOV CX, 07CEh    ; 2026\n"
                        "         MOV DH, 07h       ; 7月\n"
                        "         MOV DL, 12h       ; 18日\n"
                        "         XOR AX, AX\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_2B: XOR AX, AX\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_2C: MOV CH, 0Eh\n"
                        "         MOV CL, 06h\n"
                        "         MOV DH, 2Fh\n"
                        "         XOR AX, AX\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_2D: XOR AX, AX\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_2E: RETF 2\n"
                        "FUNC_30: MOV AX, 0A00h    ; DOS 10.0\n"
                        "         MOV BX, 0000h\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_31: RETF 2\n"
                        "FUNC_33: RETF 2\n"
                        "FUNC_35: RETF 2\n"
                        "FUNC_36: MOV AX, 0FFF7h   ; 可用簇\n"
                        "         MOV BX, 0001h     ; 每簇扇区\n"
                        "         MOV CX, 0200h     ; 每扇区字节\n"
                        "         MOV DX, 03FFh     ; 总簇数\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_38: RETF 2\n"
                        "FUNC_39: MOV AX, 0000h\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_3A: MOV AX, 0000h\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_3B: MOV AX, 0000h\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_3C: MOV AX, 0005h\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_3D: MOV AX, 0000h\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_3E: XOR AX, AX\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_3F: XOR AX, AX\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_40: MOV AX, CX\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_41: XOR AX, AX\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_42: XOR AX, AX\n"
                        "         XOR DX, DX\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_43: RETF 2\n"
                        "FUNC_44: RETF 2\n"
                        "FUNC_45: MOV AX, SRC_HANDLE\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_46: RETF 2\n"
                        "FUNC_47: MOV BYTE PTR [DI], 'A'\n"
                        "         XOR AX, AX\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_48: MOV AX, 0008h\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_49: XOR AX, AX\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_4A: XOR AX, AX\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_4B: RETF 2\n"
                        "FUNC_4C: JMP TERMINATE\n"
                        "FUNC_4D: MOV AX, [RET_CODE]\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_4E: RETF 2\n"
                        "FUNC_4F: RETF 2\n"
                        "FUNC_54: MOV AL, [VERIFY_FLAG]\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_56: RETF 2\n"
                        "FUNC_57: RETF 2\n"
                        "FUNC_58: RETF 2\n"
                        "FUNC_59: MOV AX, 0000h    ; 无错误\n"
                        "         MOV BX, 0000h\n"
                        "         MOV CH, 00h\n"
                        "         MOV DX, 0000h\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_5A: RETF 2\n"
                        "FUNC_5B: RETF 2\n"
                        "FUNC_5C: RETF 2\n"
                        "FUNC_5D: RETF 2\n"
                        "FUNC_5E: RETF 2\n"
                        "FUNC_5F: RETF 2\n"
                        "FUNC_62: MOV BX, [CUR_PSP]\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_65: RETF 2\n"
                        "FUNC_66: RETF 2\n"
                        "FUNC_67: RETF 2\n"
                        "FUNC_68: XOR AX, AX\n"
                        "         JMP FUNC_EXIT\n"
                        "FUNC_6C: RETF 2\n"
                        ";\n"
                        "TERMINATE:\n"
                        "  MOV [RET_CODE], AL\n"
                        "FUNC_EXIT:\n"
                        "  POP BP\n"
                        "  POP DI\n"
                        "  POP SI\n"
                        "  RETF 2\n"
                        ";\n"
                        "; ======== INT 24h: 致命错误处理 ========\n"
                        "INT_24:\n"
                        "  MOV AL, 03h            ; 忽略\n"
                        "  IRET\n"
                        ";\n"
                        "; ---- 内部初始化子程序 ----\n"
                        "INIT_CDS:\n"
                        "  MOV CX, 0005h\n"
                        "  MOV DI, OFFSET CDS_TABLE\n"
                        "IC_LOOP:\n"
                        "  MOV BYTE PTR [DI], 'C'\n"
                        "  MOV BYTE PTR [DI+1], ':'\n"
                        "  MOV BYTE PTR [DI+2], '\\'\n"
                        "  ADD DI, 0051h          ; 每个 CDS 81 字节\n"
                        "  LOOP IC_LOOP\n"
                        "  RET\n"
                        "INIT_SFT:\n"
                        "  MOV CX, 0014h          ; 20 个 SFT 入口\n"
                        "  MOV DI, OFFSET SFT_TABLE\n"
                        "IS_LOOP:\n"
                        "  MOV BYTE PTR [DI], 0   ; 未使用\n"
                        "  ADD DI, 0035h          ; 每个 53 字节\n"
                        "  LOOP IS_LOOP\n"
                        "  RET\n"
                        "INIT_DPB:\n"
                        "  MOV CX, 0005h\n"
                        "  MOV DI, OFFSET DPB_TABLE\n"
                        "ID_LOOP:\n"
                        "  MOV BYTE PTR [DI], 0\n"
                        "  ADD DI, 0014h\n"
                        "  LOOP ID_LOOP\n"
                        "  RET\n"
                        "INIT_FCB:\n"
                        "  MOV CX, 0010h\n"
                        "  MOV DI, OFFSET FCB_TABLE\n"
                        "  RET\n"
                        "INIT_PSP:\n"
                        "  MOV WORD PTR [CUR_PSP], 0008h\n"
                        "  RET\n"
                        "INIT_ENV:\n"
                        "  RET\n"
                        "SFT_INSTALL:\n"
                        "  RET\n"
                        ";\n"
                        "; ---- INT 22h-29h 空桩 ----\n"
                        "INT_22: IRET\n"
                        "INT_23: IRET\n"
                        "INT_25: STC\n"
                        "        RETF 2\n"
                        "INT_26: STC\n"
                        "        RETF 2\n"
                        "INT_27: IRET\n"
                        "INT_28: IRET\n"
                        "INT_29: IRET\n"
                        "INT_2A: IRET\n"
                        "INT_2E: IRET\n"
                        ";\n"
                        "; ---- 数据区 ----\n"
                        "COPY_MSG    DB 'katoDoS MSDOS kernel loaded', 0Dh, 0Ah\n"
                        "            DB 'DOS API v10.0 ready', 0Dh, 0Ah, '$'\n"
                        "CMD_SPEC    DB 'C:\\COMMAND.COM', 0\n"
                        "CMD_FAIL    DB 'COMMAND.COM load failed', 0Dh, 0Ah, '$'\n"
                        "CON_HDR     DB 0, 0, 0, 0, 0\n"
                        "DEFAULT_DRV DB 2          ; C:=2\n"
                        "VERIFY_FLAG DB 0\n"
                        "DTA_ADDR    DW 0000h\n"
                        "CUR_PSP     DW 0008h\n"
                        "RET_CODE    DB 0\n"
                        "SRC_HANDLE  DW 0\n"
                        "CDS_TABLE   DB 280h DUP (?)\n"
                        "SFT_TABLE   DB 400h DUP (?)\n"
                        "DPB_TABLE   DB 080h DUP (?)\n"
                        "FCB_TABLE   DB 100h DUP (?)\n"
                        ";\n"
                        "SEGMENT ENDS\n"
                        "END MSDOS_INIT\n",
                        system=True, protected=True)
        self.write_file(("C", ["COMMAND.COM"]),
                        "; katoDoS COMMAND.COM — 命令解释器 (v1.0)\n"
                        "; 伪源码：命令行解析 / 批量加载 / 内部命令 / 环境管理\n"
                        "; 反汇编 kato 2026\n"
                        ";\n"
                        "SEGMENT _TEXT PARA PUBLIC 'CODE'\n"
                        "  ASSUME CS:_TEXT, DS:_TEXT, ES:_TEXT, SS:_STACK\n"
                        ";\n"
                        "  ORG 0100h              ; .COM 格式偏移\n"
                        ";\n"
                        "; ---- 版本签名 ----\n"
                        "  DB 'katoDoS COMMAND.COM v1.0'\n"
                        "  DB 0Dh, 0Ah\n"
                        "  DB 'Copyright 2026 kato'\n"
                        "  DB 0Dh, 0Ah\n"
                        "  DB 'Build: 2026-07-18'\n"
                        "  DB 0Dh, 0Ah\n"
                        ";\n"
                        "; ---- 常驻区入口 (不覆盖暂驻区)----\n"
                        "  JMP INIT\n"
                        "  NOP\n"
                        "; ---- 常驻区数据 ----\n"
                        "RES_FLAG  DB 'RE'\n"
                        "RES_PSP   DW 0\n"
                        "RES_TAIL  DW 0\n"
                        "ENV_SEG   DW 0\n"
                        ";\n"
                        "; ---- 初始化入口 ----\n"
                        "INIT:\n"
                        "  MOV AX, CS\n"
                        "  MOV DS, AX\n"
                        "  MOV ES, AX\n"
                        ";\n"
                        "  CALL PSP_INIT           ; 初始化程序段前缀\n"
                        "  CALL ENV_INIT           ; 初始化环境块\n"
                        "  CALL SETUP_INT_HANDLERS ; 设置 INT 22h-24h\n"
                        "  CALL LOAD_RESIDENT      ; 加载常驻部分\n"
                        ";\n"
                        "  MOV DX, OFFSET COPY_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  JMP MAIN_LOOP\n"
                        ";\n"
                        "; ========== 暂驻区: 内部命令表 ==========\n"
                        "CMD_TABLE:\n"
                        "  DB 'BREAK', 0,  0\n"
                        "  DW CMD_BREAK\n"
                        "  DB 'CALL', 0,   0\n"
                        "  DW CMD_CALL\n"
                        "  DB 'CHCP', 0,   0\n"
                        "  DW CMD_CHCP\n"
                        "  DB 'CHDIR',0,   0\n"
                        "  DW CMD_CD\n"
                        "  DB 'CLS', 0,    0\n"
                        "  DW CMD_CLS\n"
                        "  DB 'COPY', 0,   0\n"
                        "  DW CMD_COPY\n"
                        "  DB 'CTTY', 0,   0\n"
                        "  DW CMD_CTTY\n"
                        "  DB 'DATE', 0,   0\n"
                        "  DW CMD_DATE\n"
                        "  DB 'DEL', 0,    0\n"
                        "  DW CMD_DEL\n"
                        "  DB 'DIR', 0,    0\n"
                        "  DW CMD_DIR\n"
                        "  DB 'ECHO', 0,   0\n"
                        "  DW CMD_ECHO\n"
                        "  DB 'ERASE',0,   0\n"
                        "  DW CMD_DEL\n"
                        "  DB 'EXIT', 0,   0\n"
                        "  DW CMD_EXIT\n"
                        "  DB 'FOR', 0,    0\n"
                        "  DW CMD_FOR\n"
                        "  DB 'GOTO', 0,   0\n"
                        "  DW CMD_GOTO\n"
                        "  DB 'IF', 0,     0\n"
                        "  DW CMD_IF\n"
                        "  DB 'MD', 0,     0\n"
                        "  DW CMD_MD\n"
                        "  DB 'MKDIR',0,   0\n"
                        "  DW CMD_MD\n"
                        "  DB 'MEM', 0,    0\n"
                        "  DW CMD_MEM\n"
                        "  DB 'PATH', 0,   0\n"
                        "  DW CMD_PATH\n"
                        "  DB 'PAUSE',0,   0\n"
                        "  DW CMD_PAUSE\n"
                        "  DB 'PROMPT',0,  0\n"
                        "  DW CMD_PROMPT\n"
                        "  DB 'RD', 0,     0\n"
                        "  DW CMD_RD\n"
                        "  DB 'REM', 0,    0\n"
                        "  DW CMD_REM\n"
                        "  DB 'REN', 0,    0\n"
                        "  DW CMD_REN\n"
                        "  DB 'RMDIR',0,   0\n"
                        "  DW CMD_RD\n"
                        "  DB 'SET', 0,    0\n"
                        "  DW CMD_SET\n"
                        "  DB 'SHIFT',0,   0\n"
                        "  DW CMD_SHIFT\n"
                        "  DB 'TIME', 0,   0\n"
                        "  DW CMD_TIME\n"
                        "  DB 'TYPE', 0,   0\n"
                        "  DW CMD_TYPE\n"
                        "  DB 'VER', 0,    0\n"
                        "  DW CMD_VER\n"
                        "  DB 'VERIFY',0,  0\n"
                        "  DW CMD_VERIFY\n"
                        "  DB 'VOL', 0,    0\n"
                        "  DW CMD_VOL\n"
                        "  DB 0FFh          ; 表结束\n"
                        ";\n"
                        "; ========== 主体循环 (多次暂驻) ==========\n"
                        "MAIN_LOOP:\n"
                        "  CALL PROMPT_PRINT       ; 显示提示符\n"
                        "  MOV DX, OFFSET INBUF\n"
                        "  MOV AH, 0Ah\n"
                        "  INT 21h                 ; 读取输入\n"
                        ";\n"
                        "  CALL STRIP_CRLF         ; 去掉 CR/LF\n"
                        "  CALL TOUPPER            ; 转大写\n"
                        "  CALL PARSE_LINE         ; 解析命令与参数\n"
                        "  JC  MAIN_LOOP           ; 空行\n"
                        ";\n"
                        "  CALL CHECK_RESIDENT     ; 检查是否是常驻命令\n"
                        "  JC  CMD_RESIDENT\n"
                        ";\n"
                        "  MOV SI, OFFSET CMD_TABLE\n"
                        "CT_SEARCH:\n"
                        "  CMP BYTE PTR [SI], 0FFh\n"
                        "  JZ  TRY_EXTERNAL        ; 表尾?\n"
                        "  CALL CMP_CMD\n"
                        "  JZ  CMD_FOUND\n"
                        "  XOR AX, AX\n"
                        "  LODSW                   ; 跳过命令名\n"
                        "  LODSW                   ; 跳过地址\n"
                        "  JMP CT_SEARCH\n"
                        "CMD_FOUND:\n"
                        "  LODSW                   ; 取地址到 DI\n"
                        "  MOV DI, AX\n"
                        "  CALL [DI]               ; 执行\n"
                        "  JMP MAIN_LOOP\n"
                        ";\n"
                        "CMD_RESIDENT:\n"
                        "  CALL [RES_ENTRY]\n"
                        "  JMP MAIN_LOOP\n"
                        ";\n"
                        "TRY_EXTERNAL:\n"
                        "  CALL SEARCH_PATH        ; 搜索 PATH 目录\n"
                        "  JC  TRY_CURDIR\n"
                        "  CALL LOAD_AND_EXEC      ; 加载.COM/.EXE\n"
                        "  JMP MAIN_LOOP\n"
                        "TRY_CURDIR:\n"
                        "  CALL SEARCH_CURDIR\n"
                        "  JC  CMD_NOT_FOUND\n"
                        "  CALL LOAD_AND_EXEC\n"
                        "  JMP MAIN_LOOP\n"
                        ";\n"
                        "CMD_NOT_FOUND:\n"
                        "  MOV DX, OFFSET BAD_CMD\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  JMP MAIN_LOOP\n"
                        ";\n"
                        "; ========== 内部命令实现 ==========\n"
                        "CMD_DIR:\n"
                        "  MOV DX, OFFSET CRLF\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  MOV DX, OFFSET DIR_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        ";\n"
                        "CMD_CD:\n"
                        "  MOV DX, OFFSET CUR_DIR\n"
                        "  MOV AH, 47h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        ";\n"
                        "CMD_MD:\n"
                        "  MOV DX, OFFSET CMD_TAIL\n"
                        "  MOV AH, 39h\n"
                        "  INT 21h\n"
                        "  JC  MD_FAIL\n"
                        "  RET\n"
                        "MD_FAIL:\n"
                        "  MOV DX, OFFSET ERR_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        ";\n"
                        "CMD_RD:\n"
                        "  MOV DX, OFFSET CMD_TAIL\n"
                        "  MOV AH, 3Ah\n"
                        "  INT 21h\n"
                        "  JC  RD_FAIL\n"
                        "  RET\n"
                        "RD_FAIL:\n"
                        "  MOV DX, OFFSET ERR_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        ";\n"
                        "CMD_COPY:\n"
                        "  MOV DX, OFFSET COPY_SRC\n"
                        "  MOV AX, 3D00h\n"
                        "  INT 21h\n"
                        "  JC  CPY_FAIL\n"
                        "  MOV BX, AX\n"
                        "  MOV DX, OFFSET COPY_BUF\n"
                        "  MOV CX, 0FFFFh\n"
                        "  MOV AH, 3Fh\n"
                        "  INT 21h\n"
                        "  MOV CX, AX\n"
                        "  MOV AH, 3Eh\n"
                        "  INT 21h\n"
                        "  MOV DX, OFFSET COPY_DST\n"
                        "  MOV AX, 3C00h\n"
                        "  INT 21h\n"
                        "  JC  CPY_FAIL\n"
                        "  MOV BX, AX\n"
                        "  MOV DX, OFFSET COPY_BUF\n"
                        "  MOV AH, 40h\n"
                        "  INT 21h\n"
                        "  MOV AH, 3Eh\n"
                        "  INT 21h\n"
                        "  MOV DX, OFFSET CPY_OK\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "CPY_FAIL:\n"
                        "  MOV DX, OFFSET CPY_ERR\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        ";\n"
                        "CMD_DEL:\n"
                        "  MOV DX, OFFSET CMD_TAIL\n"
                        "  MOV AH, 41h\n"
                        "  INT 21h\n"
                        "  JC  DEL_FAIL\n"
                        "  RET\n"
                        "DEL_FAIL:\n"
                        "  MOV DX, OFFSET ERR_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        ";\n"
                        "CMD_TYPE:\n"
                        "  MOV DX, OFFSET CMD_TAIL\n"
                        "  MOV AX, 3D00h\n"
                        "  INT 21h\n"
                        "  JC  TYPE_FAIL\n"
                        "  MOV BX, AX\n"
                        "TYPE_LOOP:\n"
                        "  MOV CX, 0001h\n"
                        "  MOV DX, OFFSET TYPE_BUF\n"
                        "  MOV AH, 3Fh\n"
                        "  INT 21h\n"
                        "  JC  TYPE_DONE\n"
                        "  CMP AX, 00h\n"
                        "  JZ  TYPE_DONE\n"
                        "  MOV AL, [TYPE_BUF]\n"
                        "  CMP AL, 1Ah           ; EOF\n"
                        "  JZ  TYPE_DONE\n"
                        "  PUSH BX\n"
                        "  MOV BX, 0007h\n"
                        "  MOV AH, 0Eh\n"
                        "  INT 10h\n"
                        "  POP BX\n"
                        "  JMP TYPE_LOOP\n"
                        "TYPE_DONE:\n"
                        "  MOV AH, 3Eh\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "TYPE_FAIL:\n"
                        "  MOV DX, OFFSET BAD_FILE\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        ";\n"
                        "CMD_REN:\n"
                        "  RET\n"
                        "CMD_DATE:\n"
                        "  MOV AH, 2Ah\n"
                        "  INT 21h\n"
                        "  ADD CX, 0F830h     ; 2026 = 07CEh\n"
                        "  RET\n"
                        "CMD_TIME:\n"
                        "  MOV AH, 2Ch\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "CMD_MEM:\n"
                        "  INT 12h\n"
                        "  PUSH AX\n"
                        "  MOV DX, OFFSET MEM_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  POP AX\n"
                        "  CALL PRINT_AX\n"
                        "  MOV DX, OFFSET KB_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        ";\n"
                        "CMD_VER:\n"
                        "  MOV DX, OFFSET COPY_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        ";\n"
                        "CMD_CLS:\n"
                        "  MOV AX, 0600h\n"
                        "  MOV BH, 07h\n"
                        "  XOR CX, CX\n"
                        "  MOV DX, 184Fh\n"
                        "  INT 10h\n"
                        "  MOV DX, 0000h\n"
                        "  MOV AH, 02h\n"
                        "  INT 10h\n"
                        "  RET\n"
                        ";\n"
                        "CMD_PATH:\n"
                        "  MOV DX, OFFSET PATH_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "CMD_PROMPT:\n"
                        "  RET\n"
                        "CMD_SET:\n"
                        "  MOV DX, OFFSET CRLF\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "CMD_ECHO:\n"
                        "  MOV SI, OFFSET CMD_TAIL\n"
                        "  CMP BYTE PTR [SI], 0\n"
                        "  JZ  ECHO_STATE\n"
                        "  MOV DX, SI\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  MOV DX, OFFSET CRLF\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "ECHO_STATE:\n"
                        "  MOV DX, OFFSET ECHO_ON\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        ";\n"
                        "CMD_EXIT:\n"
                        "  MOV AH, 4Ch\n"
                        "  INT 21h\n"
                        "CMD_BREAK: RET\n"
                        "CMD_CALL:  RET\n"
                        "CMD_CHCP:  RET\n"
                        "CMD_CTTY:  RET\n"
                        "CMD_FOR:   RET\n"
                        "CMD_GOTO:  RET\n"
                        "CMD_IF:    RET\n"
                        "CMD_PAUSE:\n"
                        "  MOV DX, OFFSET PAUSE_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  MOV AH, 01h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "CMD_REM:\n"
                        "  RET                     ; 无操作\n"
                        "CMD_SHIFT: RET\n"
                        "CMD_VERIFY:\n"
                        "  MOV DX, OFFSET VERIFY_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "CMD_VOL:\n"
                        "  MOV DX, OFFSET VOL_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        ";\n"
                        "; ---- 辅助子程序 ----\n"
                        "PROMPT_PRINT:\n"
                        "  MOV DX, OFFSET PMT\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "CMP_CMD:\n"
                        "  PUSH SI\n"
                        "  PUSH DI\n"
                        "  MOV DI, OFFSET CMD_BUF\n"
                        "CMP_LP:\n"
                        "  LODSB\n"
                        "  CMP AL, 0\n"
                        "  JZ  CMP_DONE\n"
                        "  SCASB\n"
                        "  JNZ CMP_FAIL\n"
                        "  JMP CMP_LP\n"
                        "CMP_DONE:\n"
                        "  CMP BYTE PTR ES:[DI], 0\n"
                        "  JNZ CMP_FAIL\n"
                        "  POP DI\n"
                        "  POP SI\n"
                        "  RET\n"
                        "CMP_FAIL:\n"
                        "  POP DI\n"
                        "  POP SI\n"
                        "  RET\n"
                        ";\n"
                        "STRIP_CRLF: RET\n"
                        "TOUPPER:    RET\n"
                        "PARSE_LINE:\n"
                        "  MOV SI, OFFSET INBUF+2\n"
                        "  MOV DI, OFFSET CMD_BUF\n"
                        "PL_SKIP:\n"
                        "  LODSB\n"
                        "  CMP AL, ' '\n"
                        "  JZ  PL_SKIP\n"
                        "  CMP AL, 0Dh\n"
                        "  JZ  PL_EMPTY\n"
                        "  DEC SI\n"
                        "PL_CMD:\n"
                        "  LODSB\n"
                        "  CMP AL, ' '\n"
                        "  JZ  PL_TAIL\n"
                        "  CMP AL, 0Dh\n"
                        "  JZ  PL_TAIL\n"
                        "  STOSB\n"
                        "  JMP PL_CMD\n"
                        "PL_TAIL:\n"
                        "  MOV BYTE PTR [DI], 0\n"
                        "  MOV DI, OFFSET CMD_TAIL\n"
                        "  CMP AL, 0Dh\n"
                        "  JZ  PL_END\n"
                        "PT_LOOP:\n"
                        "  LODSB\n"
                        "  CMP AL, 0Dh\n"
                        "  JZ  PL_END\n"
                        "  STOSB\n"
                        "  JMP PT_LOOP\n"
                        "PL_END:\n"
                        "  MOV BYTE PTR [DI], 0\n"
                        "  CLC\n"
                        "  RET\n"
                        "PL_EMPTY:\n"
                        "  STC\n"
                        "  RET\n"
                        ";\n"
                        "CHECK_RESIDENT: RET\n"
                        "SEARCH_PATH:\n"
                        "  STC\n"
                        "  RET\n"
                        "SEARCH_CURDIR:\n"
                        "  STC\n"
                        "  RET\n"
                        "LOAD_AND_EXEC:\n"
                        "  RET\n"
                        "PSP_INIT:\n"
                        "  RET\n"
                        "ENV_INIT:\n"
                        "  RET\n"
                        "SETUP_INT_HANDLERS:\n"
                        "  RET\n"
                        "LOAD_RESIDENT:\n"
                        "  RET\n"
                        "PRINT_AX:\n"
                        "  RET\n"
                        ";\n"
                        "; ---- 消息区 ----\n"
                        "COPY_MSG   DB 'katoDoS Command Interpreter v1.0', 0Dh, 0Ah, '$'\n"
                        "DIR_MSG    DB ' Volume in drive C is KATODOS', 0Dh, 0Ah\n"
                        "           DB ' Directory of C:\\', 0Dh, 0Ah, 0Dh, 0Ah\n"
                        "           DB 'IO.SYS      2,073  SYSTEM', 0Dh, 0Ah\n"
                        "           DB 'MSDOS.SYS   3,841  SYSTEM', 0Dh, 0Ah\n"
                        "           DB 'COMMAND.COM 3,275  SYSTEM', 0Dh, 0Ah\n"
                        "           DB 'CONFIG.SYS    344  SYSTEM', 0Dh, 0Ah\n"
                        "           DB 'AUTOEXEC.BAT  104  SYSTEM', 0Dh, 0Ah\n"
                        "           DB 'DOS/       <DIR>', 0Dh, 0Ah\n"
                        "           DB 'DRIVERS/   <DIR>', 0Dh, 0Ah\n"
                        "           DB 'WINDOWS/   <DIR>', 0Dh, 0Ah\n"
                        "           DB 'GAMES/     <DIR>', 0Dh, 0Ah\n"
                        "           DB 'UTIL/      <DIR>', 0Dh, 0Ah\n"
                        "           DB 'SRC/       <DIR>', 0Dh, 0Ah\n"
                        "           DB '        13 File(s)', 0Dh, 0Ah, '$'\n"
                        "BAD_CMD    DB 'Bad command or file name', 0Dh, 0Ah, '$'\n"
                        "BAD_FILE   DB 'File not found', 0Dh, 0Ah, '$'\n"
                        "ERR_MSG    DB 'ERROR', 0Dh, 0Ah, '$'\n"
                        "CRLF       DB 0Dh, 0Ah, '$'\n"
                        "CPY_OK     DB '1 file(s) copied.', 0Dh, 0Ah, '$'\n"
                        "CPY_ERR    DB 'Copy failed.', 0Dh, 0Ah, '$'\n"
                        "MEM_MSG    DB 'Total conventional memory: $'\n"
                        "KB_MSG     DB ' KB', 0Dh, 0Ah, '$'\n"
                        "PAUSE_MSG  DB 'Press any key to continue...$'\n"
                        "PATH_MSG   DB 'PATH=C:\\DOS;C:\\UTIL;C:\\GAMES;C:\\IMPORT', 0Dh, 0Ah, '$'\n"
                        "ECHO_ON    DB 'ECHO is ON', 0Dh, 0Ah, '$'\n"
                        "VERIFY_MSG DB 'VERIFY is OFF', 0Dh, 0Ah, '$'\n"
                        "VOL_MSG    DB 'Volume in drive C is KATODOS', 0Dh, 0Ah, '$'\n"
                        "PMT        DB 'C:\\>$'\n"
                        ";\n"
                        "; ---- 缓冲区 ----\n"
                        "CMD_BUF    DB 40h DUP (?)\n"
                        "CMD_TAIL   DB 80h DUP (?)\n"
                        "CUR_DIR    DB 40h DUP (?)\n"
                        "COPY_SRC   DB 40h DUP (?)\n"
                        "COPY_DST   DB 40h DUP (?)\n"
                        "COPY_BUF   DB 200h DUP (?)\n"
                        "TYPE_BUF   DB 01h DUP (?)\n"
                        "INBUF      DB 82h, 0, 82h DUP (?)\n"
                        "RES_ENTRY  DW 0\n"
                        ";\n"
                        "SEGMENT _STACK PARA STACK 'STACK'\n"
                        "  DW 80h DUP (?)\n"
                        "SEGMENT ENDS\n"
                        "END COM_ENTRY\n",
                        system=True, protected=True)
        self.write_file(("C", ["AUTOEXEC.BAT"]),
                        "@ECHO OFF\n"
                        "PROMPT $P$G\n"
                        "PATH C:\\DOS;C:\\UTIL;C:\\GAMES;C:\\IMPORT\n"
                        "CALL C:\\CONFIG.SYS\n"
                        "ECHO.\n"
                        "ECHO katoDoS 1.0 已就绪。\n"
                        "ECHO 输入 HELP 获取命令帮助。\n"
                        "ECHO.\n",
                        system=True, protected=True)
        self.write_file(("C", ["CONFIG.SYS"]),
                        "; katoDoS CONFIG.SYS — 系统配置文件\n"
                        "; 加载设备驱动与设置 DOS 内核参数\n"
                        ";\n"
                        "DEVICE=C:\\DRIVERS\\HIMEM.SYS\n"
                        "DEVICE=C:\\DRIVERS\\EMM386.EXE RAM\n"
                        "DEVICEHIGH=C:\\DRIVERS\\MOUSE.SYS\n"
                        "DEVICEHIGH=C:\\DRIVERS\\KEYBOARD.DRV\n"
                        "DEVICEHIGH=C:\\DRIVERS\\SB16.DRV /IRQ=5 /DMA=1 /PORT=220\n"
                        "DEVICE=C:\\DRIVERS\\VGA.DRV /MODE=VESA\n"
                        ";\n"
                        "DOS=HIGH,UMB\n"
                        "FILES=40\n"
                        "BUFFERS=20\n"
                        "LASTDRIVE=Z\n"
                        "FCBS=4,0\n"
                        "STACKS=9,256\n"
                        "SHELL=C:\\COMMAND.COM /P /E:512\n"
                        "COUNTRY=001,936,C:\\DOS\\COUNTRY.SYS\n",
                        system=True, protected=True)

        # 驱动文件（删除会导致对应功能不可用）— 伪源码
        self.write_file(("C", ["DRIVERS", "HIMEM.SYS"]),
                        "; katoDoS HIMEM.SYS — XMS 扩展内存管理驱动 (v1.0)\n"
                        "; 伪源码：A20 门控 / XMS 分配与释放 / 高端内存区管理\n"
                        ";\n"
                        "SEGMENT _TEXT PARA PUBLIC 'CODE'\n"
                        "  ASSUME CS:_TEXT, DS:_TEXT\n"
                        ";\n"
                        "  ORG 0000h\n"
                        "  DB 'HIMEM.SYS v1.0 - Extended Memory Manager'\n"
                        "  DB 0Dh, 0Ah\n"
                        ";\n"
                        "DRV_ENTRY:\n"
                        "  CALL A20_ENABLE         ; 打开 A20 地址线\n"
                        "  CALL DETECT_XMS_SIZE    ; 检测扩展内存大小\n"
                        "  CALL INSTALL_XMS_HANDLER ; 安装 INT 2Fh/4300h XMS API\n"
                        "  MOV DX, OFFSET OK_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RETF\n"
                        ";\n"
                        "A20_ENABLE:\n"
                        "  MOV AX, 2401h          ; 打开 A20\n"
                        "  INT 15h\n"
                        "  RET\n"
                        "A20_DISABLE:\n"
                        "  MOV AX, 2400h          ; 关闭 A20\n"
                        "  INT 15h\n"
                        "  RET\n"
                        ";\n"
                        "; ---- XMS 功能 (INT 2Fh AX=4300h) ----\n"
                        "XMS_HANDLER:\n"
                        "  CMP AH, 43h            ; XMS 检测\n"
                        "  JNZ XMS_EXIT\n"
                        "  CMP AL, 00h\n"
                        "  JZ  XMS_CHECK\n"
                        "  CMP AL, 08h            ; 查询空闲扩展内存\n"
                        "  JZ  XMS_QUERY\n"
                        "  CMP AL, 09h            ; 分配扩展内存块\n"
                        "  JZ  XMS_ALLOC\n"
                        "  CMP AL, 0Ah            ; 释放扩展内存块\n"
                        "  JZ  XMS_FREE\n"
                        "XMS_EXIT:\n"
                        "  XOR AX, AX\n"
                        "  RETF 2\n"
                        ";\n"
                        "XMS_CHECK:\n"
                        "  MOV AX, 0001h          ; XMS 存在\n"
                        "  RETF 2\n"
                        "XMS_QUERY:\n"
                        "  MOV AX, [XMS_TOTAL]    ; 总 KB\n"
                        "  MOV DX, [XMS_FREE]     ; 空闲 KB\n"
                        "  RETF 2\n"
                        "XMS_ALLOC:\n"
                        "  CMP BX, [XMS_FREE]\n"
                        "  JA  XMS_NOMEM\n"
                        "  SUB [XMS_FREE], BX\n"
                        "  MOV AX, 0001h\n"
                        "  MOV DX, [XMS_NEXT_HANDLE]\n"
                        "  INC [XMS_NEXT_HANDLE]\n"
                        "  RETF 2\n"
                        "XMS_NOMEM:\n"
                        "  XOR AX, AX\n"
                        "  MOV BL, 0A0h          ; 错误码: 内存不足\n"
                        "  RETF 2\n"
                        "XMS_FREE:\n"
                        "  MOV AX, 0001h\n"
                        "  RETF 2\n"
                        ";\n"
                        "DETECT_XMS_SIZE:\n"
                        "  MOV AX, 08800h         ; INT 15h 检测\n"
                        "  INT 15h\n"
                        "  MOV [XMS_TOTAL], AX\n"
                        "  MOV [XMS_FREE], AX\n"
                        "  RET\n"
                        "INSTALL_XMS_HANDLER:\n"
                        "  RET\n"
                        ";\n"
                        "OK_MSG    DB 'HIMEM.SYS loaded: XMS Manager active', 0Dh, 0Ah, '$'\n"
                        "XMS_TOTAL DW 07E00h       ; ~32MB\n"
                        "XMS_FREE  DW 07E00h\n"
                        "XMS_NEXT_HANDLE DW 0001h\n"
                        ";\n"
                        "SEGMENT ENDS\n"
                        "END DRV_ENTRY\n",
                        driver=True, drv_type="memory")
        self.write_file(("C", ["DRIVERS", "EMM386.EXE"]),
                        "; katoDoS EMM386.EXE — EMS/UMB 扩充内存管理驱动 (v1.0)\n"
                        "; 伪源码：EMS 页框 / LIM 4.0 规范 / UMB 映射\n"
                        ";\n"
                        "SEGMENT _TEXT PARA PUBLIC 'CODE'\n"
                        "  ASSUME CS:_TEXT, DS:_TEXT\n"
                        ";\n"
                        "  ORG 0000h\n"
                        "  DB 'EMM386.EXE v1.0 - Expanded Memory Manager'\n"
                        "  DB 0Dh, 0Ah\n"
                        ";\n"
                        "DRV_ENTRY:\n"
                        "  CALL CHECK_CPU          ; 检查 80386+\n"
                        "  CALL INIT_VCPI          ; 初始化 VCPI 接口\n"
                        "  CALL MAP_PAGE_FRAME     ; 建立 EMS 页框 (E000h段)\n"
                        "  CALL INSTALL_EMM_HANDLER; 安装 INT 67h EMS API\n"
                        "  MOV DX, OFFSET OK_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RETF\n"
                        ";\n"
                        "CHECK_CPU:\n"
                        "  PUSHF\n"
                        "  POP AX\n"
                        "  MOV CX, AX\n"
                        "  XOR AX, 4000h          ; 测试 ID 位\n"
                        "  PUSH AX\n"
                        "  POPF\n"
                        "  PUSHF\n"
                        "  POP AX\n"
                        "  AND AX, 4000h\n"
                        "  JZ  NO_386             ; 无 ID 位 = 286-\n"
                        "  MOV AX, 80000001h      ; CPUID 检测\n"
                        "  RET\n"
                        "NO_386:\n"
                        "  MOV DX, OFFSET CPU_ERR\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RETF\n"
                        ";\n"
                        "; ---- EMS 页映射 ----\n"
                        "EMM_HANDLER:\n"
                        "  CMP AH, 40h            ; 获取状态\n"
                        "  JZ  EMM_STATUS\n"
                        "  CMP AH, 41h            ; 获取页框段\n"
                        "  JZ  EMM_PAGEFRAME\n"
                        "  CMP AH, 42h            ; 获取未分配页数\n"
                        "  JZ  EMM_PAGE_COUNT\n"
                        "  CMP AH, 43h            ; 分配页\n"
                        "  JZ  EMM_ALLOCATE\n"
                        "  CMP AH, 44h            ; 映射页\n"
                        "  JZ  EMM_MAP\n"
                        "  CMP AH, 45h            ; 释放页\n"
                        "  JZ  EMM_DEALLOC\n"
                        "  MOV AH, 84h\n"
                        "  RETF 2\n"
                        ";\n"
                        "EMM_STATUS:\n"
                        "  MOV AH, 00h\n"
                        "  RETF 2\n"
                        "EMM_PAGEFRAME:\n"
                        "  MOV BX, 0E000h         ; 页框段 E000h\n"
                        "  RETF 2\n"
                        "EMM_PAGE_COUNT:\n"
                        "  MOV BX, [TOTAL_PAGES]\n"
                        "  MOV DX, [FREE_PAGES]\n"
                        "  RETF 2\n"
                        "EMM_ALLOCATE:\n"
                        "  CMP BX, [FREE_PAGES]\n"
                        "  JA  EMM_NO_MEM\n"
                        "  SUB [FREE_PAGES], BX\n"
                        "  MOV DX, [NEXT_HANDLE]\n"
                        "  INC [NEXT_HANDLE]\n"
                        "  RETF 2\n"
                        "EMM_NO_MEM:\n"
                        "  MOV AH, 88h\n"
                        "  RETF 2\n"
                        "EMM_MAP:\n"
                        "  XOR AH, AH\n"
                        "  RETF 2\n"
                        "EMM_DEALLOC:\n"
                        "  XOR AH, AH\n"
                        "  RETF 2\n"
                        ";\n"
                        "INIT_VCPI:       RET\n"
                        "MAP_PAGE_FRAME:  RET\n"
                        "INSTALL_EMM_HANDLER: RET\n"
                        ";\n"
                        "OK_MSG      DB 'EMM386.EXE loaded: EMS/UMB active', 0Dh, 0Ah, '$'\n"
                        "CPU_ERR     DB 'EMM386: 80386 processor required', 0Dh, 0Ah, '$'\n"
                        "TOTAL_PAGES DW 0100h    ; 256 页 (16MB EMS)\n"
                        "FREE_PAGES  DW 0100h\n"
                        "NEXT_HANDLE DW 0001h\n"
                        ";\n"
                        "SEGMENT ENDS\n"
                        "END DRV_ENTRY\n",
                        driver=True, drv_type="memory")
        self.write_file(("C", ["DRIVERS", "NE2000.DRV"]),
                        "; katoDoS NE2000.DRV — NE2000 兼容网卡驱动 (v1.0)\n"
                        "; 伪源码：DP8390 NIC / 包接收与发送 / 协议栈桥接\n"
                        ";\n"
                        "SEGMENT _TEXT PARA PUBLIC 'CODE'\n"
                        "  ASSUME CS:_TEXT, DS:_TEXT\n"
                        ";\n"
                        "  ORG 0000h\n"
                        "  DB 'NE2000.DRV v1.0 - Network Driver'\n"
                        "  DB 0Dh, 0Ah\n"
                        ";\n"
                        "IO_BASE   EQU 0300h       ; NE2000 I/O 基址\n"
                        "INT_VEC   EQU 03h         ; IRQ 3\n"
                        "MEM_BASE  EQU 0D000h      ; 共享内存基址\n"
                        ";\n"
                        "DRV_ENTRY:\n"
                        "  CALL RESET_NIC          ; 复位网卡\n"
                        "  CALL READ_MAC           ; 读取 MAC 地址\n"
                        "  CALL INSTALL_INT        ; 安装中断处理\n"
                        "  CALL SETUP_PROMISC      ; 设置混杂模式\n"
                        "  MOV DX, OFFSET OK_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RETF\n"
                        ";\n"
                        "RESET_NIC:\n"
                        "  MOV DX, IO_BASE + 1Fh   ; RESET 寄存器\n"
                        "  MOV AL, 1Fh\n"
                        "  OUT DX, AL\n"
                        "  CALL DELAY\n"
                        "  MOV DX, IO_BASE + 00h\n"
                        "  IN  AL, DX             ; 读取状态\n"
                        "  AND AL, 20h\n"
                        "  JZ  RESET_NIC          ; 等待就绪\n"
                        "  RET\n"
                        ";\n"
                        "READ_MAC:\n"
                        "  MOV SI, OFFSET MAC_BUF\n"
                        "  MOV DX, IO_BASE + 00h   ; PROM 地址端口\n"
                        "  MOV CX, 6\n"
                        "RM_LOOP:\n"
                        "  MOV AL, 00h\n"
                        "  OUT DX, AL\n"
                        "  INC DX\n"
                        "  IN  AL, DX             ; 读 PROM 数据\n"
                        "  MOV [SI], AL\n"
                        "  INC SI\n"
                        "  DEC DX\n"
                        "  LOOP RM_LOOP\n"
                        "  RET\n"
                        ";\n"
                        "INSTALL_INT:\n"
                        "  MOV AX, 250Bh          ; INT 0Bh (IRQ3)\n"
                        "  MOV DX, OFFSET NIC_INT\n"
                        "  INT 21h\n"
                        "  RET\n"
                        ";\n"
                        "; ---- 中断处理 ----\n"
                        "NIC_INT:\n"
                        "  PUSH AX\n"
                        "  PUSH DX\n"
                        "  PUSH DS\n"
                        "  MOV DX, IO_BASE + 07h\n"
                        "  IN  AL, DX             ; 读取中断状态\n"
                        "  TEST AL, 01h           ; 收到包\n"
                        "  JZ  NO_PKT\n"
                        "  CALL RECV_PACKET\n"
                        "NO_PKT:\n"
                        "  MOV AL, 20h\n"
                        "  OUT 20h, AL            ; EOI\n"
                        "  POP DS\n"
                        "  POP DX\n"
                        "  POP AX\n"
                        "  IRET\n"
                        ";\n"
                        "RECV_PACKET:\n"
                        "  RET\n"
                        "SEND_PACKET:\n"
                        "  RET\n"
                        "SETUP_PROMISC:\n"
                        "  RET\n"
                        "DELAY:\n"
                        "  PUSH CX\n"
                        "  MOV CX, 00FFh\n"
                        "DL: LOOP DL\n"
                        "  POP CX\n"
                        "  RET\n"
                        ";\n"
                        "OK_MSG    DB 'NE2000.DRV loaded: 00-1A-2B-3C-4D-5E', 0Dh, 0Ah, '$'\n"
                        "MAC_BUF   DB 00h, 1Ah, 2Bh, 3Ch, 4Dh, 5Eh\n"
                        ";\n"
                        "SEGMENT ENDS\n"
                        "END DRV_ENTRY\n",
                        driver=True, drv_type="network")
        self.write_file(("C", ["DRIVERS", "MOUSE.SYS"]),
                        "; katoDoS MOUSE.SYS — PS/2 鼠标驱动 (v1.0)\n"
                        "; 伪源码：INT 33h 鼠标 API / 数据包解析 / 光标管理\n"
                        ";\n"
                        "SEGMENT _TEXT PARA PUBLIC 'CODE'\n"
                        "  ASSUME CS:_TEXT, DS:_TEXT\n"
                        ";\n"
                        "  ORG 0000h\n"
                        "  DB 'MOUSE.SYS v1.0 - Mouse Driver'\n"
                        "  DB 0Dh, 0Ah\n"
                        ";\n"
                        "DRV_ENTRY:\n"
                        "  CALL INIT_MOUSE         ; 初始化 PS/2 鼠标\n"
                        "  CALL INSTALL_IRQ12      ; 安装 INT 74h\n"
                        "  CALL INSTALL_INT33      ; 安装 INT 33h API\n"
                        "  MOV DX, OFFSET OK_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RETF\n"
                        ";\n"
                        "INIT_MOUSE:\n"
                        "  MOV AL, 0D4h           ; 写鼠标命令\n"
                        "  OUT 64h, AL\n"
                        "  CALL MS_DELAY\n"
                        "  MOV AL, 0F4h           ; 启用鼠标\n"
                        "  OUT 60h, AL\n"
                        "  CALL MS_DELAY\n"
                        "  IN  AL, 60h            ; 读 ACK\n"
                        "  CMP AL, 0FAh           ; 确认?\n"
                        "  JNZ INIT_FAIL\n"
                        "  RET\n"
                        "INIT_FAIL:\n"
                        "  RET\n"
                        ";\n"
                        "MS_DELAY:\n"
                        "  PUSH CX\n"
                        "  MOV CX, 0100h\n"
                        "MSL: LOOP MSL\n"
                        "  POP CX\n"
                        "  RET\n"
                        ";\n"
                        "; ---- 鼠标数据包中断 ----\n"
                        "MOUSE_INT:              ; IRQ12 / INT 74h\n"
                        "  PUSH AX\n"
                        "  PUSH DX\n"
                        "  IN  AL, 60h            ; 读取数据\n"
                        "  MOV [MSE_BYTE], AL\n"
                        "  INC [MSE_INDEX]\n"
                        "  MOV AL, 20h\n"
                        "  OUT 0A0h, AL           ; 从片 EOI\n"
                        "  OUT 20h, AL            ; 主片 EOI\n"
                        "  POP DX\n"
                        "  POP AX\n"
                        "  IRET\n"
                        ";\n"
                        "; ---- INT 33h 鼠标 API ----\n"
                        "INT_33:\n"
                        "  CMP AX, 0000h          ; 复位与状态\n"
                        "  JZ  MS_RESET\n"
                        "  CMP AX, 0001h          ; 显示光标\n"
                        "  JZ  MS_SHOW\n"
                        "  CMP AX, 0002h          ; 隐藏光标\n"
                        "  JZ  MS_HIDE\n"
                        "  CMP AX, 0003h          ; 获取位置与按钮\n"
                        "  JZ  MS_GETPOS\n"
                        "  CMP AX, 0004h          ; 设置位置\n"
                        "  JZ  MS_SETPOS\n"
                        "  RETF 2\n"
                        ";\n"
                        "MS_RESET:\n"
                        "  XOR CX, CX\n"
                        "  XOR DX, DX\n"
                        "  MOV AX, 0FFFFh         ; 鼠标存在\n"
                        "  RETF 2\n"
                        "MS_SHOW:\n"
                        "  INC [VISIBLE]\n"
                        "  RETF 2\n"
                        "MS_HIDE:\n"
                        "  DEC [VISIBLE]\n"
                        "  RETF 2\n"
                        "MS_GETPOS:\n"
                        "  MOV CX, [MSE_X]\n"
                        "  MOV DX, [MSE_Y]\n"
                        "  MOV BX, [MSE_BTN]\n"
                        "  RETF 2\n"
                        "MS_SETPOS:\n"
                        "  MOV [MSE_X], CX\n"
                        "  MOV [MSE_Y], DX\n"
                        "  RETF 2\n"
                        ";\n"
                        "INSTALL_IRQ12:\n"
                        "  XOR AX, AX\n"
                        "  MOV ES, AX\n"
                        "  MOV WORD PTR ES:[01D0h], MOUSE_INT ; INT 74h\n"
                        "  MOV AX, CS\n"
                        "  MOV WORD PTR ES:[01D2h], AX\n"
                        "  RET\n"
                        "INSTALL_INT33:\n"
                        "  XOR AX, AX\n"
                        "  MOV ES, AX\n"
                        "  MOV WORD PTR ES:[00CCh], INT_33   ; INT 33h\n"
                        "  MOV AX, CS\n"
                        "  MOV WORD PTR ES:[00CEh], AX\n"
                        "  RET\n"
                        ";\n"
                        "OK_MSG   DB 'MOUSE.SYS loaded: PS/2 mouse driver active', 0Dh, 0Ah, '$'\n"
                        "MSE_BYTE DB 0\n"
                        "MSE_INDEX DB 0\n"
                        "MSE_X    DW 0320h\n"
                        "MSE_Y    DW 01E0h\n"
                        "MSE_BTN  DW 0000h\n"
                        "VISIBLE  DW 0000h\n"
                        ";\n"
                        "SEGMENT ENDS\n"
                        "END DRV_ENTRY\n",
                        driver=True, drv_type="mouse")
        self.write_file(("C", ["DRIVERS", "KEYBOARD.DRV"]),
                        "; katoDoS KEYBOARD.DRV — PS/2 键盘驱动 (v1.0)\n"
                        "; 伪源码：INT 09h 键盘中断 / INT 16h BIOS API / 扫描码映射\n"
                        ";\n"
                        "SEGMENT _TEXT PARA PUBLIC 'CODE'\n"
                        "  ASSUME CS:_TEXT, DS:_TEXT\n"
                        ";\n"
                        "  ORG 0000h\n"
                        "  DB 'KEYBOARD.DRV v1.0 - PS/2 Keyboard Driver'\n"
                        "  DB 0Dh, 0Ah\n"
                        ";\n"
                        "; ---- I/O 端口 ----\n"
                        "KBD_DATA EQU 0060h       ; 键盘数据端口\n"
                        "KBD_STAT EQU 0064h       ; 键盘状态端口\n"
                        "KBD_CMD  EQU 0064h       ; 键盘命令端口\n"
                        ";\n"
                        "DRV_ENTRY:\n"
                        "  CALL KBD_RESET          ; 复位键盘控制器\n"
                        "  CALL SET_TYPEMATIC      ; 设置按键重复率\n"
                        "  CALL INSTALL_INT09      ; 挂载 INT 09h\n"
                        "  CALL INSTALL_INT16      ; 挂载 INT 16h BIOS API\n"
                        "  MOV DX, OFFSET OK_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RETF\n"
                        ";\n"
                        "KBD_RESET:\n"
                        "  MOV AL, 0AAh           ; 键盘控制器自检\n"
                        "  OUT KBD_CMD, AL\n"
                        "  CALL KBD_DELAY\n"
                        "  IN  AL, KBD_DATA\n"
                        "  CMP AL, 55h            ; 自检成功返回 55h\n"
                        "  JNZ KBD_RESET_FAIL\n"
                        "  MOV AL, 0AEh           ; 启用键盘\n"
                        "  OUT KBD_CMD, AL\n"
                        "  RET\n"
                        "KBD_RESET_FAIL:\n"
                        "  STC\n"
                        "  RET\n"
                        ";\n"
                        "SET_TYPEMATIC:\n"
                        "  MOV AL, 0F3h           ; 设置重复率命令\n"
                        "  OUT KBD_DATA, AL\n"
                        "  CALL KBD_DELAY\n"
                        "  IN  AL, KBD_DATA       ; 读 ACK\n"
                        "  MOV AL, 00100000b      ; 速率 10.9cps, 延迟 500ms\n"
                        "  OUT KBD_DATA, AL\n"
                        "  CALL KBD_DELAY\n"
                        "  IN  AL, KBD_DATA       ; 读 ACK\n"
                        "  RET\n"
                        ";\n"
                        "; ---- 键盘中断处理 INT 09h ----\n"
                        "INT_09:\n"
                        "  PUSH AX\n"
                        "  PUSH BX\n"
                        "  PUSH DS\n"
                        "  XOR AX, AX\n"
                        "  MOV DS, AX\n"
                        "  CLI\n"
                        "  IN  AL, KBD_DATA       ; 读扫描码\n"
                        "  MOV [LAST_SCAN], AL\n"
                        "  TEST AL, 80h           ; 松键?\n"
                        "  JNZ KEY_RELEASE\n"
                        "  MOV BL, AL             ; 按下键\n"
                        "  CALL TRANSLATE_SCAN    ; 将扫描码转为 ASCII\n"
                        "  MOV [LAST_ASCII], AL\n"
                        "  MOV [KBD_FLAGS], 1     ; 标记有键可用\n"
                        ";\n"
                        "; ---- 更新键盘状态灯 ----\n"
                        "  CMP AL, 00h\n"
                        "  JZ  NO_UPD\n"
                        "  CMP [KBD_ECHO], 0\n"
                        "  JZ  NO_ECHO\n"
                        "  MOV AH, 0Eh           ; 回显\n"
                        "  INT 10h\n"
                        "NO_ECHO:\n"
                        "NO_UPD:\n"
                        "KEY_RELEASE:\n"
                        "  MOV AL, 20h            ; EOI\n"
                        "  OUT 20h, AL\n"
                        "  STI\n"
                        "  POP DS\n"
                        "  POP BX\n"
                        "  POP AX\n"
                        "  IRET\n"
                        ";\n"
                        "; ---- 扫描码翻译表 (US 布局，部分映射) ----\n"
                        "TRANSLATE_SCAN:\n"
                        "  MOV SI, OFFSET SCAN_TABLE\n"
                        "  XOR BH, BH\n"
                        "  DEC BL\n"
                        "  ADD SI, BX\n"
                        "  LODSB\n"
                        "  RET\n"
                        ";\n"
                        "SCAN_TABLE:\n"
                        "  DB ' ', 0, 0, 0, 0, 0, 0, 0   ; 00-07 (Esc)\n"
                        "  DB '1','2','3','4','5','6','7','8'  ; 08-0F\n"
                        "  DB '9','0','-','=',0,0,0,0       ; 10-17 (Backspace/Tab)\n"
                        "  DB 'q','w','e','r','t','y','u','i'  ; 18-1F\n"
                        "  DB 'o','p','[',']',0,0,0,0       ; 20-27 (Enter/Caps)\n"
                        "  DB 'a','s','d','f','g','h','j','k'  ; 28-2F\n"
                        "  DB 'l',';','\"','`',0,'\\','z','x'  ; 30-37\n"
                        "  DB 'c','v','b','n','m',',','.','/'  ; 38-3F\n"
                        "  DB 0,0,0,0,0,0,0,0               ; 40-47\n"
                        "  DB 0,0,0,0,0,0,0,0               ; 48-4F\n"
                        "  DB 0,0,0,0,0,0,0,0               ; 50-57\n"
                        "  DB ' ',0,0,0,0,0,0,0             ; 58-5F (Space)\n"
                        ";\n"
                        "; ---- INT 16h BIOS 键盘 API ----\n"
                        "INT_16:\n"
                        "  CMP AH, 00h            ; 读键\n"
                        "  JZ  KBD_READ\n"
                        "  CMP AH, 01h            ; 查询状态\n"
                        "  JZ  KBD_STATUS\n"
                        "  CMP AH, 02h            ; 获取 Shift 标志\n"
                        "  JZ  KBD_SHIFT\n"
                        "  CMP AH, 05h            ; 键回写\n"
                        "  JZ  KBD_WRITE\n"
                        "  CMP AH, 10h            ; 增强读键\n"
                        "  JZ  KBD_READ\n"
                        "  CMP AH, 12h            ; 增强获取 Shift 标志\n"
                        "  JZ  KBD_SHIFT\n"
                        "  IRET\n"
                        ";\n"
                        "KBD_READ:\n"
                        "  CLI\n"
                        "  CMP [KBD_FLAGS], 0\n"
                        "  JZ  KBD_READ            ; 等待有键\n"
                        "  MOV AL, [LAST_ASCII]\n"
                        "  MOV AH, [LAST_SCAN]\n"
                        "  MOV [KBD_FLAGS], 0\n"
                        "  STI\n"
                        "  IRET\n"
                        ";\n"
                        "KBD_STATUS:\n"
                        "  MOV AL, [KBD_FLAGS]\n"
                        "  CMP AL, 0\n"
                        "  JZ  KBD_NONE\n"
                        "  MOV AL, [LAST_ASCII]\n"
                        "  MOV AH, [LAST_SCAN]\n"
                        "  XOR FLAGS, FLAGS\n"
                        "  IRET\n"
                        "KBD_NONE:\n"
                        "  XOR AX, AX\n"
                        "  IRET\n"
                        ";\n"
                        "KBD_SHIFT:\n"
                        "  MOV AL, [SHIFT_FLAGS]\n"
                        "  IRET\n"
                        "KBD_WRITE:\n"
                        "  MOV [LAST_ASCII], AL\n"
                        "  MOV [LAST_SCAN], AH\n"
                        "  MOV [KBD_FLAGS], 1\n"
                        "  IRET\n"
                        ";\n"
                        "INSTALL_INT09:\n"
                        "  XOR AX, AX\n"
                        "  MOV ES, AX\n"
                        "  MOV WORD PTR ES:[0024h], INT_09  ; INT 09h\n"
                        "  MOV AX, CS\n"
                        "  MOV WORD PTR ES:[0026h], AX\n"
                        "  RET\n"
                        "INSTALL_INT16:\n"
                        "  XOR AX, AX\n"
                        "  MOV ES, AX\n"
                        "  MOV WORD PTR ES:[0058h], INT_16  ; INT 16h\n"
                        "  MOV AX, CS\n"
                        "  MOV WORD PTR ES:[005Ah], AX\n"
                        "  RET\n"
                        ";\n"
                        "KBD_DELAY:\n"
                        "  PUSH CX\n"
                        "  MOV CX, 0040h\n"
                        "KDL: LOOP KDL\n"
                        "  POP CX\n"
                        "  RET\n"
                        ";\n"
                        "OK_MSG    DB 'KEYBOARD.DRV loaded: PS/2 keyboard controller active', 0Dh, 0Ah, '$'\n"
                        "LAST_SCAN DB 0\n"
                        "LAST_ASCII DB 0\n"
                        "KBD_FLAGS DB 0\n"
                        "KBD_ECHO  DB 1\n"
                        "SHIFT_FLAGS DB 0\n"
                        ";\n"
                        "SEGMENT ENDS\n"
                        "END DRV_ENTRY\n",
                        driver=True, drv_type="keyboard")
        self.write_file(("C", ["DRIVERS", "SB16.DRV"]),
                        "; katoDoS SB16.DRV — Sound Blaster 16 声卡驱动 (v1.0)\n"
                        "; 伪源码：DSP 编程 / DMA 传输 / MIDI / 混音器\n"
                        ";\n"
                        "SEGMENT _TEXT PARA PUBLIC 'CODE'\n"
                        "  ASSUME CS:_TEXT, DS:_TEXT\n"
                        ";\n"
                        "  ORG 0000h\n"
                        "  DB 'SB16.DRV v1.0 - Sound Blaster 16 Driver'\n"
                        "  DB 0Dh, 0Ah\n"
                        ";\n"
                        "DSP_PORT EQU 0220h        ; 默认基址 220h\n"
                        "DMA_CH   EQU 01h          ; DMA 通道 1\n"
                        ";\n"
                        "DRV_ENTRY:\n"
                        "  CALL RESET_DSP          ; 复位 DSP\n"
                        "  CALL READ_VERSION       ; 读取 DSP 版本\n"
                        "  CALL INIT_MIXER         ; 初始化混音器\n"
                        "  CALL INSTALL_IRQ        ; 安装中断\n"
                        "  MOV DX, OFFSET OK_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RETF\n"
                        ";\n"
                        "RESET_DSP:\n"
                        "  MOV DX, DSP_PORT + 06h  ; 复位口\n"
                        "  MOV AL, 01h\n"
                        "  OUT DX, AL\n"
                        "  CALL SB_DELAY\n"
                        "  MOV AL, 00h\n"
                        "  OUT DX, AL\n"
                        "  MOV DX, DSP_PORT + 0Eh  ; 数据可用口\n"
                        "  IN  AL, DX             ; 读数据\n"
                        "  CMP AL, 0AAh           ; 确认字节\n"
                        "  JNZ RESET_FAIL\n"
                        "  RET\n"
                        "RESET_FAIL:\n"
                        "  RET\n"
                        ";\n"
                        "READ_VERSION:\n"
                        "  MOV DX, DSP_PORT + 0Ch  ; 命令口\n"
                        "  MOV AL, 0E1h           ; 版本查询\n"
                        "  OUT DX, AL\n"
                        "  MOV DX, DSP_PORT + 0Eh\n"
                        "  IN  AL, DX\n"
                        "  MOV [SB_MAJOR], AL\n"
                        "  IN  AL, DX\n"
                        "  MOV [SB_MINOR], AL\n"
                        "  RET\n"
                        ";\n"
                        "INIT_MIXER:\n"
                        "  MOV DX, DSP_PORT + 04h  ; 混音器地址口\n"
                        "  MOV AL, 00h             ; 主音量左\n"
                        "  OUT DX, AL\n"
                        "  MOV DX, DSP_PORT + 05h\n"
                        "  MOV AL, 0F0h            ; 最大音量\n"
                        "  OUT DX, AL\n"
                        "  RET\n"
                        ";\n"
                        "; ---- DSP 命令 ----\n"
                        "PLAY_8BIT:\n"
                        "  MOV DX, DSP_PORT + 0Ch\n"
                        "  MOV AL, 10h             ; 8位PCM直接\n"
                        "  OUT DX, AL\n"
                        "  MOV DX, DSP_PORT + 0Ch\n"
                        "  MOV AL, BL              ; 数据长度低\n"
                        "  OUT DX, AL\n"
                        "  MOV AL, BH              ; 数据长度高\n"
                        "  OUT DX, AL\n"
                        "  RET\n"
                        "STOP_PLAY:\n"
                        "  MOV DX, DSP_PORT + 0Ch\n"
                        "  MOV AL, 0D0h            ; 停止8位\n"
                        "  OUT DX, AL\n"
                        "  RET\n"
                        ";\n"
                        "INSTALL_IRQ:\n"
                        "  RET\n"
                        "SB_DELAY:\n"
                        "  PUSH CX\n"
                        "  MOV CX, 0080h\n"
                        "SBDL: LOOP SBDL\n"
                        "  POP CX\n"
                        "  RET\n"
                        ";\n"
                        "OK_MSG   DB 'SB16.DRV loaded: Sound Blaster 16 v4.05', 0Dh, 0Ah, '$'\n"
                        "SB_MAJOR DB 04h\n"
                        "SB_MINOR DB 05h\n"
                        ";\n"
                        "SEGMENT ENDS\n"
                        "END DRV_ENTRY\n",
                        driver=True, drv_type="sound")
        self.write_file(("C", ["DRIVERS", "VGA.DRV"]),
                        "; katoDoS VGA.DRV — VGA/VESA 显示驱动 (v1.0)\n"
                        "; 伪源码：模式设置 / 帧缓冲 / 调色板 / 光标控制\n"
                        ";\n"
                        "SEGMENT _TEXT PARA PUBLIC 'CODE'\n"
                        "  ASSUME CS:_TEXT, DS:_TEXT\n"
                        ";\n"
                        "  ORG 0000h\n"
                        "  DB 'VGA.DRV v1.0 - VGA Display Driver'\n"
                        "  DB 0Dh, 0Ah\n"
                        ";\n"
                        "; ---- VGA I/O 端口 ----\n"
                        "CRTC_PORT EQU 03D4h       ; CRTC 索引\n"
                        "CRTC_DATA EQU 03D5h\n"
                        "SEQ_PORT  EQU 03C4h       ; 时序索引\n"
                        "SEQ_DATA  EQU 03C5h\n"
                        "GC_PORT   EQU 03CEh       ; 图形控制\n"
                        "GC_DATA   EQU 03CFh\n"
                        "ATT_PORT  EQU 03C0h       ; 属性\n"
                        "STAT_PORT EQU 03DAh       ; 输入状态\n"
                        "MISC_PORT EQU 03C2h       ; 杂项输出\n"
                        ";\n"
                        "DRV_ENTRY:\n"
                        "  CALL DETECT_VGA         ; 检测 VGA 硬件\n"
                        "  CALL SET_MODE_3         ; 设置 80x25 文本模式\n"
                        "  CALL INIT_PALETTE       ; 初始化琥珀色调色板\n"
                        "  CALL INSTALL_INT10      ; 挂载 INT 10h 扩展\n"
                        "  MOV DX, OFFSET OK_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RETF\n"
                        ";\n"
                        "DETECT_VGA:\n"
                        "  MOV AX, 1A00h           ; 获取显示组合码\n"
                        "  INT 10h\n"
                        "  CMP AL, 1Ah\n"
                        "  JNZ NO_VGA\n"
                        "  MOV [VGA_FLAG], 1\n"
                        "  RET\n"
                        "NO_VGA:\n"
                        "  MOV [VGA_FLAG], 0\n"
                        "  RET\n"
                        ";\n"
                        "SET_MODE_3:\n"
                        "  MOV AX, 0003h           ; 80x25 文本\n"
                        "  INT 10h\n"
                        "; ---- 自定义 CRTC 时序 ----\n"
                        "  MOV DX, CRTC_PORT\n"
                        "  MOV AL, 00h             ; 水平总数\n"
                        "  MOV AH, 50h\n"
                        "  OUT DX, AX\n"
                        "  MOV AL, 01h             ; 水平显示结束\n"
                        "  MOV AH, 4Fh\n"
                        "  OUT DX, AX\n"
                        "  MOV AL, 02h             ; 水平消隐开始\n"
                        "  MOV AH, 50h\n"
                        "  OUT DX, AX\n"
                        "  MOV AL, 03h             ; 水平消隐结束\n"
                        "  MOV AH, 82h\n"
                        "  OUT DX, AX\n"
                        "  MOV AL, 04h             ; 水平回扫开始\n"
                        "  MOV AH, 55h\n"
                        "  OUT DX, AX\n"
                        "  MOV AL, 05h             ; 水平回扫结束\n"
                        "  MOV AH, 81h\n"
                        "  OUT DX, AX\n"
                        "  MOV AL, 06h             ; 垂直总数\n"
                        "  MOV AH, 0BFh\n"
                        "  OUT DX, AX\n"
                        "  MOV AL, 07h             ; 溢出\n"
                        "  OUT DX, AX\n"
                        "  RET\n"
                        ";\n"
                        "INIT_PALETTE:\n"
                        "  MOV DX, 03C8h           ; 调色板写索引\n"
                        "  MOV AL, 00h\n"
                        "  OUT DX, AL\n"
                        "  MOV DX, 03C9h           ; 调色板数据\n"
                        "  MOV CX, 0010h           ; 前 16 色\n"
                        "  MOV SI, OFFSET PAL_DATA\n"
                        "PLOOP:\n"
                        "  LODSB\n"
                        "  OUT DX, AL\n"
                        "  LOOP PLOOP\n"
                        "  RET\n"
                        ";\n"
                        "INSTALL_INT10:\n"
                        "  RET\n"
                        ";\n"
                        "OK_MSG   DB 'VGA.DRV loaded: VGA mode 80x25 / VESA active', 0Dh, 0Ah, '$'\n"
                        "VGA_FLAG DB 0\n"
                        "PAL_DATA DB 00h,00h,00h, 0FFh,0B0h,00h  ; 黑底黄字\n"
                        "         DB 0FFh,0FFh,0FFh\n"
                        ";\n"
                        "SEGMENT ENDS\n"
                        "END DRV_ENTRY\n",
                        driver=True, drv_type="video")

        # DOS 系统工具集 — 伪源码：每条都是一个有实际内容的汇编/批处理桩
        self.write_file(("C", ["DOS", "FORMAT.COM"]),
                        "; FORMAT.COM — 磁盘格式化工具 (v1.0)\n"
                        "; 伪源码：FAT 初始化 / 根目录建立 / 引导扇区写入\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET DRV_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  MOV CX, 0050h         ; 80 个磁道\n"
                        "FMT_CYL:\n"
                        "  PUSH CX\n"
                        "  MOV CX, 0010h         ; 16 磁头\n"
                        "FMT_HEAD:\n"
                        "  PUSH CX\n"
                        "  MOV CX, 003Fh         ; 63 扇区\n"
                        "FMT_SEC:\n"
                        "  CALL WRITE_SECTOR\n"
                        "  LOOP FMT_SEC\n"
                        "  POP CX\n"
                        "  LOOP FMT_HEAD\n"
                        "  POP CX\n"
                        "  LOOP FMT_CYL\n"
                        "  MOV DX, OFFSET DONE\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "WRITE_SECTOR: RET\n"
                        "DRV_MSG DB 'Formatting drive...$'\n"
                        "DONE    DB 'Format complete.', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "SYS.COM"]),
                        "; SYS.COM — 系统文件传输工具 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  MOV DX, OFFSET BOOT\n"
                        "  MOV CX, 0001h\n"
                        "  MOV BX, 7C00h\n"
                        "  MOV AH, 03h           ; 写引导扇区\n"
                        "  INT 13h\n"
                        "  MOV DX, OFFSET IO\n"
                        "  MOV CX, 0010h\n"
                        "  MOV BX, 0600h\n"
                        "  MOV AH, 03h\n"
                        "  INT 13h\n"
                        "  MOV DX, OFFSET DONE\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "MSG  DB 'System transfer...', 0Dh, 0Ah, '$'\n"
                        "BOOT DB '[BOOT SECTOR]', 0Dh, 0Ah\n"
                        "IO   DB '[IO.SYS / MSDOS.SYS]', 0Dh, 0Ah\n"
                        "DONE DB 'System transferred.', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "EDIT.COM"]),
                        "; EDIT.COM — 全屏编辑器 (v1.0) [katoEDIT 精简版]\n"
                        "; 伪源码：文本编辑 / 光标控制 / 文件 I/O\n"
                        "  ORG 0100h\n"
                        "  CALL GET_FILENAME\n"
                        "  CALL LOAD_FILE\n"
                        "  CALL EDITOR_MAIN\n"
                        "  CALL SAVE_FILE\n"
                        "  RET\n"
                        "EDITOR_MAIN:\n"
                        "  MOV AX, 0300h         ; 设置视频模式\n"
                        "  INT 10h\n"
                        "  MOV [CURSOR_X], 00h\n"
                        "  MOV [CURSOR_Y], 00h\n"
                        "ED_LOOP:\n"
                        "  MOV AH, 00h\n"
                        "  INT 16h\n"
                        "  CMP AL, 1Bh           ; ESC\n"
                        "  JZ  ED_EXIT\n"
                        "  CMP AL, 0Dh           ; ENTER\n"
                        "  JZ  ED_NEWLINE\n"
                        "  CMP AH, 48h           ; UP\n"
                        "  JZ  ED_UP\n"
                        "  CMP AH, 4Bh           ; LEFT\n"
                        "  JZ  ED_LEFT\n"
                        "  CMP AH, 4Dh           ; RIGHT\n"
                        "  JZ  ED_RIGHT\n"
                        "  CMP AH, 50h           ; DOWN\n"
                        "  JZ  ED_DOWN\n"
                        "  CALL PUT_CHAR\n"
                        "  JMP ED_LOOP\n"
                        "ED_EXIT:  RET\n"
                        "ED_NEWLINE: RET\n"
                        "ED_UP:    RET\n"
                        "ED_LEFT:  RET\n"
                        "ED_RIGHT: RET\n"
                        "ED_DOWN:  RET\n"
                        "PUT_CHAR: RET\n"
                        "GET_FILENAME: RET\n"
                        "LOAD_FILE: RET\n"
                        "SAVE_FILE: RET\n"
                        "CURSOR_X DB 0\n"
                        "CURSOR_Y DB 0\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "DEBUG.EXE"]),
                        "; DEBUG.EXE — 动态调试器 (v1.0)\n"
                        "; 伪源码：反汇编 / 内存转储 / 单步执行 / 断点\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET TITLE\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "DBG_LOOP:\n"
                        "  MOV DX, OFFSET PMT\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  MOV AH, 01h\n"
                        "  INT 21h\n"
                        "  CMP AL, 'D'          ; Dump\n"
                        "  JZ  CMD_DUMP\n"
                        "  CMP AL, 'U'          ; Unassemble\n"
                        "  JZ  CMD_UNASM\n"
                        "  CMP AL, 'G'          ; Go\n"
                        "  JZ  CMD_GO\n"
                        "  CMP AL, 'T'          ; Trace\n"
                        "  JZ  CMD_TRACE\n"
                        "  CMP AL, 'Q'          ; Quit\n"
                        "  JZ  DBG_EXIT\n"
                        "  JMP DBG_LOOP\n"
                        "CMD_DUMP:\n"
                        "  MOV AX, CS\n"
                        "  MOV ES, AX\n"
                        "  MOV CX, 0080h\n"
                        "  XOR SI, SI\n"
                        "DMP_LN:\n"
                        "  CALL PRINT_HEX_SI\n"
                        "  CALL PRINT_BUF\n"
                        "  ADD SI, 0010h\n"
                        "  LOOP DMP_LN\n"
                        "  JMP DBG_LOOP\n"
                        "CMD_UNASM: JMP DBG_LOOP\n"
                        "CMD_GO:    RET\n"
                        "CMD_TRACE: RET\n"
                        "DBG_EXIT:  RET\n"
                        "PRINT_HEX_SI: RET\n"
                        "PRINT_BUF: RET\n"
                        "TITLE DB 'katoDEBUG v1.0', 0Dh, 0Ah, '$'\n"
                        "PMT   DB 0Dh, 0Ah, '-$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "MEM.EXE"]),
                        "; MEM.EXE — 内存状态查看工具 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  MOV AX, 08800h\n"
                        "  INT 15h\n"
                        "  MOV [EXT_MEM], AX\n"
                        "  INT 12h              ; 常规内存\n"
                        "  MOV [CONV_MEM], AX\n"
                        "  MOV DX, OFFSET HDR\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  MOV DX, OFFSET CONV\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  CALL PRINT_AX_HEX\n"
                        "  MOV DX, OFFSET CRLF\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "PRINT_AX_HEX: RET\n"
                        "HDR  DB 'Memory Type        Total', 0Dh, 0Ah, '$'\n"
                        "CONV DB 'Conventional      $'\n"
                        "CRLF DB 0Dh, 0Ah, '$'\n"
                        "CONV_MEM DW 0\n"
                        "EXT_MEM  DW 0\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "XCOPY.EXE"]),
                        "; XCOPY.EXE — 增强复制工具 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "MSG DB 'XCOPY - Extended copy (simulated)', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "MORE.COM"]),
                        "; MORE.COM — 分页显示工具 (v1.0)\n"
                        "  ORG 0100h\n"
                        "MORE_LOOP:\n"
                        "  MOV CX, 0018h         ; 24 行\n"
                        "ML:\n"
                        "  MOV AH, 01h\n"
                        "  INT 21h\n"
                        "  CMP AL, 1Ah           ; EOF\n"
                        "  JZ  MORE_EXIT\n"
                        "  LOOP ML\n"
                        "  MOV DX, OFFSET PROMPT\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  MOV AH, 01h\n"
                        "  INT 21h\n"
                        "  CMP AL, 1Bh           ; ESC 退出\n"
                        "  JNZ MORE_LOOP\n"
                        "MORE_EXIT: RET\n"
                        "PROMPT DB '-- More --$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "TREE.COM"]),
                        "; TREE.COM — 目录树显示工具 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "MSG DB 'TREE - Directory tree (graphical)', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "ATTRIB.EXE"]),
                        "; ATTRIB.EXE — 文件属性管理 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "MSG DB 'ATTRIB v1.0 - Display/change file attributes', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "CHKDSK.EXE"]),
                        "; CHKDSK.EXE — 磁盘检查工具 (v1.0)\n"
                        "; 伪源码：FAT 链检查 / 簇分配 / 交叉链接检测\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  INT 12h\n"
                        "  CALL PRINT_NUM\n"
                        "  MOV DX, OFFSET MEM_MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "PRINT_NUM: RET\n"
                        "MSG     DB 'CHKDSK v1.0 - Checking disk...', 0Dh, 0Ah, '$'\n"
                        "MEM_MSG DB ' bytes total memory', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "DISKCOPY.COM"]),
                        "; DISKCOPY.COM — 磁盘复制工具 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "MSG DB 'DISKCOPY - Disk copy utility', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "KEYB.COM"]),
                        "; KEYB.COM — 键盘布局切换 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "MSG DB 'KEYB - Keyboard layout: US (default)', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "MODE.COM"]),
                        "; MODE.COM — 模式设置工具 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "MSG DB 'MODE - Display/device mode settings', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "SCANDISK.EXE"]),
                        "; SCANDISK.EXE — 磁盘扫描与修复 (v1.0)\n"
                        "; 伪源码：文件系统扫描 / 丢失簇回收 / 交叉链接修复\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  CALL SCAN_FAT\n"
                        "  CALL SCAN_DIR\n"
                        "  CALL CHECK_CROSSLINK\n"
                        "  MOV DX, OFFSET DONE\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "SCAN_FAT:      RET\n"
                        "SCAN_DIR:      RET\n"
                        "CHECK_CROSSLINK: RET\n"
                        "MSG  DB 'SCANDISK - Scanning file system...', 0Dh, 0Ah, '$'\n"
                        "DONE DB 'Scan complete, no errors found.', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "UNDELETE.EXE"]),
                        "; UNDELETE.EXE — 文件恢复工具 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "MSG DB 'UNDELETE - File recovery utility', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "DOSKEY.COM"]),
                        "; DOSKEY.COM — 命令行历史与宏 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  CALL INSTALL_HOOK\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "INSTALL_HOOK:\n"
                        "  XOR AX, AX\n"
                        "  MOV ES, AX\n"
                        "  MOV WORD PTR ES:[008Ch], DOSKEY_INT\n"
                        "  RET\n"
                        "DOSKEY_INT:\n"
                        "  IRET\n"
                        "MSG DB 'DOSKEY installed: history & macros active', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "SETVER.EXE"]),
                        "; SETVER.EXE — 版本设置表 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "MSG DB 'SETVER - Version table (katoDoS 1.0)', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "MSCDEX.EXE"]),
                        "; MSCDEX.EXE — CD-ROM 扩展 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "MSG DB 'MSCDEX - CD-ROM extension loaded (D:)', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "SMARTDRV.EXE"]),
                        "; SMARTDRV.EXE — 磁盘高速缓存 (v1.0)\n"
                        "; 伪源码：LRU 缓存 / 写延迟合并 / 写回策略\n"
                        "  ORG 0100h\n"
                        "  CALL INIT_CACHE\n"
                        "  CALL INSTALL_HOOK\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "INIT_CACHE:\n"
                        "  MOV [CACHE_SIZE], 2000h   ; 8K 缓存\n"
                        "  RET\n"
                        "INSTALL_HOOK:\n"
                        "  XOR AX, AX\n"
                        "  MOV ES, AX\n"
                        "  MOV WORD PTR ES:[004Ch], CACHE_INT ; INT 13h 钩子\n"
                        "  RET\n"
                        "CACHE_INT:\n"
                        "  IRET\n"
                        "MSG        DB 'SMARTDRV - Disk cache active (8K)', 0Dh, 0Ah, '$'\n"
                        "CACHE_SIZE DW 2000h\n",
                        system=False, protected=False)
        self.write_file(("C", ["DOS", "FDISK.EXE"]),
                        "; FDISK.EXE — 磁盘分区工具 (v1.0)\n"
                        "; 伪源码：MBR / 分区表 / 扩展分区 / 引导标志\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "MSG DB 'FDISK v1.0 - Fixed disk setup (simulated)', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        # DOS 目录中保留两个外壳文件作为"真实文件"（也可以 TYPE）
        self.write_file(("C", ["DOS", "COMMAND.COM"]),
                        "; katoDoS DOS secondary COMMAND.COM\n"
                        "; 镜像: C:\\COMMAND.COM\n"
                        "  ORG 0100h\n"
                        "  DB 'katoDoS COMMAND.COM (secondary)', 0Dh, 0Ah\n"
                        "  JMP 0F000h:0100h       ; 跳回主解释器\n",
                        system=False, protected=False)
        # IO.SYS / MSDOS.SYS — DOS 目录放完整伪源码镜像（与根目录相同）
        root_io = self.read_file(("C", ["IO.SYS"])) or ""
        root_ms = self.read_file(("C", ["MSDOS.SYS"])) or ""
        root_com = self.read_file(("C", ["COMMAND.COM"])) or ""
        self.write_file(("C", ["DOS", "IO.SYS"]), root_io, system=False, protected=False)
        self.write_file(("C", ["DOS", "MSDOS.SYS"]), root_ms, system=False, protected=False)

        # Windows 目录（兼容 CMD 风格）— 伪源码
        self.write_file(("C", ["WINDOWS", "WIN.COM"]),
                        "; WIN.COM — Windows 启动入口 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "MSG DB 'katoDoS Windows subsystem stub', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["WINDOWS", "WIN.INI"]),
                        "; WIN.INI — Windows 初始化配置文件\n"
                        ";\n"
                        "[windows]\n"
                        "load=\n"
                        "run=\n"
                        "Beep=Yes\n"
                        "Spooler=Yes\n"
                        "NullPort=None\n"
                        "device=HP LaserJet, HPPCL, LPT1:\n"
                        "\n"
                        "[desktop]\n"
                        "Wallpaper=C:\\WINDOWS\\KATO.BMP\n"
                        "TileWallpaper=0\n"
                        "WallpaperStyle=2\n"
                        "Pattern=(None)\n"
                        "\n"
                        "[extensions]\n"
                        "cal=calendar.exe ^.cal\n"
                        "crd=cardfile.exe ^.crd\n"
                        "trm=terminal.exe ^.trm\n"
                        "txt=notepad.exe ^.txt\n"
                        "ini=notepad.exe ^.ini\n"
                        "pcx=pbrush.exe ^.pcx\n"
                        "bmp=pbrush.exe ^.bmp\n"
                        "wri=write.exe ^.wri\n"
                        "\n"
                        "[fonts]\n"
                        "Courier New (TrueType)=COURIER.FOT\n"
                        "Arial (TrueType)=ARIAL.FOT\n"
                        "\n"
                        "[386Enh]\n"
                        "device=*vmm32\n"
                        "device=C:\\WINDOWS\\SYSTEM\\VGA.386\n"
                        "EMMExclude=C000-CFFF\n",
                        system=False, protected=False)
        self.write_file(("C", ["WINDOWS", "SYSTEM.INI"]),
                        "; SYSTEM.INI — Windows 系统配置\n"
                        ";\n"
                        "[boot]\n"
                        "shell=progman.exe\n"
                        "mouse=C:\\WINDOWS\\SYSTEM\\MOUSE.DRV\n"
                        "display=C:\\WINDOWS\\SYSTEM\\VGA.DRV\n"
                        "keyboard=C:\\WINDOWS\\SYSTEM\\KEYBOARD.DRV\n"
                        "system.drv=C:\\WINDOWS\\SYSTEM\\SYSTEM.DRV\n"
                        "drivers=C:\\WINDOWS\\SYSTEM\\TIMER.DRV\n"
                        "386grabber=C:\\WINDOWS\\SYSTEM\\VGAFIX.386\n"
                        "\n"
                        "[keyboard]\n"
                        "subtype=0\n"
                        "type=4\n"
                        "\n"
                        "[386Enh]\n"
                        "device=*vmm32\n"
                        "device=*vdmad\n"
                        "device=*vpicd\n"
                        "device=*int13\n"
                        "EMMExclude=A000-EFFF\n"
                        "MaxPhysPage=3FFFF\n",
                        system=False, protected=False)
        self.write_file(("C", ["WINDOWS", "REGEDIT.EXE"]),
                        "; REGEDIT.EXE — 注册表编辑器 (v1.0) [katoREG]\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "MSG DB 'katoREG - Registry Editor (simulated)', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["WINDOWS", "NOTEPAD.EXE"]),
                        "; NOTEPAD.EXE — 记事本 (v1.0) [katoPAD]\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "MSG DB 'katoPAD - Text Editor (linked to EDIT.COM)', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)

        # UTIL 额外工具 — 伪源码
        self.write_file(("C", ["UTIL", "CALC.EXE"]),
                        "; CALC.EXE — 计算器 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "MSG DB 'CALC - Calculator (simulated)', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["UTIL", "PLAY.EXE"]),
                        "; PLAY.EXE — 音频播放 (v1.0) [SB16 required]\n"
                        "  ORG 0100h\n"
                        "  MOV DX, 0220h\n"
                        "  MOV AL, 0E1h         ; 检测 DSP\n"
                        "  OUT DX, AL\n"
                        "  MOV DX, OFFSET MSG\n"
                        "  MOV AH, 09h\n"
                        "  INT 21h\n"
                        "  RET\n"
                        "MSG DB 'PLAY - Audio player (SB16 DSP detected)', 0Dh, 0Ah, '$'\n",
                        system=False, protected=False)
        self.write_file(("C", ["UTIL", "EDIT.COM"]),
                        "; EDIT.COM — 编辑器镜像 (指向 C:\\DOS\\EDIT.COM)\n"
                        "  ORG 0100h\n"
                        "  DB 'katoEDIT - see C:\\DOS\\EDIT.COM', 0Dh, 0Ah\n",
                        system=False, protected=False)
        self.write_file(("C", ["UTIL", "PING.EXE"]),
                        "; PING.EXE — 网络连通性测试 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  DB 'PING - Network tool, use PING command from shell', 0Dh, 0Ah\n",
                        system=False, protected=False)
        self.write_file(("C", ["UTIL", "TRACERT.EXE"]),
                        "; TRACERT.EXE — 路由跟踪 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  DB 'TRACERT - Route tracer, use TRACERT from shell', 0Dh, 0Ah\n",
                        system=False, protected=False)
        self.write_file(("C", ["UTIL", "IPCONFIG.EXE"]),
                        "; IPCONFIG.EXE — IP 配置查看 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  DB 'IPCONFIG - Network config, use IPCONFIG from shell', 0Dh, 0Ah\n",
                        system=False, protected=False)

        # 网络目录
        self.write_file(("C", ["NET", "HOSTS.TXT"]),
                        "127.0.0.1       localhost\n192.168.1.1     gateway\n8.8.8.8         dns\n")
        self.write_file(("C", ["NET", "CONFIG.TXT"]),
                        "IP=192.168.1.100\nMASK=255.255.255.0\nGATE=192.168.1.1\nDNS=8.8.8.8\n")

        # GAMES 游戏启动桩 — 伪源码
        self.write_file(("C", ["GAMES", "SNAKE.COM"]),
                        "; SNAKE.COM — 贪吃蛇 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  DB 'katoSNK v1.0 - Snake game', 0Dh, 0Ah\n"
                        "  DB 'Canvas-based, run from katoDoS terminal.', 0Dh, 0Ah\n",
                        system=False, protected=False)
        self.write_file(("C", ["GAMES", "TETRIS.COM"]),
                        "; TETRIS.COM — 俄罗斯方块 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  DB 'katoTET v1.0 - Tetris game', 0Dh, 0Ah\n"
                        "  DB 'Canvas-based, run from katoDoS terminal.', 0Dh, 0Ah\n",
                        system=False, protected=False)
        self.write_file(("C", ["GAMES", "MINES.COM"]),
                        "; MINES.COM — 扫雷 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  DB 'katoMINE v1.0 - Minesweeper', 0Dh, 0Ah\n"
                        "  DB 'Canvas-based, run from katoDoS terminal.', 0Dh, 0Ah\n",
                        system=False, protected=False)
        self.write_file(("C", ["GAMES", "GUESS.COM"]),
                        "; GUESS.COM — 猜数字 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  DB 'katoGUESS v1.0 - Number guessing game', 0Dh, 0Ah\n",
                        system=False, protected=False)
        self.write_file(("C", ["GAMES", "MATRIX.COM"]),
                        "; MATRIX.COM — 数字雨 (v1.0)\n"
                        "  ORG 0100h\n"
                        "  DB 'katoMATRIX v1.0 - Digital rain effect', 0Dh, 0Ah\n",
                        system=False, protected=False)
        self.write_file(("C", ["GAMES", "README.TXT"]),
                        "katoDoS 内置游戏：\n"
                        "  SNAKE   贪吃蛇   方向键/WASD 移动\n"
                        "  TETRIS  俄罗斯方块 方向键移动, 空格速降, 上旋转\n"
                        "  MINES   扫雷     左键挖, 右键标记, Q 退出\n"
                        "  GUESS   猜数字   输入 1-100, 回车猜\n"
                        "  MATRIX  数字雨   纯观赏, Q 退出\n")

        self.write_file(("C", ["README.TXT"]),
                        "katoDoS 1.0 - 像素 DOS 模拟器 (沙箱)\n"
                        "输入 HELP 查看命令；本系统同时兼容 MS-DOS / FreeDOS / CMD / PowerShell 语法。\n"
                        "输入 ASM / C 体验内置专属汇编器与类 C 解释器。\n"
                        "输入 SAVE / LOAD 保存或读取虚拟机快照。\n"
                        "警告：删除 IO.SYS / MSDOS.SYS / COMMAND.COM 会导致系统无法启动。\n"
                        "       删除驱动文件会导致对应功能不可用。\n")

        # D: 光盘
        self.write_file(("D", ["KATODOS.ISO.TXT"]), "虚拟光盘卷标: KATODOS_BOOT\n")
        self.write_file(("D", ["SETUP.EXE"]), "katoDoS 安装程序桩\n")

        # Z: 网络映射
        self.write_file(("Z", ["WELCOME.TXT"]), "Z: 网络驱动器 (模拟)\n")

        # 示例源码：汇编器 / 类 C 解释器
        self.write_file(("C", ["SRC", "HELLO.ASM"]),
                        "section .data\n"
                        "msg db \"Hello from katoASM!$\"\n"
                        "section .text\n"
                        "start:\n"
                        "    mov dx, msg\n"
                        "    mov ah, 09h\n"
                        "    int 21h\n"
                        "    mov ah, 4Ch\n"
                        "    int 21h\n")
        self.write_file(("C", ["SRC", "MATH.ASM"]),
                        "section .data\n"
                        "nl db 13, 10, '$'\n"
                        "section .text\n"
                        "start:\n"
                        "    mov cx, 10\n"
                        "    mov ax, 0\n"
                        "    mov bx, 1\n"
                        "sum:\n"
                        "    add ax, bx\n"
                        "    inc bx\n"
                        "    dec cx\n"
                        "    jnz sum\n"
                        "    call print_ax\n"
                        "    mov dx, nl\n"
                        "    mov ah, 09h\n"
                        "    int 21h\n"
                        "    mov ah, 4Ch\n"
                        "    int 21h\n"
                        "print_ax:\n"
                        "    mov bx, 10\n"
                        "    mov cx, 0\n"
                        "pdiv:\n"
                        "    mov dx, 0\n"
                        "    div bx\n"
                        "    add dl, '0'\n"
                        "    push dx\n"
                        "    inc cx\n"
                        "    cmp ax, 0\n"
                        "    jne pdiv\n"
                        "ppop:\n"
                        "    pop dx\n"
                        "    mov ah, 02h\n"
                        "    int 21h\n"
                        "    loop ppop\n"
                        "    ret\n")
        self.write_file(("C", ["SRC", "HELLO.C"]),
                        "print(\"Hello from katoC!\");\n"
                        "int a = 6, b = 7;\n"
                        "print(\"a + b =\", a + b);\n")
        self.write_file(("C", ["SRC", "FIB.C"]),
                        "int n = 10;\n"
                        "int a = 0, b = 1;\n"
                        "print(\"Fibonacci:\");\n"
                        "for (int i = 0; i < n; i = i + 1) {\n"
                        "    print(a);\n"
                        "    int t = a + b;\n"
                        "    a = b;\n"
                        "    b = t;\n"
                        "}\n")

    # ---------- 底层节点操作 ----------
    def _mkdir_node(self, node: Dict[str, Any], name: str) -> Dict[str, Any]:
        name = name.upper()
        if name not in node["children"]:
            node["children"][name] = _dir_node()
        return node["children"][name]

    def is_protected(self, ref: Ref) -> bool:
        n = self.get_node(ref)
        return bool(n and n.get("protected"))

    def is_system(self, ref: Ref) -> bool:
        n = self.get_node(ref)
        return bool(n and n.get("system"))

    def is_driver(self, ref: Ref) -> Optional[str]:
        n = self.get_node(ref)
        if n and n.get("driver"):
            return n.get("drv_type", "")
        return None

    def is_formatted(self, drive: str) -> bool:
        d = self.drives.get(drive.upper())
        return bool(d and d["formatted"])

    def drive_list(self) -> List[str]:
        return sorted(self.drives.keys())

    # ---------- 外接 U 盘挂载（懒加载 + 临时缓存，只读沙箱） ----------
    def is_mounted(self, drive: str) -> bool:
        d = self.drives.get(drive.upper())
        return bool(d and d.get("mounted"))

    def volume_label(self, drive: str) -> Optional[str]:
        return self.mount_labels.get(drive.upper())

    def mount_real_usage(self, drive: str):
        """返回挂载盘的 (已用字节, 总字节)；非挂载盘或失败返回 None。"""
        d = self.drives.get(drive.upper())
        if not d or not d.get("mounted"):
            return None
        mount = d.get("mount")
        if not mount:
            return None
        try:
            import shutil
            u = shutil.disk_usage(mount.real_root)
            return (u.used, u.total)
        except Exception:
            return None

    def real_size(self, ref: Ref) -> int:
        """挂载盘上 lazy 文件返回真实字节数（stat，不读内容）。"""
        n = self.get_node(ref)
        if n is None:
            return 0
        if n.get("lazy"):
            d = self.drives.get(ref[0].upper())
            if d and d.get("mounted"):
                mount = d.get("mount")
                if mount:
                    return mount.file_size("/".join(ref[1]))
        return len(n.get("content", ""))

    def mount_usb(self, letter: str, real_root: str, cache_path: str, label: str = "") -> None:
        letter = letter.upper()
        self.drives[letter] = {"formatted": True, "root": _dir_node(), "mounted": True}
        self.drives[letter]["mount"] = UsbMount(real_root, cache_path, label)
        self.mount_labels[letter] = label or ("可移动磁盘 %s" % letter)

    def unmount_usb(self, letter: str) -> bool:
        letter = letter.upper()
        d = self.drives.get(letter)
        if d and d.get("mounted"):
            mount = d.get("mount")
            # 删除临时缓存文件
            if mount and mount.cache_path:
                try:
                    if os.path.exists(mount.cache_path):
                        os.remove(mount.cache_path)
                except Exception:
                    pass
            del self.drives[letter]
            self.mount_labels.pop(letter, None)
            return True
        return False

    def auto_mount_usb(self, letter: str = "U") -> List[Dict[str, str]]:
        """检测并自动挂载所有可移动磁盘。返回 [{letter, label, root}]。"""
        found = detect_removable_drives()
        mounted = []
        for info in found:
            dup = any(
                d.get("mounted") and d.get("mount") and
                d["mount"].real_root.upper() == info["root"].upper()
                for d in self.drives.values()
            )
            if dup:
                for L, d in self.drives.items():
                    if d.get("mounted") and d.get("mount") and \
                       d["mount"].real_root.upper() == info["root"].upper():
                        mounted.append({"letter": L, "label": d["mount"].label, "root": info["root"]})
                continue
            cache_path = os.path.join(tempfile.gettempdir(), "katodos",
                                     "usb_%s.cache.json" % info["letter"])
            try:
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            except Exception:
                pass
            self.mount_usb(letter, info["root"], cache_path, info["label"])
            mounted.append({"letter": letter, "label": info["label"], "root": info["root"]})
            if letter != "E":
                letter = chr(ord(letter) - 1)
        return mounted

    def _ensure_mounted(self, ref: Ref) -> None:
        """访问挂载盘路径时，逐层确保目录已在内存树中占位（只建占位，不读文件内容）。"""
        drive, segs = ref
        d = self.drives.get(drive.upper())
        if not d or not d.get("mounted"):
            return
        mount = d.get("mount")
        if not mount:
            return
        mount.ensure_dir("")
        root = d["root"]
        self._populate(root, mount.cache["dirs"][""], mount)
        node = root
        rel_parts: List[str] = []
        for seg in segs:
            if node.get("type") != "dir":
                return
            child = node["children"].get(seg)
            if child is None or child.get("type") != "dir":
                return
            rel_parts.append(seg)
            rel = "/".join(rel_parts)
            mount.ensure_dir(rel)
            self._populate(child, mount.cache["dirs"][rel], mount)
            node = child

    def _populate(self, node: Dict[str, Any], dirinfo: Dict[str, Any], mount: "UsbMount") -> None:
        for name in dirinfo.get("dirs", []):
            key = name.upper()
            if key not in node["children"]:
                child = _dir_node()
                child["_mount"] = True
                node["children"][key] = child
        for name in dirinfo.get("files", []):
            key = name.upper()
            if key not in node["children"]:
                child = _file_node("", lazy=True)
                child["_mount"] = True
                node["children"][key] = child

    # ---------- 路径解析 ----------
    def resolve(self, path: str, cur_drive: str, cur_segs: PathSegs) -> Optional[Ref]:
        """把任意路径解析为 (drive, segs)。失败返回 None。"""
        path = path.replace("/", "\\").strip()
        if not path:
            return (cur_drive.upper(), list(cur_segs))
        # 盘符
        drive = cur_drive.upper()
        rest = path
        if len(path) >= 2 and path[1] == ":":
            drive = path[0].upper()
            rest = path[2:]
        if not self.is_formatted(drive):
            # 未格式化盘，仅允许解析到根
            if rest in ("", "\\"):
                return (drive, [])
            return None
        # 绝对还是相对
        if rest.startswith("\\"):
            segs: List[str] = []
            parts = [p for p in rest.split("\\") if p != ""]
        else:
            segs = list(cur_segs)
            parts = [p for p in rest.split("\\") if p != ""]
        for p in parts:
            if p == ".":
                continue
            elif p == "..":
                if segs:
                    segs.pop()
            else:
                segs.append(p.upper())
        return (drive, segs)

    def get_node(self, ref: Ref) -> Optional[Dict[str, Any]]:
        drive, segs = ref
        d = self.drives.get(drive.upper())
        if not d or not d["formatted"]:
            return None
        if d.get("mounted"):
            self._ensure_mounted(ref)
        node = d["root"]
        for seg in segs:
            if node.get("type") != "dir":
                return None
            node = node["children"].get(seg)
            if node is None:
                return None
        return node

    def exists(self, ref: Ref) -> bool:
        return self.get_node(ref) is not None

    def is_dir(self, ref: Ref) -> bool:
        n = self.get_node(ref)
        return n is not None and n.get("type") == "dir"

    def is_file(self, ref: Ref) -> bool:
        n = self.get_node(ref)
        return n is not None and n.get("type") == "file"

    def list(self, ref: Ref) -> Optional[List[Tuple[str, Dict[str, Any]]]]:
        n = self.get_node(ref)
        if n is None or n.get("type") != "dir":
            return None
        items = [(k, v) for k, v in n["children"].items()]
        items.sort(key=lambda kv: (kv[1]["type"] != "dir", kv[0]))
        return items

    def mkdir(self, ref: Ref) -> bool:
        """创建目录（含父目录）。"""
        drive, segs = ref
        d = self.drives.get(drive.upper())
        if not d or not d["formatted"]:
            return False
        if d.get("mounted"):
            return False  # 外部卷为只读沙箱镜像
        node = d["root"]
        for seg in segs:
            if seg not in node["children"]:
                node["children"][seg] = _dir_node()
            node = node["children"][seg]
            if node.get("type") != "dir":
                return False
        return True

    def write_file(self, ref: Ref, content: str, protected: bool = False,
                   system: bool = False, driver: bool = False, drv_type: str = "") -> bool:
        drive, segs = ref
        if not segs:
            return False
        d = self.drives.get(drive.upper())
        if not d or not d["formatted"]:
            return False
        if d.get("mounted"):
            return False  # 外部卷为只读沙箱镜像，禁止写回真实设备
        parent = (drive, segs[:-1])
        if not self.is_dir(parent):
            if not self.mkdir(parent):
                return False
        parent_node = self.get_node(parent)
        name = segs[-1].upper()
        parent_node["children"][name] = _file_node(content, protected=protected,
                                                   system=system, driver=driver, drv_type=drv_type)
        return True

    def read_file(self, ref: Ref) -> Optional[str]:
        n = self.get_node(ref)
        if n is None or n.get("type") != "file":
            return None
        # 挂载盘上的 lazy 文件：首次读取才从真实 U 盘读内容并写入临时缓存
        if n.get("lazy") and self.drives.get(ref[0].upper(), {}).get("mounted"):
            mount = self.drives[ref[0].upper()].get("mount")
            if mount:
                content = mount.read_file("/".join(ref[1]))
                if content is None:
                    return None
                n["content"] = content
                n.pop("lazy", None)
        return n.get("content", "")

    def delete(self, ref: Ref) -> bool:
        drive, segs = ref
        if not segs:
            return False
        if self.drives.get(drive.upper(), {}).get("mounted"):
            return False  # 外部卷为只读沙箱镜像
        parent = (drive, segs[:-1])
        pn = self.get_node(parent)
        if pn is None or pn.get("type") != "dir":
            return False
        name = segs[-1].upper()
        if name in pn["children"]:
            del pn["children"][name]
            return True
        return False

    def rename(self, ref: Ref, new_name: str) -> bool:
        drive, segs = ref
        if self.drives.get(drive.upper(), {}).get("mounted"):
            return False  # 外部卷为只读沙箱镜像
        pn = self.get_node((drive, segs[:-1]))
        if pn is None or pn.get("type") != "dir":
            return False
        name = segs[-1].upper()
        if name not in pn["children"]:
            return False
        node = pn["children"].pop(name)
        pn["children"][new_name.upper()] = node
        return True

    def disk_usage_bytes(self, drive: str) -> int:
        """递归统计某驱动器已用字节数（用于 VOL/DIR 显示剩余空间）。"""
        d = self.drives.get(drive.upper())
        if not d:
            return 0
        total = 0
        stack = [d["root"]]
        while stack:
            node = stack.pop()
            if node.get("type") == "file":
                total += len(node.get("content", "").encode("utf-8", "replace"))
            elif node.get("type") == "dir":
                for child in node["children"].values():
                    stack.append(child)
        return total

    # ---------- 系统恢复 (SYS) ----------
    def sys_transfer(self, drive: str = "C") -> None:
        """SYS 命令：把系统启动文件与驱动写回指定驱动器。

        不删除任何已有文件（覆盖同名系统文件而已），因此可用来在
        格式化 / 误删系统文件后恢复可引导状态。
        """
        drive = drive.upper()
        if drive not in self.drives:
            return
        if not self.drives[drive]["formatted"]:
            self.drives[drive]["formatted"] = True
            self.drives[drive]["root"] = _dir_node()
        root = self.drives[drive]["root"]
        for d in ["DOS", "WINDOWS", "DRIVERS", "UTIL", "GAMES", "TEMP", "USERS", "SRC", "NET", "IMPORT"]:
            self._mkdir_node(root, d)

        # 核心系统文件（删除会导致无法启动）—— 用带内容的伪源码
        root_io = ("C", ["IO.SYS"])
        root_ms = ("C", ["MSDOS.SYS"])
        root_com = ("C", ["COMMAND.COM"])
        # 从已初始化的 C 盘读取完整伪源码
        src_io = self.read_file(root_io) if self.is_file(root_io) else None
        src_ms = self.read_file(root_ms) if self.is_file(root_ms) else None
        src_com = self.read_file(root_com) if self.is_file(root_com) else None
        src_auto = self.read_file(("C", ["AUTOEXEC.BAT"])) if self.is_file(("C", ["AUTOEXEC.BAT"])) else None
        src_config = self.read_file(("C", ["CONFIG.SYS"])) if self.is_file(("C", ["CONFIG.SYS"])) else None
        self.write_file((drive, ["IO.SYS"]),
                        src_io if src_io else "; katoDoS IO.SYS (sys_transfer)\n",
                        system=True, protected=True)
        self.write_file((drive, ["MSDOS.SYS"]),
                        src_ms if src_ms else "; katoDoS MSDOS.SYS (sys_transfer)\n",
                        system=True, protected=True)
        self.write_file((drive, ["COMMAND.COM"]),
                        src_com if src_com else "; katoDoS COMMAND.COM (sys_transfer)\n",
                        system=True, protected=True)
        self.write_file((drive, ["AUTOEXEC.BAT"]),
                        src_auto if src_auto else "@ECHO OFF\nPROMPT $P$G\nPATH C:\\DOS;C:\\UTIL;C:\\GAMES;C:\\IMPORT\nECHO katoDoS 已就绪。\n",
                        system=True, protected=True)
        self.write_file((drive, ["CONFIG.SYS"]),
                        src_config if src_config else "; katoDoS CONFIG.SYS (sys_transfer)\n",
                        system=True, protected=True)

        # 驱动文件（删除会导致对应功能不可用）—— 从已初始化的 C 盘读取完整伪源码
        for drv_name, drv_type in [
            ("HIMEM.SYS", "memory"), ("EMM386.EXE", "memory"),
            ("NE2000.DRV", "network"), ("MOUSE.SYS", "mouse"),
            ("KEYBOARD.DRV", "keyboard"),
            ("SB16.DRV", "sound"), ("VGA.DRV", "video"),
        ]:
            ref = (drive, ["DRIVERS", drv_name])
            src_ref = ("C", ["DRIVERS", drv_name])
            content = self.read_file(src_ref) if self.is_file(src_ref) else "; %s (sys_transfer)\n" % drv_name
            self.write_file(ref, content, driver=True, drv_type=drv_type)

        # DOS 系统工具集
        dos_tools = [
            "FDISK.EXE", "FORMAT.COM", "SYS.COM", "EDIT.COM", "DEBUG.EXE",
            "MEM.EXE", "XCOPY.EXE", "MORE.COM", "TREE.COM", "ATTRIB.EXE",
            "CHKDSK.EXE", "DISKCOPY.COM", "KEYB.COM", "MODE.COM", "SCANDISK.EXE",
            "UNDELETE.EXE", "DOSKEY.COM", "SETVER.EXE", "MSCDEX.EXE", "SMARTDRV.EXE",
            "COMMAND.COM", "IO.SYS", "MSDOS.SYS",
        ]
        for t in dos_tools:
            self.write_file((drive, ["DOS", t]), "katoDoS 系统工具桩: %s\n" % t)

        # Windows 目录
        for t in ["WIN.COM", "WIN.INI", "SYSTEM.INI", "REGEDIT.EXE", "NOTEPAD.EXE"]:
            self.write_file((drive, ["WINDOWS", t]), "katoDoS Windows 桩: %s\n" % t)

        # UTIL 额外工具
        for t in ["CALC.EXE", "PLAY.EXE", "EDIT.COM", "PING.EXE", "TRACERT.EXE", "IPCONFIG.EXE"]:
            self.write_file((drive, ["UTIL", t]), "katoDoS 实用工具桩: %s\n" % t)

        # 网络目录
        self.write_file((drive, ["NET", "HOSTS.TXT"]),
                        "127.0.0.1       localhost\n192.168.1.1     gateway\n8.8.8.8         dns\n")
        self.write_file((drive, ["NET", "CONFIG.TXT"]),
                        "IP=192.168.1.100\nMASK=255.255.255.0\nGATE=192.168.1.1\nDNS=8.8.8.8\n")

        # GAMES 游戏启动桩
        for t in ["SNAKE.COM", "TETRIS.COM", "MINES.COM", "GUESS.COM", "MATRIX.COM"]:
            self.write_file((drive, ["GAMES", t]), "katoDoS 游戏入口桩: %s\n" % t)

        # 示例源码
        self.write_file((drive, ["SRC", "HELLO.ASM"]),
                        "section .data\nmsg db \"Hello from katoASM!$\"\nsection .text\n"
                        "start:\n    mov dx, msg\n    mov ah, 09h\n    int 21h\n"
                        "    mov ah, 4Ch\n    int 21h\n")
        self.write_file((drive, ["SRC", "HELLO.C"]),
                        "print(\"Hello from katoC!\");\nint a = 6, b = 7;\n"
                        "print(\"a + b =\", a + b);\n")

    # ---------- 序列化 ----------
    def serialize(self) -> str:
        # 挂载盘是运行时外部设备，不持久化进快照
        clean = {L: d for L, d in self.drives.items() if not d.get("mounted")}
        return json.dumps({"drives": clean}, ensure_ascii=False)

    @classmethod
    def deserialize(cls, data: str) -> "VFS":
        obj = cls.__new__(cls)
        obj.drives = {}
        try:
            loaded = json.loads(data)
            obj.drives = loaded.get("drives", {})
        except Exception:
            obj.drives = {}
        # 补全默认盘符，避免旧快照缺盘
        for letter in ["C", "D", "A", "Z"]:
            if letter not in obj.drives:
                obj.drives[letter] = {"formatted": letter != "A", "root": _dir_node()}
        return obj

    def save_to(self, path: str) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(self.serialize())
        os.replace(tmp, path)

    @classmethod
    def load_from(cls, path: str) -> "VFS":
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return cls.deserialize(f.read())
            except Exception:
                pass
        return cls()


def fmt_path(ref: Ref) -> str:
    drive, segs = ref
    if not segs:
        return f"{drive}:\\"
    return f"{drive}:\\" + "\\".join(segs)
