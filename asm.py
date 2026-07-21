"""katoASM — katoDoS 专属汇编器 / 解释器

一个 8086 子集的汇编器 + 寄存器虚拟机，语法贴近 NASM。
支持段 (.data/.text)、标号、寄存器 (AX..SP / 8 位 AH..DL)、
内存寻址、条件跳转、子程序 (call/ret)，以及 DOS INT 21h 系统调用：
    ah=02h  在 dl 中打印单个字符
    ah=09h  打印 ds:dx 指向、以 '$' 结尾的字符串
    ah=01h  从输入流读取一个字符 -> al
    ah=4Ch 退出，返回码在 al
    int 20h 终止

示例 (hello.asm):
    section .data
    msg db "Hello, katoDoS!$"
    section .text
    start:
        mov dx, msg
        mov ah, 09h
        int 21h
        mov ah, 4Ch
        mov al, 0
        int 21h
"""

DATA_BASE = 0x100  # 数据段基址 (像 COM 文件)
MEM_SIZE = 0x10000


class AsmError(Exception):
    def __init__(self, msg, line=-1):
        self.line = line
        super().__init__(("汇编错误 (行 %d): %s" % (line, msg)) if line >= 0 else ("汇编错误: %s" % msg))


REGS16 = ["AX", "BX", "CX", "DX", "SI", "DI", "BP", "SP"]
REG8_TO16 = {"AH": "AX", "AL": "AX", "BH": "BX", "BL": "BX",
             "CH": "CX", "CL": "CX", "DH": "DX", "DL": "DX"}


def _parse_num(tok):
    tok = tok.strip()
    if len(tok) >= 2 and tok[0] == "'" and tok[-1] == "'":
        if len(tok) == 3:
            return ord(tok[1])
        raise AsmError("非法字符常量: " + tok)
    if len(tok) >= 3 and tok[1:3] in ("0x", "0X"):
        return int(tok[2:], 16)
    if len(tok) >= 2 and tok[-1] in "bB" and all(c in "01" for c in tok[:-1]):
        return int(tok[:-1], 2)
    if len(tok) >= 2 and tok[-1] in "hH" and tok[0].isdigit():
        return int(tok[:-1], 16)
    s = tok
    if s and s[-1] in "dD":
        s = s[:-1]
    if s.startswith("-"):
        return -int(s)
    return int(s)


def _is_reg(tok):
    t = tok.upper()
    return t in REGS16 or t in REG8_TO16


class Assembler:
    def __init__(self):
        self.data_bytes = bytearray()
        self.data_labels = {}
        self.code_labels = {}
        self.code = []          # (op, [operands], lineno)
        self.entry = 0

    def assemble(self, src):
        raw_lines = src.replace("\r\n", "\n").split("\n")
        lines = []
        for i, raw in enumerate(raw_lines, 1):
            if ";" in raw:
                raw = raw[:raw.index(";")]
            raw = raw.strip()
            if not raw:
                continue
            lines.append((i, raw))

        section = ".text"
        for lineno, line in lines:
            low = line.lower()
            if low.startswith("section"):
                seg = line.split(None, 1)[1].strip().lower() if len(line.split()) > 1 else ""
                section = ".data" if seg in (".data", "data") else ".text"
                continue
            if low.startswith("org"):
                continue
            if section == ".data":
                self._parse_data(line, lineno)
            else:
                self._parse_text(line, lineno)

        if "start" in self.code_labels:
            self.entry = self.code_labels["start"]
        else:
            self.entry = 0

    def _parse_data(self, line, lineno):
        if line.endswith(":"):
            self.data_labels[line[:-1].upper()] = len(self.data_bytes)
            return
        low = " " + line.lower() + " "
        if " db " in low or " dw " in low or " resb " in low:
            idx = line.index(" ")
            name = line[:idx].strip()
            rest = line[idx + 1:].strip()
            directive, _, val = rest.partition(" ")
            directive = directive.lower()
            self.data_labels[name.upper()] = len(self.data_bytes)
            if directive == "resb":
                n = _parse_num(val.strip())
                self.data_bytes.extend(bytes(n))
            elif directive == "db":
                for v in self._split_data(val):
                    if isinstance(v, str):
                        self.data_bytes.extend(v.encode("latin-1", "replace"))
                    else:
                        self.data_bytes.append(v & 0xFF)
            elif directive == "dw":
                for v in self._split_data(val):
                    if isinstance(v, str):
                        for ch in v.encode("latin-1", "replace"):
                            self.data_bytes.append(ch)
                    else:
                        w = v & 0xFFFF
                        self.data_bytes.append(w & 0xFF)
                        self.data_bytes.append((w >> 8) & 0xFF)
            else:
                raise AsmError("未知数据伪指令: " + directive, lineno)
        else:
            if line.endswith(":"):
                self.data_labels[line[:-1].upper()] = len(self.data_bytes)
            else:
                raise AsmError("无法解析的数据段行: " + line, lineno)

    def _split_data(self, s):
        out = []
        i = 0
        s = s.strip()
        while i < len(s):
            c = s[i]
            if c == '"' or c == "'":
                j = s.index(c, i + 1)
                out.append(s[i + 1:j])
                i = j + 1
            elif c.isspace() or c == ",":
                i += 1
                continue
            else:
                j = i
                while j < len(s) and s[j] not in (",", " ", "\t"):
                    j += 1
                out.append(_parse_num(s[i:j]))
                i = j
        return out

    def _parse_text(self, line, lineno):
        if line.endswith(":") and " " not in line and line.count(":") == 1:
            self.code_labels[line[:-1].upper()] = len(self.code)
            return
        if ":" in line:
            label, _, rest = line.partition(":")
            self.code_labels[label.strip().upper()] = len(self.code)
            line = rest.strip()
            if not line:
                return
        if " " in line:
            op, _, ops = line.partition(" ")
            op = op.strip().lower()
            ops = ops.strip()
        else:
            op = line.lower()
            ops = ""
        operands = [o.strip() for o in ops.split(",")] if ops else []
        self.code.append((op, operands, lineno))

    def resolve_operand(self, opstr):
        opstr = opstr.strip()
        if opstr.startswith("[") and opstr.endswith("]"):
            return ("mem", opstr[1:-1].strip())
        if _is_reg(opstr):
            return ("reg", opstr.upper())
        return ("ref", opstr)


class VM:
    def __init__(self, asm, stdin=""):
        self.asm = asm
        self.mem = bytearray(MEM_SIZE)
        self.mem[DATA_BASE:DATA_BASE + len(asm.data_bytes)] = asm.data_bytes
        self.regs = {r: 0 for r in REGS16}
        self.regs["SP"] = 0xFFF0
        self.flags = {"Z": 0, "S": 0, "C": 0}
        self.ip = asm.entry
        self.output = ""
        self.exit_code = 0
        self.halted = False
        self._in_chars = list(stdin)
        self._in_pos = 0

    def _reg_size(self, name):
        return 1 if name in REG8_TO16 else 2

    def reg_get(self, name):
        name = name.upper()
        if name in REGS16:
            return self.regs[name]
        base = REG8_TO16[name]
        val = self.regs[base]
        return (val >> 8) & 0xFF if name[1] == "H" else val & 0xFF

    def reg_set(self, name, val):
        name = name.upper()
        val &= 0xFFFF
        if name in REGS16:
            self.regs[name] = val
            return
        base = REG8_TO16[name]
        lo = self.regs[base] & 0xFF
        hi = (self.regs[base] >> 8) & 0xFF
        if name[1] == "H":
            hi = val & 0xFF
        else:
            lo = val & 0xFF
        self.regs[base] = (hi << 8) | lo

    def mem_get(self, addr, size):
        addr &= 0xFFFF
        if size == 1:
            return self.mem[addr]
        return self.mem[addr] | (self.mem[(addr + 1) & 0xFFFF] << 8)

    def mem_set(self, addr, val, size):
        addr &= 0xFFFF
        val &= 0xFF if size == 1 else 0xFFFF
        if size == 1:
            self.mem[addr] = val
        else:
            self.mem[addr] = val & 0xFF
            self.mem[(addr + 1) & 0xFFFF] = (val >> 8) & 0xFF

    def _resolve_mem(self, expr):
        expr = expr.strip()
        total = 0
        parts = expr.replace("-", "+-").split("+")
        for p in parts:
            p = p.strip()
            if not p:
                continue
            if p.startswith("-"):
                total -= self._resolve_atom(p[1:].strip())
            else:
                total += self._resolve_atom(p)
        return total & 0xFFFF

    def _resolve_atom(self, p):
        if _is_reg(p):
            return self.reg_get(p)
        if p.upper() in self.asm.data_labels:
            return DATA_BASE + self.asm.data_labels[p.upper()]
        return _parse_num(p)

    def _resolve_label_ip(self, name):
        name = name.upper()
        if name in self.asm.code_labels:
            return self.asm.code_labels[name]
        raise AsmError("未定义标号: " + name)

    def _read_val(self, operand, size):
        kind = operand[0]
        if kind == "imm":
            return operand[1] & (0xFF if size == 1 else 0xFFFF)
        if kind == "reg":
            return self.reg_get(operand[1])
        if kind == "mem":
            addr = self._resolve_mem(operand[1])
            return self.mem_get(addr, size)
        if kind == "ref":
            name = operand[1]
            if name.upper() in self.asm.data_labels:
                return DATA_BASE + self.asm.data_labels[name.upper()]
            if _is_reg(name):
                return self.reg_get(name)
            return _parse_num(name) & 0xFFFF
        raise AsmError("非法操作数")

    def _write_val(self, operand, val, size):
        kind = operand[0]
        if kind == "reg":
            self.reg_set(operand[1], val)
            return
        if kind == "mem":
            addr = self._resolve_mem(operand[1])
            self.mem_set(addr, val, size)
            return
        raise AsmError("无法写入操作数: " + str(operand))

    def _operand_size(self, operand, fallback):
        if operand[0] == "reg":
            return self._reg_size(operand[1])
        return fallback

    def _set_flags(self, res, size):
        mask = 0xFF if size == 1 else 0xFFFF
        self.flags["Z"] = 1 if (res & mask) == 0 else 0
        self.flags["S"] = 1 if (res & (0x80 if size == 1 else 0x8000)) else 0

    def run(self):
        code = self.asm.code
        while not self.halted and 0 <= self.ip < len(code):
            op, operands, lineno = code[self.ip]
            self.ip += 1
            try:
                self._step(op, operands)
            except AsmError as e:
                e.line = lineno
                raise
        return self.output

    def _norm(self, s):
        return self.asm.resolve_operand(s)

    def _step(self, op, operands):
        if op == "nop" or op == "hlt":
            if op == "hlt":
                self.halted = True
            return

        if op in ("mov", "add", "sub", "and", "or", "xor"):
            d = self._norm(operands[0])
            s = self._norm(operands[1])
            size = self._operand_size(d, 2)
            a = self._read_val(d, size)
            b = self._read_val(s, size)
            if op == "mov":
                res = b
            elif op == "add":
                raw = a + b
                self.flags["C"] = 1 if raw > (0xFF if size == 1 else 0xFFFF) else 0
                res = raw
            elif op == "sub":
                raw = a - b
                self.flags["C"] = 1 if raw < 0 else 0
                res = raw
            else:
                res = {"and": a & b, "or": a | b, "xor": a ^ b}[op]
            res &= (0xFF if size == 1 else 0xFFFF)
            self._write_val(d, res, size)
            if op != "mov":
                self._set_flags(res, size)
            return

        if op in ("mul", "imul"):
            s = self._norm(operands[0])
            size = self._operand_size(s, 2)
            b = self._read_val(s, size)
            if size == 1:
                a = self.reg_get("AL")
                res = a * b
                self.reg_set("AX", res & 0xFFFF)
                self.flags["C"] = 1 if res > 0xFF else 0
            else:
                a = self.reg_get("AX")
                res = a * b
                self.reg_set("AX", res & 0xFFFF)
                self.reg_set("DX", (res >> 16) & 0xFFFF)
                self.flags["C"] = 1 if res > 0xFFFF else 0
            return

        if op in ("div", "idiv"):
            s = self._norm(operands[0])
            size = self._operand_size(s, 2)
            b = self._read_val(s, size)
            if b == 0:
                raise AsmError("除零")
            if size == 1:
                a = self.reg_get("AX")
                self.reg_set("AL", (a // b) & 0xFF)
                self.reg_set("AH", (a % b) & 0xFF)
            else:
                a = (self.reg_get("DX") << 16) | self.reg_get("AX")
                self.reg_set("AX", (a // b) & 0xFFFF)
                self.reg_set("DX", (a % b) & 0xFFFF)
            return

        if op in ("inc", "dec", "not", "neg"):
            d = self._norm(operands[0])
            size = self._operand_size(d, 2)
            a = self._read_val(d, size)
            if op == "inc":
                res = a + 1
            elif op == "dec":
                res = a - 1
            elif op == "not":
                res = (~a) & (0xFF if size == 1 else 0xFFFF)
            else:
                res = (-a) & (0xFF if size == 1 else 0xFFFF)
            res &= (0xFF if size == 1 else 0xFFFF)
            self._write_val(d, res, size)
            self._set_flags(res, size)
            return

        if op == "cmp":
            a = self._read_val(self._norm(operands[0]), 2)
            b = self._read_val(self._norm(operands[1]), 2)
            res = a - b
            self.flags["C"] = 1 if res < 0 else 0
            self._set_flags(res, 2)
            return

        if op in ("push", "pop"):
            if op == "push":
                v = self._read_val(self._norm(operands[0]), 2)
                self.regs["SP"] = (self.regs["SP"] - 2) & 0xFFFF
                self.mem_set(self.regs["SP"], v, 2)
            else:
                v = self.mem_get(self.regs["SP"], 2)
                self.regs["SP"] = (self.regs["SP"] + 2) & 0xFFFF
                self._write_val(self._norm(operands[0]), v, 2)
            return

        if op == "call":
            target = self._resolve_label_ip(operands[0])
            self.regs["SP"] = (self.regs["SP"] - 2) & 0xFFFF
            self.mem_set(self.regs["SP"], self.ip, 2)
            self.ip = target
            return
        if op == "ret":
            v = self.mem_get(self.regs["SP"], 2)
            self.regs["SP"] = (self.regs["SP"] + 2) & 0xFFFF
            self.ip = v
            return

        if op == "jmp":
            self.ip = self._resolve_label_ip(operands[0])
            return

        jmap = {
            "je": lambda: self.flags["Z"], "jz": lambda: self.flags["Z"],
            "jne": lambda: not self.flags["Z"], "jnz": lambda: not self.flags["Z"],
            "jg": lambda: not self.flags["Z"] and not self.flags["S"],
            "jge": lambda: not self.flags["S"],
            "jl": lambda: self.flags["S"],
            "jle": lambda: self.flags["Z"] or self.flags["S"],
            "ja": lambda: not self.flags["C"] and not self.flags["Z"],
            "jb": lambda: self.flags["C"],
            "jc": lambda: self.flags["C"],
            "jnc": lambda: not self.flags["C"],
        }
        if op in jmap:
            if jmap[op]():
                self.ip = self._resolve_label_ip(operands[0])
            return

        if op == "int":
            self._int(_parse_num(operands[0]))
            return

        if op == "lea":
            d = self._norm(operands[0])
            addr = self._resolve_mem(operands[1])
            self._write_val(d, addr, 2)
            return

        if op == "loop":
            self.regs["CX"] = (self.regs["CX"] - 1) & 0xFFFF
            if self.regs["CX"] != 0:
                self.ip = self._resolve_label_ip(operands[0])
            return

        raise AsmError("不支持的指令: " + op)

    def _int(self, num):
        if num == 0x20:
            self.halted = True
            return
        if num != 0x21:
            return
        ah = self.reg_get("AH")
        if ah == 0x02:
            ch = self.reg_get("DL")
            if 32 <= ch <= 126 or ch in (9, 10, 13):
                self.output += chr(ch)
        elif ah == 0x09:
            addr = self.reg_get("DX")
            s = ""
            while True:
                b = self.mem[addr & 0xFFFF]
                if b == 0x24:
                    break
                s += chr(b)
                addr = (addr + 1) & 0xFFFF
                if len(s) > 65536:
                    break
            self.output += s
        elif ah == 0x01:
            if self._in_pos < len(self._in_chars):
                ch = self._in_chars[self._in_pos]
                self._in_pos += 1
            else:
                ch = "\n"
            self.reg_set("AL", ord(ch) & 0xFF)
            self.output += ch
        elif ah == 0x4C:
            self.exit_code = self.reg_get("AL")
            self.halted = True


def assemble_and_run(src, stdin=""):
    asm = Assembler()
    asm.assemble(src)
    vm = VM(asm, stdin)
    out = vm.run()
    return out, vm.exit_code


if __name__ == "__main__":
    demo = """
section .data
msg db "Hello from katoASM!$"
section .text
start:
    mov cx, 5
    mov dx, msg
loop1:
    mov ah, 09h
    int 21h
    dec cx
    jnz loop1
    mov ah, 4Ch
    int 21h
"""
    print(assemble_and_run(demo)[0])
