"""katoC — katoDoS 专属类 C 解释器

一个迷你 C 子集的解释器（递归下降解析 + 树遍历执行）。
特性：
  - int 变量声明与赋值： int a;  int a = 5;  int a, b = 3;
  - 算术 / 比较 / 逻辑： + - * / %   == != < > <= >=   && || !
  - 语句： if / else、while、for、块 { }
  - 内置函数： print(...) 打印并换行（支持多参数与字符串字面量）
              input()   从输入流读取一个整数
              readline()读取一行字符串
              sqrt(x) abs(x)
  - 注释： // 行注释    /* 块注释 */

示例 (hello.c)：
    int n = 1;
    for (int i = 1; i <= 5; i = i + 1) {
        n = n * i;
    }
    print("5! =", n);
"""

import math
import re


class CError(Exception):
    def __init__(self, msg, line=-1):
        self.line = line
        super().__init__(("katoC 错误 (行 %d): %s" % (line, msg)) if line >= 0 else ("katoC 错误: " + msg))


# ---------------- 词法 ----------------
TOKEN_RE = re.compile(r"""
    \s+                         |   # 空白
    //[^\n]*                    |   # 行注释
    /\*[\s\S]*?\*/              |   # 块注释
    (?P<NUM>\d+(\.\d+)?)        |
    "(?P<STR>(?:\\.|[^"\\])*)"  |
    (?P<ID>[A-Za-z_][A-Za-z0-9_]*) |
    (?P<OP><=|>=|==|!=|&&|\|\||[+\-*/%<>=!&|();{},])
""", re.VERBOSE)


def _unescape(s):
    out = []
    i = 0
    mapping = {'n': '\n', 't': '\t', 'r': '\r', '"': '"', '\\': '\\', "'": "'"}
    while i < len(s):
        c = s[i]
        if c == '\\' and i + 1 < len(s):
            n = s[i + 1]
            if n in mapping:
                out.append(mapping[n])
                i += 2
                continue
        out.append(c)
        i += 1
    return "".join(out)


def tokenize(src):
    tokens = []
    pos = 0
    line = 1
    while pos < len(src):
        m = TOKEN_RE.match(src, pos)
        if not m:
            raise CError("无法识别的字符: %r (附近行 %d)" % (src[pos], line), line)
        pos = m.end()
        txt = m.group(0)
        if txt.startswith("//") or txt.startswith("/*") or txt.isspace():
            line += txt.count("\n")
            continue
        if m.group("NUM"):
            val = float(txt) if "." in txt else int(txt)
            tokens.append(("NUM", val, line))
        elif m.group("STR") is not None:
            tokens.append(("STR", _unescape(m.group("STR")), line))
        elif m.group("ID"):
            tokens.append(("ID", txt, line))
        else:
            tokens.append(("OP", txt, line))
    tokens.append(("EOF", "", line))
    return tokens


# ---------------- 解析 ----------------
class Parser:
    def __init__(self, tokens):
        self.toks = tokens
        self.i = 0

    def peek(self):
        return self.toks[self.i]

    def next(self):
        t = self.toks[self.i]
        self.i += 1
        return t

    def expect(self, kind, val=None):
        t = self.next()
        if t[0] != kind or (val is not None and t[1] != val):
            raise CError("期望 %s%s，却得到 %r" % (kind, ("" if val is None else " '" + val + "'"), t[1]), t[2])
        return t

    def parse_program(self):
        stmts = []
        while self.peek()[0] != "EOF":
            stmts.append(self.parse_stmt())
        return stmts

    def parse_stmt(self):
        t = self.peek()
        if t[0] == "OP" and t[1] == "{":
            return self.parse_block()
        if t[0] == "ID" and t[1] == "if":
            return self.parse_if()
        if t[0] == "ID" and t[1] == "while":
            return self.parse_while()
        if t[0] == "ID" and t[1] == "for":
            return self.parse_for()
        if t[0] == "ID" and t[1] == "print":
            return self.parse_print()
        if t[0] == "ID" and t[1] in ("int",):
            return self.parse_decl()
        if t[0] == "ID":
            return self.parse_assign()
        if t[0] == "OP" and t[1] == ";":
            self.next()
            return ("EMPTY",)
        raise CError("无法解析的语句: %r" % (t[1],), t[2])

    def parse_block(self):
        self.expect("OP", "{")
        stmts = []
        while not (self.peek()[0] == "OP" and self.peek()[1] == "}"):
            if self.peek()[0] == "EOF":
                raise CError("缺少 }", self.peek()[2])
            stmts.append(self.parse_stmt())
        self.expect("OP", "}")
        return ("BLOCK", stmts)

    def parse_if(self):
        self.expect("ID", "if")
        self.expect("OP", "(")
        cond = self.parse_expr()
        self.expect("OP", ")")
        then = self.parse_stmt()
        els = None
        if self.peek()[0] == "ID" and self.peek()[1] == "else":
            self.next()
            els = self.parse_stmt()
        return ("IF", cond, then, els)

    def parse_while(self):
        self.expect("ID", "while")
        self.expect("OP", "(")
        cond = self.parse_expr()
        self.expect("OP", ")")
        body = self.parse_stmt()
        return ("WHILE", cond, body)

    def parse_for(self):
        self.expect("ID", "for")
        self.expect("OP", "(")
        init = self.parse_stmt()
        cond = self.parse_expr()
        self.expect("OP", ";")
        post = self.parse_post()
        self.expect("OP", ")")
        body = self.parse_stmt()
        return ("FOR", init, cond, post, body)

    def parse_post(self):
        # for 的第三段：允许赋值或表达式
        t = self.peek()
        if t[0] == "ID" and self.i + 1 < len(self.toks) and \
                self.toks[self.i + 1][0] == "OP" and self.toks[self.i + 1][1] == "=":
            name = self.next()[1]
            self.next()  # '='
            val = self.parse_expr()
            return ("ASSIGN", name, val)
        return self.parse_expr()

    def parse_print(self):
        self.expect("ID", "print")
        self.expect("OP", "(")
        args = []
        if not (self.peek()[0] == "OP" and self.peek()[1] == ")"):
            args.append(self.parse_expr())
            while self.peek()[0] == "OP" and self.peek()[1] == ",":
                self.next()
                args.append(self.parse_expr())
        self.expect("OP", ")")
        self.expect("OP", ";")
        return ("PRINT", args)

    def parse_decl(self):
        self.expect("ID", "int")
        decls = []
        while True:
            name = self.expect("ID")[1]
            init = None
            if self.peek()[0] == "OP" and self.peek()[1] == "=":
                self.next()
                init = self.parse_expr()
            decls.append((name, init))
            if self.peek()[0] == "OP" and self.peek()[1] == ",":
                self.next()
                continue
            break
        self.expect("OP", ";")
        return ("DECL", decls)

    def parse_assign(self):
        name = self.expect("ID")[1]
        self.expect("OP", "=")
        val = self.parse_expr()
        self.expect("OP", ";")
        return ("ASSIGN", name, val)

    def parse_expr_stmt_no_semi(self):
        # for 的第三段：表达式（不带分号）
        return self.parse_post()

    # ---- 表达式（优先级）----
    def parse_expr(self):
        return self.parse_or()

    def parse_or(self):
        left = self.parse_and()
        while self.peek()[0] == "OP" and self.peek()[1] == "||":
            self.next()
            right = self.parse_and()
            left = ("OR", left, right)
        return left

    def parse_and(self):
        left = self.parse_eq()
        while self.peek()[0] == "OP" and self.peek()[1] == "&&":
            self.next()
            right = self.parse_eq()
            left = ("AND", left, right)
        return left

    def parse_eq(self):
        left = self.parse_cmp()
        while self.peek()[0] == "OP" and self.peek()[1] in ("==", "!="):
            op = self.next()[1]
            right = self.parse_cmp()
            left = ("EQ" if op == "==" else "NE", left, right)
        return left

    def parse_cmp(self):
        left = self.parse_add()
        while self.peek()[0] == "OP" and self.peek()[1] in ("<", ">", "<=", ">="):
            op = self.next()[1]
            right = self.parse_add()
            left = (op, left, right)
        return left

    def parse_add(self):
        left = self.parse_mul()
        while self.peek()[0] == "OP" and self.peek()[1] in ("+", "-"):
            op = self.next()[1]
            right = self.parse_mul()
            left = ("ADD" if op == "+" else "SUB", left, right)
        return left

    def parse_mul(self):
        left = self.parse_unary()
        while self.peek()[0] == "OP" and self.peek()[1] in ("*", "/", "%"):
            op = self.next()[1]
            right = self.parse_unary()
            name = {"*": "MUL", "/": "DIV", "%": "MOD"}[op]
            left = (name, left, right)
        return left

    def parse_unary(self):
        t = self.peek()
        if t[0] == "OP" and t[1] in ("-", "!", "+"):
            self.next()
            operand = self.parse_unary()
            return ("NEG" if t[1] == "-" else "NOT", operand)
        return self.parse_primary()

    def parse_primary(self):
        t = self.next()
        if t[0] == "NUM":
            return ("NUM", t[1])
        if t[0] == "STR":
            return ("STR", t[1])
        if t[0] == "ID":
            if self.peek()[0] == "OP" and self.peek()[1] == "(":
                self.next()
                args = []
                if not (self.peek()[0] == "OP" and self.peek()[1] == ")"):
                    args.append(self.parse_expr())
                    while self.peek()[0] == "OP" and self.peek()[1] == ",":
                        self.next()
                        args.append(self.parse_expr())
                self.expect("OP", ")")
                return ("CALL", t[1], args)
            return ("VAR", t[1])
        if t[0] == "OP" and t[1] == "(":
            e = self.parse_expr()
            self.expect("OP", ")")
            return e
        raise CError("无法解析的表达式: %r" % (t[1],), t[2])


# ---------------- 执行 ----------------
class Interp:
    def __init__(self, stdin=""):
        self.env = {}
        self.out = []
        self._in = list(stdin.split("\n"))
        self._in_pos = 0

    def _next_input(self):
        while self._in_pos < len(self._in) and self._in[self._in_pos].strip() == "":
            self._in_pos += 1
        if self._in_pos < len(self._in):
            v = self._in[self._in_pos]
            self._in_pos += 1
            return v
        return ""

    def run(self, stmts):
        for s in stmts:
            self.exec_stmt(s)

    def exec_stmt(self, s):
        kind = s[0]
        if kind == "EMPTY":
            return
        if kind == "BLOCK":
            for st in s[1]:
                self.exec_stmt(st)
            return
        if kind == "DECL":
            for name, init in s[1]:
                self.env[name] = self.eval(init) if init is not None else 0
            return
        if kind == "ASSIGN":
            self.env[s[1]] = self.eval(s[2])
            return
        if kind == "IF":
            if self.eval(s[1]):
                self.exec_stmt(s[2])
            elif s[3] is not None:
                self.exec_stmt(s[3])
            return
        if kind == "WHILE":
            while self.eval(s[1]):
                self.exec_stmt(s[2])
            return
        if kind == "FOR":
            self.exec_stmt(s[1])
            while self.eval(s[2]):
                self.exec_stmt(s[4])
                self.exec_stmt(s[3])
            return
        if kind == "PRINT":
            parts = []
            for a in s[1]:
                v = self.eval(a)
                parts.append(str(v))
            self.out.append(" ".join(parts))
            return
        raise CError("未知语句: " + kind)

    def eval(self, node):
        kind = node[0]
        if kind == "NUM":
            return node[1]
        if kind == "STR":
            return node[1]
        if kind == "VAR":
            if node[1] not in self.env:
                raise CError("未定义变量: " + node[1])
            return self.env[node[1]]
        if kind == "CALL":
            return self.call(node[1], [self.eval(a) for a in node[2]])
        if kind == "NEG":
            return -self.eval(node[1])
        if kind == "NOT":
            return 0 if self.eval(node[1]) else 1
        if kind == "ADD":
            return self.eval(node[1]) + self.eval(node[2])
        if kind == "SUB":
            return self.eval(node[1]) - self.eval(node[2])
        if kind == "MUL":
            return self.eval(node[1]) * self.eval(node[2])
        if kind == "DIV":
            b = self.eval(node[2])
            a = self.eval(node[1])
            return a // b if isinstance(a, int) and isinstance(b, int) else a / b
        if kind == "MOD":
            return self.eval(node[1]) % self.eval(node[2])
        if kind in ("<", ">", "<=", ">="):
            a, b = self.eval(node[1]), self.eval(node[2])
            return {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[kind]
        if kind == "EQ":
            return 1 if self.eval(node[1]) == self.eval(node[2]) else 0
        if kind == "NE":
            return 1 if self.eval(node[1]) != self.eval(node[2]) else 0
        if kind == "AND":
            return 1 if (self.eval(node[1]) and self.eval(node[2])) else 0
        if kind == "OR":
            return 1 if (self.eval(node[1]) or self.eval(node[2])) else 0
        raise CError("未知表达式节点: " + kind)

    def call(self, name, args):
        if name == "input":
            v = self._next_input().strip()
            try:
                return int(v)
            except ValueError:
                try:
                    return float(v)
                except ValueError:
                    return 0
        if name == "readline":
            return self._next_input()
        if name == "sqrt":
            return math.sqrt(args[0])
        if name == "abs":
            return abs(args[0])
        raise CError("未知函数: " + name)


def run_c(src, stdin=""):
    toks = tokenize(src)
    ast = Parser(toks).parse_program()
    interp = Interp(stdin)
    interp.run(ast)
    return "\n".join(interp.out)


if __name__ == "__main__":
    demo = """
    int n = 1;
    for (int i = 1; i <= 5; i = i + 1) {
        n = n * i;
    }
    print("5! =", n);
    int x = input();
    print("你输入的是", x, "它的平方是", x * x);
    """
    print(run_c(demo, "7"))
