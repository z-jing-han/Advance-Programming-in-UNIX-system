#!/usr/bin/env python3
"""
run_tests.py — snapshot-style test runner for sdb.

Each test case is a plain-text file under tests/in/<name>.in describing how
to launch sdb and what to type at the "(sdb) " prompt. A matching
tests/ans/<name>.ans file (created via `record`) holds the last output you
confirmed was correct — the expected answer; `check` re-runs the case and
diffs the fresh output against it. Every run (show/check/record) also saves
its raw output to tests/out/<name>.out, so you can inspect or `diff` a
failing case by hand after the fact instead of only seeing it scroll by.
tests/out/ is entirely disposable — it's overwritten on every run.

---------------------------------------------------------------------------
.in file format
---------------------------------------------------------------------------
    # lines starting with '#' are comments
    # blank lines are ignored (use "@blank" to actually send an empty line)

    @args ./hello          # argv passed to sdb, e.g. `./sdb ./hello`.
                            # `@args` with nothing after it launches `./sdb`
                            # with no argument at all. Optional: defaults to
                            # no argument if the line is omitted entirely.
    @setup ln -sf hola hola_link   # optional shell command(s) to run
                                    # (via `sh -c`, cwd = this script's dir)
                                    # before sdb is launched. May repeat.

    si                      # everything else is sent to sdb's stdin,
    load ./hello            # one line per line, exactly as you'd type it
    si
    si
    cont

    @blank                  # sends a literal empty line to stdin
                            # (for EOF / blank-line regression tests)

Once the last command line is consumed, stdin is closed — so a case that
simply ends without a trailing command naturally exercises "EOF while the
target is still running".

---------------------------------------------------------------------------
Usage
---------------------------------------------------------------------------
    ./run_tests.py list                    # what test cases exist, ans recorded?
    ./run_tests.py show   [PATTERN ...]    # just run & print raw output
    ./run_tests.py check  [PATTERN ...]    # run + diff against tests/ans,
                                            # print a PASS/FAIL table
    ./run_tests.py record [PATTERN ...]    # (re)capture tests/ans snapshots

PATTERN supports shell-style globs against the case name (fnmatch), e.g.
`./run_tests.py check 'r*'`. No PATTERN => all discovered cases.

Options:
    -v, --verbose   check: also print a diff for every FAIL/CRASH/TIMEOUT
    --raw           check: disable address masking, diff byte-for-byte
    --timeout SEC   per-test wall-clock limit (default: 5)
    --no-color      disable ANSI colors

---------------------------------------------------------------------------
Why addresses are masked by default
---------------------------------------------------------------------------
PIE binaries (hola, soyorin) get a fresh load address every run, and even
non-PIE ones leak a few ASLR'd pointers (stack/heap/shared-lib addresses)
into `info reg`. A byte-for-byte diff would falsely FAIL those every time
even with a perfectly correct sdb. So by default, any hex literal with 9
or more digits (0x + 9 hex chars) is replaced with the placeholder 0xADDR
before diffing — that threshold comfortably covers real addresses (PIE
bases and this program's `anon` mmap region are 12 hex digits; `info reg`
values are 16) while leaving small, deterministic operands like `0xfec`,
`0x20`, or `0x9685d` untouched, so a genuine wrong-operand bug still shows
up as a mismatch. Known trade-off: `anon`'s fixed 0x700000000000 region
is technically deterministic but still gets masked (it's 12 hex digits);
use --raw if you specifically need to verify that literal address.
The .ans file itself always stores the RAW captured output — masking only
happens at diff time — so `cat tests/ans/<name>.ans` still shows you
exactly what was printed when you recorded it.
"""
import argparse
import fnmatch
import os
import pty
import re
import select
import shlex
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
IN_DIR = SCRIPT_DIR / "tests" / "in"
ANS_DIR = SCRIPT_DIR / "tests" / "ans"
OUT_DIR = SCRIPT_DIR / "tests" / "out"
SDB = SCRIPT_DIR / "sdb"


def rebuild(col: "Color") -> None:
    """`make clean` then rebuild sdb + refresh the demo binaries, mirroring
    the Makefile's `test` target minus its own recursive call into this
    script."""
    for target in (["make", "clean"], ["make", "sdb", "copy_test_case"]):
        print(col.bold(f"==> {' '.join(target)}"))
        proc = subprocess.run(target, cwd=SCRIPT_DIR)
        if proc.returncode != 0:
            print(col.red(f"error: `{' '.join(target)}` failed (exit {proc.returncode})"), file=sys.stderr)
            sys.exit(2)

def cleanup(col: "Color") -> None:
    """`make clean` after the run, so sdb and the copied demo binaries
    don't linger in the working tree once the test(s) are done."""
    print(col.bold("==> make clean"))
    proc = subprocess.run(["make", "clean"], cwd=SCRIPT_DIR)
    if proc.returncode != 0:
        print(col.red(f"warning: `make clean` failed (exit {proc.returncode})"), file=sys.stderr)


ADDR_RE = re.compile(r"0x[0-9a-fA-F]{9,}")


def normalize(text: str) -> str:
    return "\n".join(ADDR_RE.sub("0xADDR", line) for line in text.splitlines())


class Case:
    def __init__(self, path: Path):
        self.name = path.stem
        self.in_path = path
        self.ans_path = ANS_DIR / f"{self.name}.ans"
        self.out_path = OUT_DIR / f"{self.name}.out"
        self.args: list[str] = []
        self.setup: list[str] = []
        self.stdin_lines: list[str] = []
        self._parse()

    def _parse(self):
        args_seen = False
        for raw in self.in_path.read_text().splitlines():
            line = raw.rstrip("\n")
            stripped = line.strip()
            if stripped == "":
                continue
            if stripped.startswith("#"):
                continue
            if stripped == "@args" or stripped.startswith("@args "):
                if args_seen:
                    raise ValueError(f"{self.in_path}: '@args' given more than once")
                rest = stripped[len("@args"):].strip()
                self.args = shlex.split(rest) if rest else []
                args_seen = True
                continue
            if stripped.startswith("@setup "):
                self.setup.append(stripped[len("@setup "):].strip())
                continue
            if stripped == "@blank":
                self.stdin_lines.append("")
                continue
            self.stdin_lines.append(line)

    @property
    def has_ans(self) -> bool:
        return self.ans_path.exists()

    def save_output(self, text: str) -> None:
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        self.out_path.write_text(text)

    def stdin_bytes(self) -> bytes:
        if not self.stdin_lines:
            return b""
        return ("\n".join(self.stdin_lines) + "\n").encode()

    def run(self, timeout: float):
        """Returns (output_text, status) where status is one of:
        'ok', 'timeout', or 'signal:<n>' (process killed by signal n).

        sdb's traced child inherits sdb's stdout, and glibc only
        line-buffers stdout when it's a real terminal — over a plain pipe
        it's fully block-buffered, so short prints from the traced program
        never reach us unless it happens to exit on its own. Routing
        stdout/stderr through a pty instead of a pipe keeps isatty() true
        for the traced program too, so its output shows up the same way it
        would if you ran sdb by hand."""
        if not SDB.exists():
            print(f"error: {SDB} not found — run `make` first.", file=sys.stderr)
            sys.exit(2)
        for setup_cmd in self.setup:
            subprocess.run(setup_cmd, shell=True, cwd=SCRIPT_DIR, check=False)

        master_fd, slave_fd = pty.openpty()
        try:
            proc = subprocess.Popen(
                [str(SDB), *self.args],
                stdin=subprocess.PIPE,
                stdout=slave_fd,
                stderr=slave_fd,
                cwd=SCRIPT_DIR,
            )
        finally:
            os.close(slave_fd)

        try:
            proc.stdin.write(self.stdin_bytes())
            proc.stdin.close()
        except BrokenPipeError:
            pass

        chunks = []
        deadline = time.monotonic() + timeout
        status = "ok"
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                status = "timeout"
                break
            ready, _, _ = select.select([master_fd], [], [], min(remaining, 0.05))
            if ready:
                try:
                    data = os.read(master_fd, 65536)
                except OSError:
                    data = b""
                if data:
                    chunks.append(data)
                    continue
                break  # slave side fully closed: real EOF
            if proc.poll() is not None:
                # sdb exited; grab anything already flushed and stop. The
                # traced child can outlive sdb (e.g. still ptrace-stopped
                # mid-test) and keep the pty open without ever writing
                # more, so we don't wait for the pty itself to EOF.
                try:
                    ready, _, _ = select.select([master_fd], [], [], 0.05)
                    if ready:
                        data = os.read(master_fd, 65536)
                        if data:
                            chunks.append(data)
                except OSError:
                    pass
                break
        os.close(master_fd)

        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        # a pty's output side does the usual tty NL->CRLF translation
        # (same as a real terminal); normalize it away so captures don't
        # pick up a stray \r on every line.
        text = b"".join(chunks).decode("utf-8", "replace").replace("\r\n", "\n")
        if status == "timeout":
            return text, "timeout"
        if proc.returncode is not None and proc.returncode < 0:
            return text, f"signal:{-proc.returncode}"
        return text, "ok"


def discover(patterns: list[str]) -> list[Case]:
    all_cases = [Case(p) for p in sorted(IN_DIR.glob("*.in"))]
    if not patterns:
        return all_cases
    out, seen = [], set()
    for pat in patterns:
        for c in all_cases:
            if c.name not in seen and fnmatch.fnmatch(c.name, pat):
                out.append(c)
                seen.add(c.name)
    return out


class Color:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code, text):
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def green(self, t): return self._wrap(32, t)
    def red(self, t): return self._wrap(31, t)
    def yellow(self, t): return self._wrap(33, t)
    def bold(self, t): return self._wrap(1, t)


def status_label(status: str) -> str:
    if status == "ok":
        return "ok"
    if status == "timeout":
        return "TIMEOUT"
    if status.startswith("signal:"):
        n = int(status.split(":")[1])
        names = {4: "SIGILL", 6: "SIGABRT", 8: "SIGFPE", 11: "SIGSEGV", 9: "SIGKILL"}
        return f"CRASH({names.get(n, f'signal {n}')})"
    return status


def cmd_list(args, col: Color):
    cases = discover(args.pattern)
    if not cases:
        print("no test cases found under", IN_DIR)
        return 0
    for c in cases:
        ans = col.green("ans recorded") if c.has_ans else col.yellow("no ans yet")
        argv = " ".join(c.args) if c.args else "(none)"
        print(f"  {c.name:<32} args={argv:<14} {ans}")
    return 0


def cmd_show(args, col: Color):
    cases = discover(args.pattern)
    if not cases:
        print("no matching test cases")
        return 1
    for c in cases:
        text, status = c.run(args.timeout)
        c.save_output(text)
        argv = " ".join([str(SDB), *c.args]) if c.args else str(SDB)
        print(col.bold(f"===== {c.name}  ({argv})  [{status_label(status)}] ====="))
        print(text, end="" if text.endswith("\n") else "\n")
        print()
    return 0


def cmd_check(args, col: Color):
    cases = discover(args.pattern)
    if not cases:
        print("no matching test cases")
        return 1
    results = []  # (case, label, ok_for_exit_code)
    for c in cases:
        text, status = c.run(args.timeout)
        c.save_output(text)
        if status != "ok":
            results.append((c, status_label(status), False, text, None))
            continue
        if not c.has_ans:
            results.append((c, "NO ANS", True, text, None))
            continue
        ans_raw = c.ans_path.read_text()
        if args.raw:
            match = text == ans_raw
        else:
            match = normalize(text) == normalize(ans_raw)
        results.append((c, "PASS" if match else "FAIL", match, text, ans_raw))

    name_w = max(len(c.name) for c, *_ in results)
    for c, label, ok, text, ans_raw in results:
        if label == "PASS":
            tag = col.green("PASS")
        elif label == "NO ANS":
            tag = col.yellow("NO ANS")
        else:
            tag = col.red(label)
        print(f"  [{tag:<9}] {c.name:<{name_w}}")

    n_pass = sum(1 for r in results if r[1] == "PASS")
    n_noans = sum(1 for r in results if r[1] == "NO ANS")
    n_fail = len(results) - n_pass - n_noans
    print()
    summary = f"{n_pass} passed, {n_fail} failed, {n_noans} no ans, {len(results)} total"
    print(col.bold(summary))

    if args.verbose:
        import difflib
        for c, label, ok, text, ans_raw in results:
            if label in ("PASS", "NO ANS"):
                continue
            print()
            print(col.bold(f"----- diff: {c.name} -----"))
            if ans_raw is None:
                print(text)
                continue
            a = (ans_raw if args.raw else normalize(ans_raw)).splitlines()
            b = (text if args.raw else normalize(text)).splitlines()
            diff = difflib.unified_diff(a, b, lineterm="", fromfile="ans", tofile="out")
            for line in diff:
                if line.startswith("+"):
                    print(col.green(line))
                elif line.startswith("-"):
                    print(col.red(line))
                else:
                    print(line)

    any_bad = any(r[1] not in ("PASS", "NO ANS") for r in results)
    return 1 if any_bad else 0


def cmd_record(args, col: Color):
    cases = discover(args.pattern)
    if not cases:
        print("no matching test cases")
        return 1
    import difflib
    for c in cases:
        text, status = c.run(args.timeout)
        c.save_output(text)
        if status != "ok":
            print(col.red(f"skip {c.name}: {status_label(status)} — not recording a crash as the expected answer"))
            continue
        if c.has_ans:
            old = c.ans_path.read_text()
            if old != text:
                print(col.bold(f"----- updating {c.name} -----"))
                diff = difflib.unified_diff(
                    old.splitlines(), text.splitlines(), lineterm="",
                    fromfile="old ans", tofile="new ans",
                )
                for line in diff:
                    if line.startswith("+"):
                        print(col.green(line))
                    elif line.startswith("-"):
                        print(col.red(line))
                    else:
                        print(line)
            else:
                print(f"{c.name}: unchanged")
                continue
        else:
            print(col.green(f"{c.name}: recorded new ans"))
        ANS_DIR.mkdir(parents=True, exist_ok=True)
        c.ans_path.write_text(text)
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--timeout", type=float, default=5.0, help="per-test wall-clock limit in seconds (default: 5)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    sub = p.add_subparsers(dest="subcommand")

    sp_list = sub.add_parser("list", help="list discovered test cases")
    sp_list.add_argument("pattern", nargs="*")

    sp_show = sub.add_parser("show", help="run test(s) and print raw output")
    sp_show.add_argument("pattern", nargs="*")

    sp_check = sub.add_parser("check", help="run test(s) and diff against tests/ans")
    sp_check.add_argument("pattern", nargs="*")
    sp_check.add_argument("-v", "--verbose", action="store_true")
    sp_check.add_argument("--raw", action="store_true")

    sp_record = sub.add_parser("record", help="(re)capture tests/ans snapshot(s)")
    sp_record.add_argument("pattern", nargs="*")

    args = p.parse_args()
    col = Color(enabled=not args.no_color and sys.stdout.isatty())

    if args.subcommand is None:
        args.subcommand = "check"
        args.pattern = []
        args.verbose = False
        args.raw = False

    dispatch = {"list": cmd_list, "show": cmd_show, "check": cmd_check, "record": cmd_record}

    if args.subcommand == "list":
        return dispatch[args.subcommand](args, col)

    rebuild(col)
    try:
        return dispatch[args.subcommand](args, col)
    finally:
        cleanup(col)


if __name__ == "__main__":
    sys.exit(main())
