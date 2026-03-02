
#!/data/data/com.termux/files/usr/bin/python

import asyncio, importlib.util, os, re, sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Iterable, List, Optional, Dict, Any

def _b():
    req = {"rich": "rich", "typer": "typer"}
    m = [v for k, v in req.items() if importlib.util.find_spec(k) is None]
    if m:
        a = [sys.executable, "-m", "pip", "install", "--user"] + m
        if "termux" in sys.executable.lower(): a += ["--break-system-packages"]
        import subprocess
        try:
            subprocess.check_call(a, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except: sys.exit(1)

_b()

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

class S(Enum): L=auto(); M=auto(); H=auto(); C=auto()

@dataclass(frozen=True)
class Sig:
    id: str; pat: re.Pattern; desc: str; rem: str; sev: S=S.M; meta: Dict[str, Any]=field(default_factory=dict)

class Diag:
    def __init__(self, t: str, m: List[Sig], r: str): self.t = t; self.m = m; self.ts = datetime.now(); self.r = r

class Plg(ABC):
    @abstractmethod
    def idf(self, b: str) -> float: ... 
    @abstractmethod
    def scn(self, b: str) -> Iterable[Sig]: ...

_plgs: List[Plg] = []

class Bsc(Plg):
    def __init__(self, n: str, tr: List[str], rl: List[Sig]):
        self.n = n; self.tr = [t.lower() for t in tr]; self.rl = rl; _plgs.append(self)
    def idf(self, b: str) -> float:
        s = b.lower()
        score = sum(s.count(t) for t in self.tr)
        return min(score / 4.0, 1.0)
    def scn(self, b: str) -> Iterable[Sig]:
        ls = b.splitlines()
        for r in self.rl:
            for m in r.pat.finditer(b):
                p = m.start(); ln = b[:p].count('\n') + 1; cl = ls[max(0, ln-2):ln+2]
                yield Sig(r.id, r.pat, f"{r.desc} (L{ln})", r.rem, r.sev, {"mt": m.group(0), "ctx": "\n".join(cl).strip()})

class Krn:
    def __init__(self): self._r()
    def _r(self):
        Bsc("nmap", ["nmap", "scan", "report", "latency", "port"], [
            Sig("N01", re.compile(r"(raw socket|permission|privileged|root|PF_PACKET|socket:)", re.I), "Privilege Error", "Use -sT -Pn or sudo/tsu", S.C),
            Sig("N02", re.compile(r"(interface.*not|failed to open device|no such device)", re.I), "Interface Error", "Check 'ifconfig' and use -e <interface>", S.H),
            Sig("N03", re.compile(r"(all ports.*filtered|host.*down|0 hosts up)", re.I), "Firewall/Host Down", "Try -Pn to skip discovery", S.H),
            Sig("N04", re.compile(r"(too many.*timeout|dropping.*probes)", re.I), "Rate Limiting", "Network slow; use -T3 or --scan-delay", S.M),
        ])
        
        Bsc("john", ["john", "password", "hash", "wordlist", "loaded"], [
            Sig("J01", re.compile(r"(No password hashes loaded|Loaded 0 password hashes)", re.I), "No Hashes Found", "Did you convert the file first? (e.g., zip2john)", S.C),
            Sig("J02", re.compile(r"(unknown cipher|unsupported format|invalid utf-8)", re.I), "Format Error", "Use the proper '2john' converter for this file type", S.H),
            Sig("J03", re.compile(r"(cannot open.*wordlist|no such file)", re.I), "File Access Error", "Check path to your wordlist/rockyou.txt", S.H),
            Sig("J04", re.compile(r"Nothing left to do", re.I), "Session Finished", "Hash already cracked or list exhausted. Check 'john --show'", S.M),
        ])

    async def ana(self, s: str) -> List[Diag]:
        r = []
        for g in _plgs:
            if g.idf(s) > 0.05:
                r.append(Diag(g.n, list(g.scn(s)), s))
        return r

class UI:
    def __init__(self): self.c = Console()
    def dsp(self, rs: List[Diag]):
        if not rs:
            self.c.print(Panel("[bold yellow]NO TOOL OUTPUT RECOGNIZED[/]", border_style="red"))
            return
        for d in rs:
            if not d.m:
                self.c.print(Panel(f"[yellow]Found {d.t.upper()} output, but no specific errors matched.[/]", title="ANALYSIS COMPLETE"))
                continue
            tb = Table(expand=True, border_style="blue")
            tb.add_column("ID", style="dim"); tb.add_column("Severity"); tb.add_column("Description"); tb.add_column("Recommendation", style="bold green")
            for m in sorted(d.m, key=lambda x: x.sev.value, reverse=True):
                color = {S.C: "bold red", S.H: "red", S.M: "yellow", S.L: "blue"}[m.sev]
                tb.add_row(m.id, f"[{color}]{m.sev.name}[/]", m.desc, m.rem)
            self.c.print(Panel(tb, title=f"[bold cyan]{d.t.upper()} CRITIQUE[/]", border_style="bright_blue"))

cli = typer.Typer()

@cli.command()
def scan(file: Optional[Path] = typer.Option(None, "--file", "-f")):
    u = UI()
    try:
        if file and file.exists():
            c = file.read_text(errors="replace")
        elif not sys.stdin.isatty():
            c = sys.stdin.read()
        else:
            u.c.print("[bold cyan]ENTER/PASTE LOG BELOW[/] (Press [bold yellow]CTRL+D[/] on a new line when done)\n")
            lines = []
            while True:
                try:
                    line = input()
                    lines.append(line)
                except EOFError:
                    break
            c = "\n".join(lines)
        
        if not c.strip(): return
        k = Krn(); rs = asyncio.run(k.ana(c)); u.dsp(rs)
        if rs: Path("kcritic.log").open("a").write(f"{datetime.now().isoformat()}|{','.join(d.t for d in rs)}\n")
    except Exception as e: u.c.print(f"[red]Error:[/red] {e}")

if __name__ == "__main__":
    cli()

