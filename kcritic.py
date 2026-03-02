#!/data/data/com.termux/files/usr/bin/python

import sys
import subprocess
import importlib.util

def bootstrap():
    pkgs = ["rich", "pyyaml", "typer"]
    missing = [p for p in pkgs if importlib.util.find_spec("yaml" if p == "pyyaml" else p) is None]
    if not missing:
        return
    print("\nInstalling:", ", ".join(missing))
    cmd = [sys.executable, "-m", "pip", "install", "--user", "--no-cache-dir"] + missing
    if "termux" in sys.executable.lower():
        cmd.insert(-1, "--break-system-packages")
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Done. Run again.")
        sys.exit(0)
    except Exception as e:
        print(f"Install failed: {e}")
        print("Try manually:")
        print("  pip install --user " + " ".join(missing))
        sys.exit(1)

bootstrap()

from dataclasses import dataclass
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Tuple

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme

try:
    import yaml
except ImportError:
    yaml = None

app = typer.Typer(add_completion=False, invoke_without_command=True)

console = Console(theme=Theme({
    "title": "bold cyan",
    "high": "bold red",
    "med": "bold yellow",
    "low": "bold green",
    "dim": "dim white",
}))

@dataclass(frozen=True)
class Rule:
    pattern: str
    desc: str
    fix: str
    note: str = ""
    severity: str = "medium"

    @property
    def compiled(self) -> re.Pattern:
        return re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)

DEFAULT_RULES: Dict[str, List[Rule]] = {
    "nmap": [
        Rule(
            r"(permission denied|PF_PACKET|socket.*failed|raw sockets|needs root)",
            "Raw socket / privilege error",
            "Try -sT -Pn or --unprivileged",
            "Termux can't do raw sockets",
            "high"
        ),
        Rule(
            r"(Failed to open device|interface not found|no interfaces)",
            "Interface access issue",
            "Use -e wlan0 or IP directly",
            "Proot hides interfaces",
            "medium"
        ),
    ],
    "sqlmap": [
        Rule(
            r"(403|401|blocked|WAF|IPS|Cloudflare|Akamai|ModSecurity)",
            "WAF/firewall block",
            "--random-agent --delay=3 --tamper=...",
            "Try more evasion",
            "high"
        ),
    ],
    "metasploit": [
        Rule(
            r"(database not connected|postgresql|msfdb init|pg_ctl)",
            "Metasploit DB not running",
            "msfdb init  or  service postgresql start",
            "Common in Termux",
            "high"
        ),
    ],
}

class Critic:
    def __init__(self, extra_rules: Optional[Path] = None):
        self.rules = DEFAULT_RULES.copy()
        if extra_rules and yaml:
            try:
                with extra_rules.open() as f:
                    data = yaml.safe_load(f)
                for t, rs in (data or {}).items():
                    t = t.lower()
                    self.rules.setdefault(t, []).extend(Rule(**r) for r in rs)
            except Exception as e:
                print(f"Extra rules failed: {e}")

    def detect_tool(self, text: str) -> Optional[str]:
        if not text.strip():
            return None
        head = " ".join(text.lower().splitlines()[:12])
        scores = {t: head.count(t)*3 for t in self.rules if t in head}
        return max(scores, key=scores.get) if scores else None

    def analyze(self, text: str) -> Tuple[Optional[str], List[Rule]]:
        tool = self.detect_tool(text)
        if not tool:
            return None, []
        return tool, [r for r in self.rules.get(tool, []) if r.compiled.search(text)]

def make_report(tool: str, issues: List[Rule], json_out: bool = False):
    if json_out:
        console.print_json(data={
            "tool": tool,
            "issues": [{"desc": i.desc, "fix": i.fix, "severity": i.severity} for i in issues]
        })
        return
    table = Table(title=f"[title]{tool.upper() or 'Unknown'}[/title]", border_style="blue")
    table.add_column("Sev", style="bold", width=6)
    table.add_column("Issue")
    table.add_column("Fix", style="green")
    for i in issues:
        s = i.severity
        sev_style = "high" if s == "high" else "med" if s == "medium" else "low"
        table.add_row(f"[{sev_style}]{s.upper()}[/]", i.desc, i.fix)
    console.print(Panel(table, expand=False))

def run_analysis(
    file: Optional[Path] = None,
    rules: Optional[Path] = None,
    json: bool = False,
    verbose: bool = False,
):
    critic = Critic(rules)
    if verbose:
        print("[dim]Reading input...[/dim]")
    if file:
        text = file.read_text(errors="replace")
    else:
        if sys.stdin.isatty():
            console.print("[yellow]Paste output → Ctrl+D (or Ctrl+Z Enter)[/yellow]")
        text = sys.stdin.read()
    tool, issues = critic.analyze(text)
    if not issues:
        console.print("[green]No issues found[/green]")
    else:
        make_report(tool or "unknown", issues, json)
    if issues:
        log_line = f"{datetime.now()} | {tool or '?'} | {len(issues)}\n"
        log_path = Path("kcritic.log")
        with log_path.open("a", encoding="utf-8") as f:
            f.write(log_line)

@app.callback()
def main(
    ctx: typer.Context,
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Read from file"),
    rules: Optional[Path] = typer.Option(None, "--rules", help="Extra YAML rules"),
    json: bool = typer.Option(False, "--json", help="JSON output"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose mode"),
):
    if ctx.invoked_subcommand is None:
        run_analysis(file, rules, json, verbose)

if __name__ == "__main__":
    app()
