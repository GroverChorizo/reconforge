"""
Tool detection + install-plan generator.

Used by the wizard's "Tool Detect" screen and the CLI's
``reconforge tools status`` command. Pure logic — no subprocess
execution; the wizard owns running install commands.

Each tool entry knows:
  * binary name
  * how to ask the binary for its version (--version / -V / ...)
  * preferred install backend (apt / go / pip) and the exact command

A ``scan()`` call returns a list[ToolStatus] suitable for rendering in
the wizard table; ``install_plan()`` returns the shell commands an
operator (or the wizard) would run to install everything missing.
"""
from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ── catalog ──────────────────────────────────────────────────────
@dataclass
class ToolEntry:
    name: str
    binary: str
    version_arg: str = "--version"
    apt: Optional[str] = None     # apt package name
    go_install: Optional[str] = None
    pip: Optional[str] = None
    notes: str = ""
    category: str = "other"       # subdomain | dns_http | screenshot | vuln | fuzz | api | graphql | cloud | js | other

    def install_cmd(self) -> Optional[List[str]]:
        if self.apt:
            return ["sudo", "apt-get", "install", "-y", self.apt]
        if self.go_install:
            return ["go", "install", "-v", self.go_install]
        if self.pip:
            return ["pip", "install", "--user", self.pip]
        return None

    def install_method(self) -> str:
        if self.apt: return "apt"
        if self.go_install: return "go"
        if self.pip: return "pip"
        return "manual"


CATALOG: Dict[str, ToolEntry] = {
    # Subdomain enumeration
    "subfinder":    ToolEntry("Subfinder",   "subfinder", "-version",
                              go_install="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                              category="subdomain"),
    "amass":        ToolEntry("Amass",       "amass",     "-version",
                              go_install="github.com/owasp-amass/amass/v4/...@master",
                              apt="amass", category="subdomain"),
    "assetfinder":  ToolEntry("Assetfinder", "assetfinder",
                              go_install="github.com/tomnomnom/assetfinder@latest",
                              category="subdomain"),
    "findomain":    ToolEntry("Findomain",   "findomain", "--version",
                              apt="findomain", category="subdomain"),
    "sublist3r":    ToolEntry("Sublist3r",   "sublist3r", apt="sublist3r",
                              category="subdomain"),
    # DNS / HTTP
    "dnsx":         ToolEntry("DNSx",        "dnsx",      "-version",
                              go_install="github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
                              category="dns_http"),
    "httpx":        ToolEntry("HTTPx",       "httpx",     "-version",
                              go_install="github.com/projectdiscovery/httpx/cmd/httpx@latest",
                              category="dns_http"),
    "puredns":      ToolEntry("Puredns",     "puredns",
                              go_install="github.com/d3mondev/puredns/v2@latest",
                              category="dns_http"),
    # Screenshots
    "gowitness":    ToolEntry("Gowitness",   "gowitness",
                              go_install="github.com/sensepost/gowitness@latest",
                              category="screenshot"),
    # Vuln scan
    "nuclei":       ToolEntry("Nuclei",      "nuclei",    "-version",
                              go_install="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                              category="vuln"),
    "nikto":        ToolEntry("Nikto",       "nikto",     "-Version", apt="nikto",
                              category="vuln"),
    # WAF / CDN
    "wafw00f":      ToolEntry("WafW00f",     "wafw00f",   "--version", apt="wafw00f",
                              category="dns_http"),
    # Crawl / fuzz
    "ffuf":         ToolEntry("ffuf",        "ffuf",      "-V",
                              go_install="github.com/ffuf/ffuf/v2@latest",
                              category="fuzz"),
    "katana":       ToolEntry("Katana",      "katana",    "-version",
                              go_install="github.com/projectdiscovery/katana/cmd/katana@latest",
                              category="fuzz"),
    "feroxbuster":  ToolEntry("Feroxbuster", "feroxbuster", "--version", apt="feroxbuster",
                              category="fuzz"),
    "x8":           ToolEntry("x8",          "x8",        "--version",
                              notes="No package manager; cargo install x8",
                              category="fuzz"),
    # API / Swagger
    "kiterunner":   ToolEntry("Kiterunner",  "kr",
                              go_install="github.com/assetnote/kiterunner/cmd/kr@latest",
                              category="api"),
    # GraphQL
    "graphw00f":    ToolEntry("graphw00f",   "graphw00f", pip="graphw00f",
                              category="graphql"),
    "clairvoyance": ToolEntry("clairvoyance","clairvoyance", pip="clairvoyance",
                              category="graphql"),
    "inql":         ToolEntry("InQL",        "inql",      pip="inql-scanner",
                              category="graphql"),
    # Cloud
    "s3scanner":    ToolEntry("s3scanner",   "s3scanner",
                              go_install="github.com/sa7mon/s3scanner@latest",
                              category="cloud"),
    "cdncheck":     ToolEntry("CDNcheck",    "cdncheck",
                              go_install="github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
                              category="cloud"),
    # JS analysis
    "jsluice":      ToolEntry("JSluice",     "jsluice",
                              go_install="github.com/BishopFox/jsluice/cmd/jsluice@latest",
                              category="js"),
    "trufflehog":   ToolEntry("TruffleHog",  "trufflehog",
                              go_install="github.com/trufflesecurity/trufflehog/v3@latest",
                              category="js"),
}


# ── status ────────────────────────────────────────────────────────
@dataclass
class ToolStatus:
    name: str
    binary: str
    installed: bool
    path: Optional[str] = None
    version: Optional[str] = None
    install_method: str = "manual"
    install_cmd: Optional[List[str]] = None
    notes: str = ""
    category: str = "other"


def scan(catalog: Optional[Dict[str, ToolEntry]] = None,
         *, version_probe: bool = False) -> List[ToolStatus]:
    """Scan PATH for every catalog tool. ``version_probe`` optionally
    subprocesses each found binary to capture its version (slow)."""
    cat = catalog if catalog is not None else CATALOG
    out: List[ToolStatus] = []
    for key, entry in cat.items():
        path = shutil.which(entry.binary)
        ver: Optional[str] = None
        if path and version_probe and entry.version_arg:
            ver = _probe_version(path, entry.version_arg)
        out.append(ToolStatus(
            name=entry.name, binary=entry.binary,
            installed=bool(path), path=path, version=ver,
            install_method=entry.install_method(),
            install_cmd=entry.install_cmd(),
            notes=entry.notes, category=entry.category,
        ))
    return out


def install_plan(catalog: Optional[Dict[str, ToolEntry]] = None,
                 *, missing_only: bool = True) -> List[List[str]]:
    """Shell-command sequence that would install missing tools.

    Returns a list of ``argv`` lists; the wizard surfaces these for
    confirmation, then runs each ``subprocess.run`` style.
    """
    statuses = scan(catalog)
    plan: List[List[str]] = []
    for s in statuses:
        if missing_only and s.installed:
            continue
        if s.install_cmd:
            plan.append(s.install_cmd)
    # Coalesce consecutive apt installs into one — fewer prompts.
    return _coalesce_apt(plan)


def install_plan_human(catalog: Optional[Dict[str, ToolEntry]] = None) -> str:
    """The same plan rendered as a copy-pasteable shell block."""
    lines = []
    for cmd in install_plan(catalog):
        lines.append("  " + " ".join(shlex.quote(p) for p in cmd))
    return "\n".join(lines) or "  # everything already installed"


# ── helpers ───────────────────────────────────────────────────────
_VER_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[a-z0-9.-]*)?)")


def _probe_version(path: str, arg: str, timeout: int = 5) -> Optional[str]:
    try:
        proc = subprocess.run([path, arg], capture_output=True, text=True,
                               timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None
    text = (proc.stdout or "") + " " + (proc.stderr or "")
    m = _VER_RE.search(text)
    return m.group(1) if m else None


def _coalesce_apt(plan: List[List[str]]) -> List[List[str]]:
    """Merge runs of ``sudo apt-get install -y X``, ``... Y`` into a single cmd."""
    out: List[List[str]] = []
    buf: List[str] = []
    for cmd in plan:
        if cmd[:4] == ["sudo", "apt-get", "install", "-y"]:
            buf.extend(cmd[4:])
        else:
            if buf:
                out.append(["sudo", "apt-get", "install", "-y", *sorted(set(buf))])
                buf = []
            out.append(cmd)
    if buf:
        out.append(["sudo", "apt-get", "install", "-y", *sorted(set(buf))])
    return out


def summarize(catalog: Optional[Dict[str, ToolEntry]] = None) -> Dict[str, int]:
    statuses = scan(catalog)
    return {
        "total":     len(statuses),
        "installed": sum(1 for s in statuses if s.installed),
        "missing":   sum(1 for s in statuses if not s.installed),
    }
