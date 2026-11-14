"""Load every file in the dataset folder and work out what kind of file it is."""
from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from pathlib import Path

TEXT_EXT = {".log", ".txt", ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".md", ".yml", ".yaml"}
LOG_KINDS = {"auth", "vpn", "web", "firewall", "email", "log", "dhcp", "ids"}
MAX_BYTES = 20 * 1024 * 1024


@dataclass
class SourceFile:
    path: str                      # path relative to the dataset root, forward slashes
    kind: str
    lines: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]

    @property
    def is_log(self) -> bool:
        return self.kind in LOG_KINDS

    def cite(self, line: int) -> str:
        return f"{self.path}:L{line}"

    def fenced(self) -> list[int]:
        """1-based line numbers inside ``` code fences (the raw log part of a Markdown export)."""
        out, inside = [], False
        for i, l in enumerate(self.lines, 1):
            if l.strip().startswith("```"):
                inside = not inside
                continue
            if inside and l.strip():
                out.append(i)
        return out


def classify(rel: str, lines: list[str]) -> str:
    """Decide the file kind from its name first, then from its content."""
    low = rel.lower()
    name = low.rsplit("/", 1)[-1]
    stem = name.rsplit(".", 1)[0]
    ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    head = "\n".join(lines[:15]).lower()
    has = lambda *ks: any(k in stem for k in ks)

    if "runbook" in low or "playbook" in low or re.match(r"(\d+_)?rb[-_ ]?\d", stem):
        return "runbook"
    if has("severity"):
        return "severity"
    if has("escalat", "contact", "oncall"):
        return "escalation"
    if has("coverage", "log_source", "logsource", "data_source"):
        return "coverage"
    if has("inventory", "asset", "cmdb"):
        return "inventory"
    if has("directory", "staff", "employee", "users", "people"):
        return "directory"
    if has("change", "calendar", "maintenance"):
        return "change"
    if stem.startswith("readme"):
        return "doc"
    if has("ids", "alert", "siem", "detection"):
        return "ids"
    if has("dhcp", "lease"):
        return "dhcp"
    if has("vpn"):
        return "vpn"
    if has("auth", "login", "logon", "sshd", "signin", "secure.log", "_dc_", "domain_controller", "kerberos", "windows"):
        return "auth"
    if has("firewall", "fw", "netflow"):
        return "firewall"
    if has("mail", "smtp"):
        return "email"
    if has("web", "access", "http", "nginx", "apache", "proxy", "waf"):
        return "web"
    if has("rule", "policy", "policies", "standard", "guideline"):
        return "policy"
    if ext in {".log", ".jsonl", ".ndjson"} or "/logs/" in "/" + low or "log" in stem:
        return "log"
    if "criticality" in head and ("hostname" in head or "asset" in head):
        return "inventory"
    if re.search(r"\bsev\s?\d\b|\bp[1-4]\b", head) and ("notify" in head or "inform" in head):
        return "escalation"
    if ext == ".md":
        return "policy"
    return "log" if ext in {".csv", ".json", ".txt"} else "doc"


def load_dataset(root: str | Path) -> dict[str, SourceFile]:
    root = Path(root)
    if not root.is_dir():
        raise FileNotFoundError(f"dataset folder not found: {root}")
    files: dict[str, SourceFile] = {}
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.name.startswith("."):
            continue
        if p.suffix.lower() not in TEXT_EXT or p.stat().st_size > MAX_BYTES:
            continue
        rel = p.relative_to(root).as_posix()
        try:
            text = p.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        files[rel] = SourceFile(rel, classify(rel, lines), lines)
    return files


# ----------------------------------------------------------------- tables
def _split_md_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def read_table(sf: SourceFile) -> list[tuple[int, dict[str, str]]]:
    """Read a CSV/TSV file or the markdown pipe tables in a file.

    Returns (line_number, {lower-case header: value}) for every data row.
    """
    rows: list[tuple[int, dict[str, str]]] = []
    md_lines = [i for i, l in enumerate(sf.lines) if l.strip().startswith("|") and l.count("|") >= 2]
    if md_lines:
        header: list[str] | None = None
        prev = -5
        for i in md_lines:
            cells = _split_md_row(sf.lines[i])
            if i != prev + 1:
                header = [c.lower() for c in cells]            # first row of a new table
            elif all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
                pass                                            # the |---|---| separator
            elif header:
                rows.append((i + 1, {h: (cells[k] if k < len(cells) else "") for k, h in enumerate(header)}))
            prev = i
        return rows
    data = [(i, l) for i, l in enumerate(sf.lines) if l.strip() and not l.lstrip().startswith("#")]
    if not data:
        return rows
    first = data[0][1]
    delim = max([",", "\t", ";", "|"], key=first.count)
    if first.count(delim) == 0:
        return rows
    header = [h.strip().lower() for h in next(csv.reader(io.StringIO(first), delimiter=delim))]
    for i, l in data[1:]:
        try:
            cells = next(csv.reader(io.StringIO(l), delimiter=delim))
        except (csv.Error, StopIteration):
            continue
        rows.append((i + 1, {h: (cells[k].strip() if k < len(cells) else "") for k, h in enumerate(header)}))
    return rows


def find_col(row: dict[str, str], *needles: str, exclude: tuple[str, ...] = ()) -> str | None:
    """Return the first header that contains any of the needles."""
    for n in needles:
        for h in row:
            if n in h and not any(x in h for x in exclude):
                return h
    return None
