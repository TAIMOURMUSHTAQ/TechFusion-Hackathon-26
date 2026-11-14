"""Tests against the organiser's base files (data/) and the synthetic set (samples/synthetic/).

The expected answers were worked out by hand from the files before the code was written.
"""
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from triage.pipeline import analyse          # noqa: E402
from triage.qa import Index, answer, verify  # noqa: E402
from triage.timeparse import iso             # noqa: E402

DATA = ROOT / "data"


@pytest.fixture(scope="module")
def an():
    return analyse(DATA)


def copy_data(tmp_path, src=DATA):
    d = tmp_path / "data"
    shutil.copytree(src, d)
    for f in d.rglob("*"):          # the source files may be read-only; tests edit the copies
        f.chmod(f.stat().st_mode | 0o200)
    return d


def edit(path: Path, old: str, new: str):
    t = path.read_text()
    assert old in t, old
    path.write_text(t.replace(old, new))


def inc_with(an, ftype):
    return next(i for i in an.incidents if any(f.type == ftype for f in i.findings))


def finding(an, ftype, **kw):
    return next(f for f in an.findings if f.type == ftype and all(getattr(f, k) == v for k, v in kw.items()))


def ev(an, file, line):
    return next(e for e in an.events if e.file == file and e.line == line)


# ---------------------------------------------------------------- 1. timeline and time zones
@pytest.mark.parametrize("file,line,utc", [
    ("11_vpn_auth_log.md", 12, "2026-11-04 05:49:12"),          # ISO Z
    ("12_windows_dc_auth_log.md", 9, "2026-11-04 05:55:33"),     # "UTC" in the line
    ("13_web_server_log.md", 14, "2026-11-04 06:06:02"),         # 11:06:02 +0500
    ("14_firewall_perimeter_log.md", 13, "2026-11-04 04:19:40"), # no zone, UTC per coverage sheet
    ("15_firewall_internal_log.md", 11, "2026-11-04 06:03:12"),  # 11:21:19 PKT logged at CLOSE, minus 1087 s
    ("16_email_gateway_log.md", 7, "2026-11-04 04:12:07"),       # 09:12:07 PKT
    ("17_ids_alert_summary.md", 13, "2026-11-04 16:05:29"),      # table row
    ("19_dhcp_lease_log.md", 7, "2026-11-04 03:57:40"),          # +05:00
])
def test_timestamps_to_utc(an, file, line, utc):
    assert iso(ev(an, file, line).ts) == utc


def test_close_logged_session_end_kept(an):
    e = ev(an, "15_firewall_internal_log.md", 19)
    assert iso(e.ts) == "2026-11-04 17:31:05" and iso(e.end) == "2026-11-04 18:24:12"
    assert iso(ev(an, "12_windows_dc_auth_log.md", 16).ts) == iso(e.ts)    # same second as the RDP logon


def test_timeline_sorted_and_cited(an):
    j = an.to_json()["incidents"][0]["timeline"]
    assert [e["utc"] for e in j] == sorted(e["utc"] for e in j)
    assert all(re.fullmatch(r"[\w./-]+:L\d+", e["cite"]) for e in j)


def test_every_citation_in_report_exists(an):
    found = re.findall(r"([\w./-]+\.\w+):L(\d+)(?:-L(\d+))?", an.report_md)
    assert len(found) > 100
    for path, a, b in found:
        f = an.files[path]
        assert 1 <= int(a) <= len(f.lines) and 1 <= int(b or a) <= len(f.lines), (path, a)


def test_report_has_required_sections(an):
    for s in ["Summary", "Timeline (UTC, with file and line)", "Affected assets and accounts", "Severity (with steps)",
              "Confirmed", "Suspected", "Not enough evidence in the logs", "Missing log sources",
              "Closed as harmless (with change ID)", "Recommended actions (runbook ID and step)",
              "People to inform (name and time limit)"]:
        assert re.search(rf"^## \d+\. {re.escape(s)}$", an.report_md, re.M), s


# ---------------------------------------------------------------- 2. incidents and severity
def test_incident_list(an):
    got = [(i.severity, sorted(f.type for f in i.findings)) for i in an.incidents]
    assert got == [("P1", ["credential_compromise", "data_exfiltration", "phishing"]),
                   ("P2", ["web_attack"]), ("P3", ["credential_compromise"]), ("P4", ["port_scan"])]


def test_p1_reasoning(an):
    inc = an.incidents[0]
    steps = " ".join(inc.severity_steps)
    assert "SRV-FS01 (High)" in steps and "Data exfiltration" in steps and "= **P1**" in steps
    assert "Not counted: SRV-DC01" in steps                       # Kerberos to the DC is not a session (rule 4.1)
    cc = finding(an, "credential_compromise", variant="successful")
    assert {a.label for a, _ in cc.affected} == {"SRV-VPN01", "SRV-FS01", "SRV-DB01"}


def test_web_attack_success_suspected_p2(an):
    f = finding(an, "web_attack")
    assert f.variant == "successful" and f.affected[0][0].label == "SRV-WEB01"
    assert any("48,213" in c.text for c in f.confirmed)
    assert any("success" in c.text.lower() for c in f.suspected)


def test_recon_is_p4_not_web_attack(an):
    f = finding(an, "port_scan", src_ips=["192.0.2.88"])
    assert not f.dismissed and len(f.evidence) >= 9      # 6 firewall lines + 3 web probes
    assert inc_with(an, "port_scan").severity == "P4"


def test_rule_62_utariq(an):
    f = finding(an, "credential_compromise", variant="suspected")
    assert f.users == ["utariq"] and any("rule 6.2" in c.text for c in f.suspected)
    assert any("AFTER" in c.text for c in f.confirmed)   # the phishing email came later, so it is not the cause
    assert all(f not in i.findings for i in an.incidents if i.severity == "P1")


# ---------------------------------------------------------------- 3. messy evidence
def test_click_seen_through_firewall_and_threat_intel(an):
    p = finding(an, "phishing")
    assert p.clickers == ["amalik"] and p.link_ips == ["198.51.100.77"]
    assert any("LT-FIN-014" in m for m in p.matches)
    assert {a.label for a, _ in p.affected} == {"LT-FIN-022", "LT-WH-021"}       # no-click recipients only


def test_entity_matching(an):
    cc = finding(an, "credential_compromise", variant="successful")
    m = " ".join(cc.matches)
    assert "cifs/FS01.orbit.local" in m and "orbit.local" in m and "A-1005" in m
    assert "10.10.3.45" in m and "VS-20433" in m


def test_noise_closed_with_change_ids(an):
    assert {f.change.change.id for f in an.dismissed} == {"CHG-2026-1104-02", "CHG-2026-1104-03"}
    assert {a.extra["alert id"] for f in an.dismissed for a in f.alerts} == {"ALT-9006", "ALT-9007"}


def test_traps_not_used_to_close(an):
    txt = " ".join(r for f in an.findings for r in f.related_changes)
    assert "CHG-2026-1104-01" in txt and "CHG-2026-1104-05" in txt and "Postponed" in txt
    assert all(f.change is None or not f.change.covered or f.change.change.id not in
               ("CHG-2026-1104-01", "CHG-2026-1104-05", "CHG-2026-1105-01") for f in an.findings)


def test_no_overclaim(an):
    for f in an.findings:
        for c in f.confirmed:
            assert not re.search(r"\b(stolen|leaked|exfiltrated)\b", c.text, re.I), c.text
    x = finding(an, "data_exfiltration")
    assert any("which files" in c.text.lower() for c in x.unknown)


def test_missing_sources_and_gaps(an):
    cov = an.coverage
    assert len(cov.missing) == 5
    gap = next(g for g in cov.gaps if "internal" in g.file)
    assert (iso(gap.start), iso(gap.end)) == ("2026-11-04 06:32:00", "2026-11-04 07:28:59")
    inc = an.incidents[0]
    assert any("15_firewall_internal_log" in g and "CHG-2026-1104-05" in g for g in inc.gaps)
    assert any("audit" in m for m in inc.missing) and any("EDR" in m for m in inc.missing)


def test_every_alert_accounted_for(an):
    out = {a.extra["alert id"]: (f.id if f else None) for a, f in an.alert_map}
    assert len(out) == 8 and None not in out.values()


# ---------------------------------------------------------------- 4. actions and contacts
def test_actions_only_from_runbooks(an):
    rb = "\n".join(l for f in an.files.values() if f.kind == "runbook" for l in f.lines)
    for inc in an.incidents:
        for a in inc.actions:
            for s in a.get("steps", []):
                if s["step"] != "note":
                    assert s["text"] in rb and re.fullmatch(r"RB-[A-Z]+-\d+ step \d+", s["step"])


def test_conditions(an):
    steps = {s["step"]: s for a in an.incidents[0].actions for s in a.get("steps", [])}
    assert steps["RB-PHISH-01 step 5"]["condition"] == "met"
    assert steps["RB-CRED-02 step 6"]["condition"].startswith("met")
    assert steps["RB-CRED-02 step 1"]["condition"] == ""               # "ask if" is not a condition
    assert "do not exist" in steps["RB-EXFIL-04 step 5"]["condition"]
    assert "+92-300-5550114" in steps["RB-CRED-02 step 1"]["applies_to"]


def test_p1_contacts(an):
    esc = an.incidents[0].escalation
    assert [e["limit"] for e in esc] == ["15 minutes", "30 minutes", "1 hour", "1 hour"]
    assert "Saima Noor" in esc[3]["resolved"] and esc[2]["condition"].startswith("condition met")


# ---------------------------------------------------------------- robustness: change the files, the answer must follow
def test_scan_outside_window_not_closed(tmp_path):
    d = copy_data(tmp_path)
    edit(d / "05_change_calendar.md", "| 21:00 - 23:00 | Servers in 10.10.1.0/24", "| 19:00 - 20:00 | Servers in 10.10.1.0/24")
    an2 = analyse(d)
    assert "CHG-2026-1104-02" not in {f.change.change.id for f in an2.dismissed}
    s = finding(an2, "port_scan", src_ips=["10.10.9.50"])
    assert any("NOT inside" in r for r in s.change.reasons)


def test_postponed_change_does_not_close(tmp_path):
    d = copy_data(tmp_path)
    edit(d / "05_change_calendar.md", "Security patching, remote desktop session | Approved by IT Director",
         "Security patching, remote desktop session | Postponed, not performed")
    an2 = analyse(d)
    rdp = finding(an2, "remote_admin")
    assert not rdp.dismissed and "Postponed" in " ".join(rdp.change.reasons)


def test_change_timezone_is_respected(tmp_path):
    d = copy_data(tmp_path)
    edit(d / "05_change_calendar.md", "(all times PKT)", "(all times UTC)")
    edit(d / "05_change_calendar.md", "| Window (PKT) |", "| Window (UTC) |")
    an2 = analyse(d)          # 21:00-23:00 UTC no longer contains 16:05 UTC
    assert "CHG-2026-1104-02" not in {f.change.change.id for f in an2.dismissed}


def test_internal_fw_close_logging_matters(tmp_path):
    d = copy_data(tmp_path)
    edit(d / "20_log_source_coverage.md", "Logged when the session closes, not when it starts. ", "")
    an2 = analyse(d)
    assert iso(next(e for e in an2.events if e.file.startswith("15_") and e.line == 11).ts) == "2026-11-04 06:21:19"


def test_missing_reference_files_degrade(tmp_path):
    d = copy_data(tmp_path)
    (d / "03_severity_matrix.md").unlink()
    for p in d.glob("*runbook*"):
        p.unlink()
    an2 = analyse(d)
    assert all(i.severity is None for i in an2.incidents)
    assert all(a.get("runbook") is None for i in an2.incidents for a in i.actions)
    assert any("severity matrix" in w for w in an2.warnings)


def test_garbage_lines_do_not_crash(tmp_path):
    d = copy_data(tmp_path)
    edit(d / "11_vpn_auth_log.md", "```\n2026-11-04T02:58:41Z", "```\n\x00 garbage\n{not json\n2026-11-04T02:58:41Z")
    an2 = analyse(d)
    assert any("no readable timestamp" in w for w in an2.warnings) and an2.incidents[0].severity == "P1"


def test_synthetic_dataset_still_works():
    an3 = analyse(ROOT / "samples" / "synthetic")
    assert an3.incidents[0].severity == "SEV1"
    assert {f.change.change.id for f in an3.dismissed} == {"CHG-1042", "CHG-1045"}


# ---------------------------------------------------------------- Q&A
def test_verify_removes_fake_citations(an):
    idx = Index(an)
    text, good, bad = verify("Login [11_vpn_auth_log.md:L12]. Fake [11_vpn_auth_log.md:L999] and [nope.md:L1].", idx)
    assert good == ["11_vpn_auth_log.md:L12"] and len(bad) == 2 and "citation removed" in text


def test_fallback_answer_without_key(an, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    r = answer(an, Index(an), "Was data stolen from SRV-FS01?")
    assert r["model"] == "deterministic-fallback" and "audit" in r["answer"].split("Most relevant")[0]


def test_query_expansion_alias(an):
    hits = Index(an).search("FS01 large transfer")
    assert any("10.10.1.20" in t for _, _, t in hits[:5])


class _Resp:
    def __init__(self, code, body=None, headers=None):
        self.status_code, self._b, self.headers, self.text = code, body, headers or {}, str(body)

    def json(self):
        return self._b


def test_llm_retries_429_then_falls_back(monkeypatch, an):
    from triage import llm
    monkeypatch.setenv("GROQ_API_KEY", "x")
    monkeypatch.setenv("OPENROUTER_API_KEY", "y")
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    calls = []

    def fake_post(url, **kw):
        calls.append(url)
        if "groq" in url:
            return _Resp(429, {"error": "rate"}, {"retry-after": "1"})
        return _Resp(200, {"choices": [{"message": {"content":
            "Confirmed: VPN login from RO [11_vpn_auth_log.md:L12]. Invented [11_vpn_auth_log.md:L5000]."}}]})
    monkeypatch.setattr(llm.requests, "post", fake_post)
    r = answer(an, Index(an), "Where did amalik log in from?")
    assert sum("groq" in c for c in calls) == 3 and "openrouter" in calls[-1]
    assert r["citations"] == ["11_vpn_auth_log.md:L12"] and r["flags"]


# ---------------------------------------------------------------- API and CLI
def test_api(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    from app.main import app
    c = TestClient(app)
    assert c.get("/api/health").json()["ok"]
    j = c.get("/api/analyze").json()
    assert j["incidents"][0]["severity"] == "P1" and len(j["alerts"]) == 8
    assert c.post("/api/ask", json={"question": "was data stolen?"}).status_code == 200
    assert c.get("/").status_code == 200
    assert c.post("/api/ask", json={"question": "x", "dataset": "nope"}).status_code == 404


def test_api_upload_zip(tmp_path):
    from app.main import app
    z = shutil.make_archive(str(tmp_path / "ds"), "zip", DATA)
    with open(z, "rb") as f:
        r = TestClient(app).post("/api/upload", files=[("files", ("ds.zip", f, "application/zip"))])
    assert r.status_code == 200 and r.json()["incidents"][0]["severity"] == "P1"


def test_cli(tmp_path):
    out = tmp_path / "r.md"
    p = subprocess.run([sys.executable, "-m", "triage", str(DATA), "-o", str(out)], cwd=ROOT, capture_output=True, text=True)
    assert p.returncode == 0 and "P1" in p.stdout and out.read_text().startswith("# Incident Report")
