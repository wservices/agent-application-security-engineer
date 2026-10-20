"""Behavior-contract tests for secure_code_review.py — offline static patterns.

Note: the fixtures below are deliberately-vulnerable *call constructs*, never
secrets. No credential/token literals appear here (the platform secret scanner
owns that surface; this tool flags dangerous calls only).
"""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("secure_code_review", ROOT / "scripts" / "secure_code_review.py")
scr = importlib.util.module_from_spec(spec)
sys.modules["secure_code_review"] = scr
spec.loader.exec_module(scr)

BAD_PY = (
    "import hashlib, pickle, subprocess, yaml\n"
    "def run(cmd):\n"
    "    subprocess.call(cmd, shell=True)\n"
    "def load(d):\n"
    "    return pickle.loads(d)\n"
    "def weak(x):\n"
    "    return hashlib.md5(x).hexdigest()\n"
    "def q(conn, name):\n"
    "    conn.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n"
    "def q2(conn, uid):\n"
    "    conn.execute(f\"SELECT * FROM t WHERE id = {uid}\")\n"
    "def danger(e):\n"
    "    return eval(e)\n"
    "def cfg(t):\n"
    "    return yaml.load(t)\n"
)

SAFE_PY = (
    "import hashlib, yaml\n"
    "def strong(x):\n"
    "    return hashlib.sha256(x).hexdigest()\n"
    "def q(conn, uid):\n"
    "    conn.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))\n"
    "def cfg(t):\n"
    "    return yaml.safe_load(t)\n"
    "def cfg2(t):\n"
    "    return yaml.load(t, Loader=yaml.SafeLoader)\n"
)


def test_flags_known_bad_snippet_with_categories_and_cwe():
    findings = scr.scan_text(BAD_PY, "bad.py")
    cats = {f["category"] for f in findings}
    assert {"code-injection", "command-injection", "unsafe-deserialization",
            "sql-injection", "weak-crypto"} <= cats
    # every finding carries a CWE and a severity in the known set
    assert all(f["cwe"].startswith("CWE-") for f in findings)
    assert all(f["severity"] in scr._SEV_ORDER for f in findings)
    # eval is critical; the two SQL-injection lines are both caught
    assert any(f["category"] == "code-injection" and f["severity"] == "critical" for f in findings)
    assert sum(1 for f in findings if f["category"] == "sql-injection") == 2


def test_clean_on_safe_snippet():
    # sha256, parameterized %s query, safe_load, and explicit SafeLoader are all OK
    assert scr.scan_text(SAFE_PY, "safe.py") == []


def test_language_awareness():
    # innerHTML is a JS/HTML concern, not flagged in a .py file
    js = "el.innerHTML = userInput;\n"
    assert any(f["category"] == "dom-xss" for f in scr.scan_text(js, "x.js"))
    assert scr.scan_text(js, "x.py") == []
    # subprocess shell=True is a Python rule, not applied to .js
    py = "subprocess.run(cmd, shell=True)\n"
    assert any(f["category"] == "command-injection" for f in scr.scan_text(py, "x.py"))
    assert scr.scan_text(py, "x.js") == []


def test_diff_mode_scans_only_added_lines_with_new_file_numbering():
    diff = (
        "--- a/app/db.py\n"
        "+++ b/app/db.py\n"
        "@@ -10,3 +10,4 @@ def get(conn, name):\n"
        "     cur = conn.cursor()\n"
        "-    return cur.fetchone()\n"
        "+    conn.execute(\"SELECT * FROM t WHERE name = '\" + name + \"'\")\n"
        "+    return cur.fetchone()\n"
    )
    findings = scr.scan_diff(diff)
    assert len(findings) == 1
    assert findings[0]["file"] == "app/db.py"
    assert findings[0]["line"] == 11
    assert findings[0]["category"] == "sql-injection"
