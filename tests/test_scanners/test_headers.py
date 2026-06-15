"""Tests for the headers scanner — focused on CSRF noise reduction."""

from pathlib import Path

from scout.scanners.headers import HeadersScanner


def _write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_csrf_not_flagged_for_token_api(tmp_path: Path):
    # Flask + Bearer-token API, no cookies/sessions/forms -> not CSRF-vulnerable.
    api = _write(
        tmp_path / "api.py",
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        '@app.post("/users")\n'
        "def create():\n"
        '    token = request.headers["Authorization"]\n',
    )
    findings = HeadersScanner().scan([api])
    assert not any("CSRF" in f.title for f in findings), [f.title for f in findings]


def test_csrf_flagged_once_per_project_with_python_comment(tmp_path: Path):
    # Session/template app across two files -> exactly ONE CSRF finding.
    app = _write(
        tmp_path / "app.py",
        "from flask import Flask, session, render_template\n"
        "app = Flask(__name__)\n"
        '@app.route("/login", methods=["POST"])\n'
        "def login():\n"
        '    session["user"] = 1\n'
        '    return render_template("home.html")\n',
    )
    routes = _write(tmp_path / "routes.py", "from flask import Flask\n# extra routes\n")

    findings = HeadersScanner().scan([app, routes])
    csrf = [f for f in findings if "CSRF" in f.title]

    assert len(csrf) == 1  # once per project, not once per file
    assert csrf[0].snippet.startswith("# ")  # Python comment style, not //


def test_csrf_suppressed_when_protection_present(tmp_path: Path):
    app = _write(
        tmp_path / "app.py",
        "from flask import Flask, session, render_template\n"
        "from flask_wtf import CSRFProtect\n"
        "app = Flask(__name__)\n"
        "CSRFProtect(app)\n"
        'session["x"] = 1\n'
        'render_template("a.html")\n',
    )
    findings = HeadersScanner().scan([app])
    assert not any("CSRF" in f.title for f in findings)
