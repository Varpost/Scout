"""Tests for the headers scanner — CSRF noise reduction, Helmet, CORS."""

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


def test_express_without_helmet_is_flagged(tmp_path: Path):
    app = _write(
        tmp_path / "server.js",
        'const express = require("express");\nconst app = express();\napp.listen(3000);\n',
    )
    findings = HeadersScanner().scan([app])
    assert any("Helmet" in f.title for f in findings)


def test_express_with_helmet_is_clean(tmp_path: Path):
    app = _write(
        tmp_path / "server.js",
        'const express = require("express");\n'
        'const helmet = require("helmet");\n'
        "const app = express();\napp.use(helmet());\n",
    )
    findings = HeadersScanner().scan([app])
    assert not any("Helmet" in f.title for f in findings)


def test_wildcard_cors_is_flagged_with_real_line(tmp_path: Path):
    app = _write(
        tmp_path / "server.js",
        'const express = require("express");\n'
        "const app = express();\n"
        'app.use((req, res) => res.set("Access-Control-Allow-Origin", "*"));\n',
    )
    findings = HeadersScanner().scan([app])
    cors = [f for f in findings if "CORS" in f.title]
    assert len(cors) == 1
    assert cors[0].line == 3
    assert cors[0].snippet  # surrounding-context snippet, not a placeholder


def test_non_web_files_are_skipped(tmp_path: Path):
    script = _write(tmp_path / "tool.py", "print('no framework here')\n")
    assert HeadersScanner().scan_file(script, script.read_text(encoding="utf-8")) == []


def test_flask_without_talisman_is_flagged(tmp_path: Path):
    app = _write(
        tmp_path / "app.py",
        "from flask import Flask\napp = Flask(__name__)\n@app.route('/')\ndef home():\n    return 'hi'\n",
    )
    findings = HeadersScanner().scan([app])
    hdr = [f for f in findings if "security headers" in f.title.lower()]
    assert len(hdr) == 1
    assert hdr[0].severity == "MEDIUM"
    assert hdr[0].line == 2  # anchored to the Flask(...) line, not a synthetic 1
    assert "Talisman" in hdr[0].fix_summary  # plain-English, actionable fix


def test_flask_with_talisman_is_clean(tmp_path: Path):
    app = _write(
        tmp_path / "app.py",
        "from flask import Flask\nfrom flask_talisman import Talisman\napp = Flask(__name__)\nTalisman(app)\n",
    )
    findings = HeadersScanner().scan([app])
    assert not any("security headers" in f.title.lower() for f in findings)


def test_fastapi_without_middleware_is_flagged(tmp_path: Path):
    app = _write(
        tmp_path / "main.py",
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/')\ndef root():\n    return {}\n",
    )
    findings = HeadersScanner().scan([app])
    mw = [f for f in findings if "security middleware" in f.title.lower()]
    assert len(mw) == 1
    assert mw[0].severity == "LOW"


def test_fastapi_with_middleware_is_clean(tmp_path: Path):
    app = _write(
        tmp_path / "main.py",
        "from fastapi import FastAPI\n"
        "from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware\n"
        "app = FastAPI()\napp.add_middleware(HTTPSRedirectMiddleware)\n",
    )
    findings = HeadersScanner().scan([app])
    assert not any("security middleware" in f.title.lower() for f in findings)


def test_django_settings_missing_hardening_is_flagged(tmp_path: Path):
    settings = _write(
        tmp_path / "settings.py",
        "from pathlib import Path\n"
        "INSTALLED_APPS = [\n    'django.contrib.admin',\n    'django.contrib.auth',\n]\n"
        "MIDDLEWARE = ['django.middleware.security.SecurityMiddleware']\n"
        "DEBUG = False\n",
    )
    findings = HeadersScanner().scan([settings])
    django = [f for f in findings if "Django" in f.title]
    assert len(django) == 1
    assert "SECURE_SSL_REDIRECT" in django[0].fix_summary


def test_django_settings_hardened_is_clean(tmp_path: Path):
    settings = _write(
        tmp_path / "settings.py",
        "INSTALLED_APPS = ['django.contrib.admin']\nSECURE_SSL_REDIRECT = True\nSECURE_HSTS_SECONDS = 31536000\n",
    )
    findings = HeadersScanner().scan([settings])
    assert not any("Django" in f.title for f in findings)


def test_safe_app_fixture_stays_zero_fp():
    safe = Path(__file__).parent.parent / "fixtures" / "safe_app.py"
    assert HeadersScanner().scan([safe]) == []
