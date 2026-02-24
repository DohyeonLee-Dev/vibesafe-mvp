"""Tests for VibeSafe security rules."""
import pytest
from vibesafe.rules import RuleEngine


@pytest.fixture
def engine():
    return RuleEngine()


def test_detects_hardcoded_api_key(engine):
    code = 'api_key = "sk-proj-abc123def456ghi789jkl012mno345"'
    findings = engine.check("config.py", code)
    assert any(f.rule_id == "VS-SEC-001" for f in findings)


def test_detects_hardcoded_password(engine):
    code = 'password = "super_secret_123"'
    findings = engine.check("config.py", code)
    assert any(f.rule_id == "VS-SEC-002" for f in findings)


def test_detects_sql_injection(engine):
    code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    findings = engine.check("app.py", code)
    assert any(f.rule_id == "VS-INJ-001" for f in findings)


def test_detects_innerHTML_xss(engine):
    code = "element.innerHTML = userInput;"
    findings = engine.check("app.js", code)
    assert any(f.rule_id == "VS-INJ-003" for f in findings)


def test_detects_eval(engine):
    code = "result = eval(user_input)"
    findings = engine.check("handler.py", code)
    assert any(f.rule_id == "VS-INJ-004" for f in findings)


def test_detects_debug_mode(engine):
    code = "DEBUG = True"
    findings = engine.check("settings.py", code)
    assert any(f.rule_id == "VS-CFG-001" for f in findings)


def test_detects_pickle(engine):
    code = "data = pickle.loads(raw_bytes)"
    findings = engine.check("handler.py", code)
    assert any(f.rule_id == "VS-AI-001" for f in findings)


def test_detects_disabled_ssl(engine):
    code = "resp = requests.get(url, verify=False)"
    findings = engine.check("client.py", code)
    assert any(f.rule_id == "VS-AI-003" for f in findings)


def test_clean_code_no_critical_issues(engine):
    code = (
        "import os\n"
        "\n"
        "def get_user(user_id: int):\n"
        "    return db.query(User).filter(User.id == user_id).first()\n"
    )
    findings = engine.check("app.py", code)
    critical_high = [f for f in findings if f.severity in ("critical", "high")]
    assert len(critical_high) == 0
