"""Security rules engine with pattern-based vulnerability detection."""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class Finding:
    """A single security finding."""
    rule_id: str
    severity: str  # critical, high, medium, low
    file_path: str
    line_number: int
    message: str
    snippet: str = ""
    fix_hint: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "message": self.message,
            "snippet": self.snippet,
            "fix_hint": self.fix_hint,
        }


@dataclass
class Rule:
    """A security rule definition."""
    rule_id: str
    name: str
    severity: str
    description: str
    pattern: re.Pattern
    file_patterns: list[str] = field(default_factory=lambda: ["*"])
    message_template: str = ""
    fix_hint: str = ""

    def check_line(self, line: str, file_path: str,
                   line_num: int) -> Finding | None:
        """Check a single line against this rule."""
        if not self._matches_file(file_path):
            return None
        match = self.pattern.search(line)
        if match:
            msg = self.message_template or f"{self.name}: {self.description}"
            return Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                file_path=file_path,
                line_number=line_num,
                message=msg,
                snippet=line.strip()[:120],
                fix_hint=self.fix_hint,
            )
        return None

    def _matches_file(self, file_path: str) -> bool:
        """Check if this rule applies to the given file."""
        if "*" in self.file_patterns:
            return True
        from pathlib import Path
        suffix = Path(file_path).suffix.lower()
        name = Path(file_path).name.lower()
        for pat in self.file_patterns:
            if pat.startswith(".") and suffix == pat:
                return True
            if pat in name:
                return True
        return False


# ---- Built-in Security Rules ----

_RULES: list[Rule] = [
    # CRITICAL: Hardcoded secrets
    Rule(
        rule_id="VS-SEC-001",
        name="Hardcoded API Key",
        severity="critical",
        description="Hardcoded API key or secret token detected",
        pattern=re.compile(
            r"""(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token"""
            r"""|auth[_-]?token|bearer)\s*[=:]\s*['"][A-Za-z0-9_\-]{16,}['"]""",
            re.IGNORECASE,
        ),
        message_template="Hardcoded API key or secret detected \u2014 use environment variables instead",
        fix_hint="Move secrets to .env file and use os.environ.get()",
    ),
    Rule(
        rule_id="VS-SEC-002",
        name="Hardcoded Password",
        severity="critical",
        description="Hardcoded password in source code",
        pattern=re.compile(
            r"""(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{4,}['"]""",
            re.IGNORECASE,
        ),
        message_template="Hardcoded password detected \u2014 never store passwords in source code",
        fix_hint="Use environment variables or a secrets manager",
    ),
    Rule(
        rule_id="VS-SEC-003",
        name="AWS Credentials",
        severity="critical",
        description="AWS access key or secret key in source code",
        pattern=re.compile(
            r"""(?:AKIA[0-9A-Z]{16}|aws_secret_access_key\s*=\s*['"][A-Za-z0-9/+=]{30,}['"])"""
        ),
        message_template="AWS credentials detected in source code",
        fix_hint="Use AWS IAM roles or environment variables",
    ),
    Rule(
        rule_id="VS-SEC-004",
        name="Private Key",
        severity="critical",
        description="Private key embedded in source code",
        pattern=re.compile(r"-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        message_template="Private key detected in source code",
        fix_hint="Store private keys in secure key management",
    ),

    # HIGH: Injection vulnerabilities
    Rule(
        rule_id="VS-INJ-001",
        name="SQL Injection",
        severity="high",
        description="Potential SQL injection via string formatting",
        pattern=re.compile(
            r"""(?:execute|cursor\.execute|query|raw)\s*\(\s*(?:f['"]|['"].*%s|['"].*\+\s*|['"].*\.format)""",
            re.IGNORECASE,
        ),
        file_patterns=[".py", ".js", ".ts", ".rb", ".php"],
        message_template="Potential SQL injection \u2014 use parameterized queries",
        fix_hint="Use parameterized queries instead of string formatting",
    ),
    Rule(
        rule_id="VS-INJ-002",
        name="Command Injection",
        severity="high",
        description="Shell command with user input",
        pattern=re.compile(
            r"""(?:os\.system|subprocess\.call|subprocess\.run|exec|eval)\s*\(\s*(?:f['"]|['"].*%|['"].*\+|.*\bformat\b)""",
            re.IGNORECASE,
        ),
        file_patterns=[".py"],
        message_template="Potential command injection",
        fix_hint="Use subprocess with a list of args, validate inputs",
    ),
    Rule(
        rule_id="VS-INJ-003",
        name="XSS via innerHTML",
        severity="high",
        description="Setting innerHTML with potentially untrusted data",
        pattern=re.compile(r"""(?:innerHTML|outerHTML|dangerouslySetInnerHTML)\s*="""),
        file_patterns=[".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte", ".html"],
        message_template="Potential XSS via innerHTML",
        fix_hint="Use textContent or sanitize with DOMPurify",
    ),
    Rule(
        rule_id="VS-INJ-004",
        name="eval() Usage",
        severity="high",
        description="Use of eval() can execute arbitrary code",
        pattern=re.compile(r"""\beval\s*\("""),
        file_patterns=[".py", ".js", ".ts", ".jsx", ".tsx"],
        message_template="eval() can execute arbitrary code",
        fix_hint="Use JSON.parse(), ast.literal_eval(), or specific parsers",
    ),

    # MEDIUM: Configuration issues
    Rule(
        rule_id="VS-CFG-001",
        name="Debug Mode Enabled",
        severity="medium",
        description="Debug mode left enabled",
        pattern=re.compile(
            r"""(?:DEBUG\s*=\s*True|debug\s*:\s*true|NODE_ENV.*development)""",
            re.IGNORECASE,
        ),
        message_template="Debug mode is enabled \u2014 disable in production",
        fix_hint="Use environment variables for debug settings",
    ),
    Rule(
        rule_id="VS-CFG-002",
        name="CORS Allow All",
        severity="medium",
        description="CORS allows all origins",
        pattern=re.compile(
            r"""(?:allow_origins\s*=\s*\[['"]?\*['"]?\]|Access-Control-Allow-Origin.*\*|cors\(\s*\))""",
            re.IGNORECASE,
        ),
        message_template="CORS allows all origins",
        fix_hint="Restrict to specific trusted domains",
    ),
    Rule(
        rule_id="VS-CFG-003",
        name="Missing HTTPS",
        severity="medium",
        description="HTTP URL used instead of HTTPS",
        pattern=re.compile(
            r"""(?:fetch|axios|request|http\.get)\s*\(\s*['"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)"""
        ),
        file_patterns=[".js", ".ts", ".jsx", ".tsx", ".py"],
        message_template="HTTP URL detected \u2014 use HTTPS",
        fix_hint="Change http:// to https://",
    ),

    # Crypto issues
    Rule(
        rule_id="VS-CRY-001",
        name="Weak Hash Algorithm",
        severity="medium",
        description="MD5 or SHA1 used for security",
        pattern=re.compile(
            r"""(?:hashlib\.md5|hashlib\.sha1|createHash\s*\(\s*['"](?:md5|sha1)['"])""",
            re.IGNORECASE,
        ),
        message_template="Weak hash (MD5/SHA1) \u2014 use SHA-256 or bcrypt",
        fix_hint="Use hashlib.sha256() or bcrypt for passwords",
    ),
    Rule(
        rule_id="VS-CRY-002",
        name="Hardcoded JWT Secret",
        severity="high",
        description="JWT signed with a hardcoded secret",
        pattern=re.compile(
            r"""(?:jwt\.(?:encode|sign|decode|verify))\s*\([^)]*['"][A-Za-z0-9_\-]{8,}['"]""",
            re.IGNORECASE,
        ),
        message_template="JWT uses hardcoded secret",
        fix_hint="Use environment variable for JWT secret",
    ),

    # AI-generated code patterns
    Rule(
        rule_id="VS-AI-001",
        name="Pickle Deserialization",
        severity="high",
        description="pickle.loads can execute arbitrary code",
        pattern=re.compile(r"""pickle\.loads?\s*\("""),
        file_patterns=[".py"],
        message_template="pickle deserialization can execute arbitrary code",
        fix_hint="Use json.loads() or pydantic for deserialization",
    ),
    Rule(
        rule_id="VS-AI-002",
        name="YAML Unsafe Load",
        severity="high",
        description="yaml.load without SafeLoader",
        pattern=re.compile(r"""yaml\.load\s*\([^)]*(?!Loader|SafeLoader)\)"""),
        file_patterns=[".py"],
        message_template="yaml.load() without SafeLoader can execute code",
        fix_hint="Use yaml.safe_load() instead",
    ),
    Rule(
        rule_id="VS-AI-003",
        name="Disabled SSL Verification",
        severity="high",
        description="SSL verification disabled",
        pattern=re.compile(
            r"""(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED.*0)""",
            re.IGNORECASE,
        ),
        message_template="SSL verification disabled",
        fix_hint="Enable SSL verification",
    ),

    # Code quality
    Rule(
        rule_id="VS-QLT-001",
        name="TODO/FIXME in Code",
        severity="low",
        description="Unresolved TODO or FIXME comment",
        pattern=re.compile(r"""(?:#|//|/\*)\s*(?:TODO|FIXME|HACK|XXX)\b""", re.IGNORECASE),
        message_template="Unresolved TODO/FIXME",
        fix_hint="Resolve or create a tracked issue",
    ),
    Rule(
        rule_id="VS-QLT-002",
        name="Console.log in Production",
        severity="low",
        description="console.log left in code",
        pattern=re.compile(r"""\bconsole\.log\s*\("""),
        file_patterns=[".js", ".ts", ".jsx", ".tsx"],
        message_template="console.log() in production code",
        fix_hint="Use a proper logging library",
    ),
    Rule(
        rule_id="VS-QLT-003",
        name="Bare Except",
        severity="low",
        description="Bare except catches all exceptions",
        pattern=re.compile(r"""except\s*:"""),
        file_patterns=[".py"],
        message_template="Bare except: catches all exceptions",
        fix_hint="Catch specific exception types",
    ),
]


class RuleEngine:
    """Applies all security rules to source code."""

    def __init__(self) -> None:
        self.rules = list(_RULES)

    def check(self, file_path: str, content: str) -> list[Finding]:
        """Check all rules against the file content."""
        findings: list[Finding] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            for rule in self.rules:
                finding = rule.check_line(line, file_path, line_num)
                if finding:
                    findings.append(finding)

        return findings
