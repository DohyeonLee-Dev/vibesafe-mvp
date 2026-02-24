"""File scanner that applies security rules to source code."""
from __future__ import annotations

import logging
from pathlib import Path

from vibesafe.rules import RuleEngine, Finding

SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".rb", ".php", ".java", ".kt",
    ".html", ".htm", ".vue", ".svelte",
    ".yaml", ".yml", ".toml", ".json", ".env",
    ".sh", ".bash", ".zsh",
    ".sql", ".dockerfile",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".svelte-kit", "target",
    ".mypy_cache", ".pytest_cache", "htmlcov", ".tox",
    "vendor", "third_party",
}

MAX_FILE_SIZE = 1_000_000  # 1MB


class Scanner:
    """Walks a directory and applies security rules to each file."""

    def __init__(self, engine: RuleEngine,
                 ignore_rules: set[str] | None = None):
        self.engine = engine
        self.ignore_rules = ignore_rules or set()
        self.logger = logging.getLogger("Scanner")

    def scan_directory(self, root: Path) -> list[Finding]:
        """Scan all files in the directory tree."""
        findings: list[Finding] = []

        if root.is_file():
            return self._scan_file(root)

        for path in sorted(root.rglob("*")):
            if path.is_dir():
                continue
            if any(skip in path.parts for skip in SKIP_DIRS):
                continue
            if path.suffix.lower() not in SCANNABLE_EXTENSIONS:
                continue
            if path.stat().st_size > MAX_FILE_SIZE:
                continue

            findings.extend(self._scan_file(path))

        return findings

    def _scan_file(self, path: Path) -> list[Finding]:
        """Scan a single file."""
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            return []

        raw_findings = self.engine.check(str(path), content)
        return [f for f in raw_findings if f.rule_id not in self.ignore_rules]
