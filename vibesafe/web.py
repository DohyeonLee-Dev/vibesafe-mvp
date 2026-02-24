"""FastAPI web dashboard for browsing scan results."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from vibesafe.scanner import Scanner
from vibesafe.rules import RuleEngine
from vibesafe.report import ReportGenerator


def create_app(project_path: str) -> FastAPI:
    """Create a FastAPI app with scan results pre-loaded."""
    app = FastAPI(title="VibeSafe Dashboard")

    engine = RuleEngine()
    scanner = Scanner(engine)
    findings = scanner.scan_directory(Path(project_path))
    findings.sort(
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
            f.severity, 4
        ),
    )

    reporter = ReportGenerator()

    @app.get("/", response_class=HTMLResponse)
    async def home():
        return reporter.generate_html(findings, project_path)

    @app.get("/api/findings")
    async def api_findings():
        return [f.to_dict() for f in findings]

    @app.get("/api/summary")
    async def api_summary():
        return {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
            "project_path": project_path,
        }

    return app
