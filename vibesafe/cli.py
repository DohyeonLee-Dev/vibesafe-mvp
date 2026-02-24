"""VibeSafe CLI - scan projects for security vulnerabilities."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from vibesafe.scanner import Scanner
from vibesafe.rules import RuleEngine
from vibesafe.report import ReportGenerator

console = Console()


@click.group()
@click.version_option(package_name="vibesafe")
def main():
    """VibeSafe - catch security issues in AI-generated code before they ship."""
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["table", "json", "html"]),
    default="table",
    help="Output format",
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default=None,
    help="Minimum severity to show",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file path")
@click.option("--ignore", "-i", multiple=True, help="Rule IDs to ignore")
def scan(path: str, output_format: str, severity: str | None,
         output: str | None, ignore: tuple[str, ...]):
    """Scan a project directory for security vulnerabilities."""
    target = Path(path)
    console.print(Panel.fit(
        f"[bold cyan]VibeSafe[/] scanning [yellow]{target.resolve()}[/]",
        border_style="cyan",
    ))

    engine = RuleEngine()
    scanner = Scanner(engine, ignore_rules=set(ignore))
    findings = scanner.scan_directory(target)

    # Filter by severity
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    if severity:
        min_level = severity_order.get(severity, 0)
        findings = [
            f for f in findings
            if severity_order.get(f.severity, 0) >= min_level
        ]

    # Sort by severity (critical first)
    findings.sort(
        key=lambda f: severity_order.get(f.severity, 0), reverse=True
    )

    if output_format == "table":
        _print_table(findings)
    elif output_format == "json":
        data = [f.to_dict() for f in findings]
        result = json.dumps(data, indent=2)
        if output:
            Path(output).write_text(result)
            console.print(f"[green]JSON report saved to {output}[/]")
        else:
            click.echo(result)
    elif output_format == "html":
        reporter = ReportGenerator()
        html = reporter.generate_html(findings, str(target.resolve()))
        out_path = Path(output) if output else Path("vibesafe-report.html")
        out_path.write_text(html)
        console.print(f"[green]HTML report saved to {out_path}[/]")

    # Summary
    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    med = sum(1 for f in findings if f.severity == "medium")
    low = sum(1 for f in findings if f.severity == "low")

    console.print()
    summary = Text()
    summary.append(f"  Found {len(findings)} issues: ", style="bold")
    if crit:
        summary.append(f"{crit} critical ", style="bold red")
    if high:
        summary.append(f"{high} high ", style="red")
    if med:
        summary.append(f"{med} medium ", style="yellow")
    if low:
        summary.append(f"{low} low ", style="dim")
    if not findings:
        summary.append("No issues found!", style="bold green")

    border = "red" if crit or high else "yellow" if med else "green"
    console.print(Panel(summary, border_style=border))

    if crit or high:
        sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--port", "-p", type=int, default=8000, help="Dashboard port")
def dashboard(path: str, port: int):
    """Launch the web dashboard to browse scan results."""
    import uvicorn
    from vibesafe.web import create_app

    target = Path(path).resolve()
    app = create_app(str(target))
    console.print(Panel.fit(
        f"[bold cyan]VibeSafe Dashboard[/]\n"
        f"Scanning: [yellow]{target}[/]\n"
        f"Open: [link=http://localhost:{port}]http://localhost:{port}[/link]",
        border_style="cyan",
    ))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")


@main.command()
def rules():
    """List all available security rules."""
    engine = RuleEngine()
    table = Table(title="VibeSafe Security Rules", show_lines=True)
    table.add_column("ID", style="cyan", width=18)
    table.add_column("Name", style="bold")
    table.add_column("Severity", width=10)
    table.add_column("Description")

    sev_styles = {
        "critical": "bold red", "high": "red",
        "medium": "yellow", "low": "dim",
    }

    for rule in engine.rules:
        table.add_row(
            rule.rule_id,
            rule.name,
            Text(rule.severity, style=sev_styles.get(rule.severity, "")),
            rule.description,
        )

    console.print(table)


def _print_table(findings):
    """Print findings as a Rich table."""
    if not findings:
        console.print("[bold green]No security issues found![/]")
        return

    table = Table(title="Security Findings", show_lines=True)
    table.add_column("Severity", width=10)
    table.add_column("Rule", style="cyan", width=20)
    table.add_column("File", style="yellow")
    table.add_column("Line", justify="right", width=6)
    table.add_column("Description")

    sev_styles = {
        "critical": "bold red", "high": "red",
        "medium": "yellow", "low": "dim",
    }

    for f in findings:
        table.add_row(
            Text(f.severity.upper(), style=sev_styles.get(f.severity, "")),
            f.rule_id,
            f.file_path,
            str(f.line_number),
            f.message,
        )

    console.print(table)
