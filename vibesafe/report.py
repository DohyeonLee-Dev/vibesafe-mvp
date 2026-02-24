"""Generate HTML security reports."""
from __future__ import annotations

from datetime import datetime, timezone

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#6b7280",
}

SEVERITY_BG = {
    "critical": "#fef2f2",
    "high": "#fff7ed",
    "medium": "#fefce8",
    "low": "#f9fafb",
}


class ReportGenerator:
    """Generate HTML reports from scan findings."""

    def generate_html(self, findings: list, project_path: str) -> str:
        """Generate a complete HTML report."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        crit = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        med = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        if crit > 0:
            grade, grade_color = "F", "#dc2626"
        elif high > 0:
            grade, grade_color = "D", "#ea580c"
        elif med > 3:
            grade, grade_color = "C", "#ca8a04"
        elif med > 0:
            grade, grade_color = "B", "#2563eb"
        else:
            grade, grade_color = "A", "#16a34a"

        findings_html = ""
        for f in findings:
            color = SEVERITY_COLORS.get(f.severity, "#6b7280")
            bg = SEVERITY_BG.get(f.severity, "#f9fafb")
            snippet_block = ""
            if f.snippet:
                esc = f.snippet.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                snippet_block = (
                    f'<code style="display:block;background:#1e1e1e;color:#d4d4d4;'
                    f'padding:8px;margin-top:6px;border-radius:4px;font-size:0.85em;'
                    f'overflow-x:auto;">{esc}</code>'
                )
            fix_block = ""
            if f.fix_hint:
                fix_block = (
                    f'<p style="margin-top:6px;color:#16a34a;font-size:0.85em;">'
                    f'\u2705 Fix: {f.fix_hint}</p>'
                )
            findings_html += (
                f'<div style="border-left:4px solid {color};background:{bg};'
                f'padding:12px 16px;margin:8px 0;border-radius:4px;">'
                f'<div style="display:flex;justify-content:space-between;align-items:center;">'
                f'<strong style="color:{color};">{f.severity.upper()}</strong>'
                f'<code style="font-size:0.85em;color:#6b7280;">{f.rule_id}</code></div>'
                f'<p style="margin:4px 0;font-weight:600;">{f.message}</p>'
                f'<p style="margin:2px 0;color:#6b7280;font-size:0.9em;">'
                f'{f.file_path}:{f.line_number}</p>'
                f'{snippet_block}{fix_block}</div>\n'
            )

        clean_msg = (
            '<p style="color:#16a34a;font-weight:600;font-size:1.1em;padding:20px 0;">'
            '\u2705 No security issues found. Your code looks clean!</p>'
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VibeSafe Security Report</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:#0f172a; color:#e2e8f0; line-height:1.6; }}
.container {{ max-width:900px; margin:0 auto; padding:40px 20px; }}
.header {{ text-align:center; margin-bottom:32px; }}
.header h1 {{ font-size:2.2em; background:linear-gradient(135deg,#06b6d4,#8b5cf6); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }}
.header p {{ color:#94a3b8; margin-top:8px; }}
.grade {{ display:inline-flex; align-items:center; justify-content:center; width:80px; height:80px; border-radius:50%; font-size:2.5em; font-weight:800; color:white; background:{grade_color}; margin:16px 0; }}
.stats {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:24px 0; }}
.stat {{ background:#1e293b; border-radius:8px; padding:16px; text-align:center; }}
.stat .num {{ font-size:1.8em; font-weight:700; }}
.stat .label {{ font-size:0.85em; color:#94a3b8; margin-top:4px; }}
.findings {{ background:#1e293b; border-radius:12px; padding:24px; margin-top:24px; }}
.findings h2 {{ margin-bottom:16px; }}
.footer {{ text-align:center; margin-top:40px; color:#475569; font-size:0.85em; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>\U0001f6e1\ufe0f VibeSafe Security Report</h1>
    <p>{project_path}</p>
    <p style="font-size:0.85em;color:#64748b;">Generated {now}</p>
    <div class="grade">{grade}</div>
  </div>
  <div class="stats">
    <div class="stat"><div class="num" style="color:#dc2626;">{crit}</div><div class="label">Critical</div></div>
    <div class="stat"><div class="num" style="color:#ea580c;">{high}</div><div class="label">High</div></div>
    <div class="stat"><div class="num" style="color:#ca8a04;">{med}</div><div class="label">Medium</div></div>
    <div class="stat"><div class="num" style="color:#6b7280;">{low}</div><div class="label">Low</div></div>
  </div>
  <div class="findings">
    <h2>Findings ({len(findings)} total)</h2>
    {findings_html if findings_html else clean_msg}
  </div>
  <div class="footer">
    <p>Generated by <strong>VibeSafe</strong> \u2014 security scanner for vibe-coded projects</p>
  </div>
</div>
</body>
</html>"""
