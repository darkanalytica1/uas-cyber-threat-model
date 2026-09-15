"""Render the threat model as a Markdown matrix and a standalone HTML page. Output is deterministic."""
from __future__ import annotations

import html

from .model import STRIDE_ORDER, ThreatModel

GENERATED_NOTE = "Generated from data/threat-model.yaml by `python -m uasthreat render`. Do not edit by hand."


def _md(text: str) -> str:
    return text.replace("|", "\\|")


def to_markdown(m: ThreatModel) -> str:
    out = [f"# Threat matrix: {m.system}", "", f"<!-- {GENERATED_NOTE} -->", ""]
    out += [
        "Rows are attack surfaces, columns are STRIDE categories with the property each one attacks. "
        "Each cell lists the threats identified there; every cell is filled, which is the point of STRIDE: "
        "gaps are named rather than missed. Threat IDs link to the detail tables below.",
        "",
    ]
    head = "| Surface | " + " | ".join(f"{L} · {m.stride[L]['threat']}<br><sub>{m.stride[L]['property']}</sub>" for L in STRIDE_ORDER) + " |"
    out += [head, "|---|" + "---|" * len(STRIDE_ORDER)]
    for s in m.surfaces:
        cells = []
        for L in STRIDE_ORDER:
            items = m.cell(s.id, L)
            cells.append("<br>".join(f"[{t.id}](#{t.id.lower()})" + (" n/a" if t.not_applicable else "") for t in items))
        out.append(f"| **{s.id}** {_md(s.name)} | " + " | ".join(cells) + " |")
    out += ["", "## Trust boundaries", "", "| ID | Boundary | Why it matters |", "|---|---|---|"]
    for b in m.boundaries:
        out.append(f"| {b['id']} | {_md(b['name'])} | {_md(b['description'])} |")
    for s in m.surfaces:
        out += ["", f"## {s.id} · {s.name}", "", f"{s.description} Trust boundary: {s.boundary}.", ""]
        out += ["| ID | STRIDE | Threat | Controls | Residual risk |", "|---|---|---|---|---|"]
        for L in STRIDE_ORDER:
            for t in m.cell(s.id, L):
                text = f"Not applicable: {t.not_applicable}" if t.not_applicable else t.threat
                ctrls = ", ".join(f"[{c}](#{c.lower()})" for c in t.controls)
                out.append(f"| <a id=\"{t.id.lower()}\"></a>{t.id} | {m.stride[L]['threat']} | {_md(text)} | {ctrls} | {_md(t.residual)} |")
    out += ["", "## Control catalogue", "", "| ID | Control | What it means | Counters | References |", "|---|---|---|---|---|"]
    for c in m.controls.values():
        used = ", ".join(t.id for t in m.threats_for_control(c.id))
        out.append(f"| <a id=\"{c.id.lower()}\"></a>{c.id} | {_md(c.name)} | {_md(c.detail)} | {used} | {_md('; '.join(c.refs))} |")
    out.append("")
    return "\n".join(out)


CSS = """
:root{--page:#F5F7FA;--surface:#FFFFFF;--line:#D8DEE6;--ink:#0E1726;--ink2:#3D4A5C;--ink3:#5F6B7C;
--navy:#0B2545;--brass:#8A6A1F;--teal:#2F6F73;--tint:#EDF1F6}
*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--ink);
font:16px/1.6 'IBM Plex Sans',system-ui,-apple-system,'Segoe UI',sans-serif}
main{max-width:1120px;margin:0 auto;padding:48px 24px}
.label{font:500 12px/1 'IBM Plex Mono',ui-monospace,monospace;letter-spacing:.08em;text-transform:uppercase;color:var(--ink3)}
h1,h2{font-family:'IBM Plex Sans',system-ui,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;font-weight:600;letter-spacing:-.01em;line-height:1.25}
h1{font-size:32px;margin:12px 0 8px;border-top:3px solid var(--navy);padding-top:16px}h2{font-size:24px;margin:40px 0 12px}
p{color:var(--ink2);max-width:760px}
.wrap{overflow-x:auto;background:var(--surface);border:1px solid var(--line);border-radius:6px}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{border-bottom:1px solid var(--line);padding:10px 12px;text-align:left;vertical-align:top}
th{background:var(--page);font-weight:600;position:sticky;top:0}
th small{display:block;font:400 11px 'IBM Plex Mono',ui-monospace,monospace;color:var(--ink3);letter-spacing:.04em}
.chip{display:inline-block;font:500 12px 'IBM Plex Mono',ui-monospace,monospace;background:var(--tint);
color:var(--navy);border-radius:4px;padding:2px 6px;margin:2px 4px 2px 0;text-decoration:none}
.chip:hover,.chip:focus{background:var(--navy);color:#fff}
.mono{font-family:'IBM Plex Mono',ui-monospace,monospace;font-size:13px}
td.res{color:var(--ink2)}
"""


def to_html(m: ThreatModel) -> str:
    e = html.escape
    parts = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        f"<title>Threat matrix · {e(m.system)}</title><style>{CSS}</style></head><body><main>",
        f"<!-- {e(GENERATED_NOTE)} -->",
        "<div class=\"label\">DarkAnalytica · threat model · defensive reference</div>",
        f"<h1>Threat matrix: {e(m.system)}</h1>",
        "<p>Attack surfaces against STRIDE categories. Every cell is filled; each threat is paired with the controls that counter it and the residual risk that remains.</p>",
        "<div class=\"wrap\"><table><thead><tr><th>Surface</th>",
    ]
    parts += [f"<th>{L} · {e(m.stride[L]['threat'])}<small>{e(m.stride[L]['property'])}</small></th>" for L in STRIDE_ORDER]
    parts.append("</tr></thead><tbody>")
    for s in m.surfaces:
        parts.append(f"<tr><td><strong>{e(s.id)}</strong> {e(s.name)}<br><span class=\"mono\">{e(s.boundary)}</span></td>")
        for L in STRIDE_ORDER:
            chips = "".join(f"<a class=\"chip\" href=\"#{t.id.lower()}\">{e(t.id)}</a>" for t in m.cell(s.id, L))
            parts.append(f"<td>{chips}</td>")
        parts.append("</tr>")
    parts.append("</tbody></table></div>")
    for s in m.surfaces:
        parts.append(f"<h2>{e(s.id)} · {e(s.name)}</h2><p>{e(s.description)}</p>")
        parts.append("<div class=\"wrap\"><table><thead><tr><th>ID</th><th>STRIDE</th><th>Threat</th><th>Controls</th><th>Residual risk</th></tr></thead><tbody>")
        for L in STRIDE_ORDER:
            for t in m.cell(s.id, L):
                text = f"Not applicable: {t.not_applicable}" if t.not_applicable else t.threat
                chips = "".join(f"<a class=\"chip\" href=\"#{c.lower()}\">{e(c)}</a>" for c in t.controls)
                parts.append(
                    f"<tr id=\"{t.id.lower()}\"><td class=\"mono\">{e(t.id)}</td><td>{e(m.stride[L]['threat'])}</td>"
                    f"<td>{e(text)}</td><td>{chips}</td><td class=\"res\">{e(t.residual)}</td></tr>"
                )
        parts.append("</tbody></table></div>")
    parts.append("<h2>Control catalogue</h2><div class=\"wrap\"><table><thead><tr><th>ID</th><th>Control</th><th>What it means</th><th>Counters</th><th>References</th></tr></thead><tbody>")
    for c in m.controls.values():
        used = "".join(f"<a class=\"chip\" href=\"#{t.id.lower()}\">{e(t.id)}</a>" for t in m.threats_for_control(c.id))
        parts.append(
            f"<tr id=\"{c.id.lower()}\"><td class=\"mono\">{e(c.id)}</td><td>{e(c.name)}</td><td>{e(c.detail)}</td>"
            f"<td>{used}</td><td class=\"res\">{e('; '.join(c.refs))}</td></tr>"
        )
    parts.append("</tbody></table></div></main></body></html>\n")
    return "\n".join(parts)
