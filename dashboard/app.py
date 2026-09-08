import os
import csv
import math
from collections import Counter
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

DECISION_LOG = os.path.join(os.path.dirname(__file__), "..", "gateway", "gateway_decisions.csv")
app = FastAPI(title="APISentry AI Dashboard")

DEC_COLORS = {"ALLOW": "#22c55e", "BLOCK": "#ef4444", "RATE_LIMIT": "#f59e0b"}
TYPE_COLORS = {
    "normal": "#22c55e", "sql_injection": "#ef4444", "api_flooding": "#f97316",
    "bola": "#a855f7", "brute_force": "#eab308", "credential_stuffing": "#ec4899",
    "parameter_tampering": "#14b8a6", "token_replay": "#f43f5e",
}

CSS = """
* { box-sizing: border-box; }
body { font-family: 'Segoe UI', system-ui, Arial, sans-serif; background:
  radial-gradient(1200px 600px at 20% -10%, #14203b 0%, #0b1220 55%); color:#e2e8f0;
  margin:0; padding:22px; }
.top { display:flex; align-items:center; justify-content:space-between; margin-bottom:20px; }
.brand { display:flex; align-items:center; gap:12px; }
.logo { width:42px; height:42px; border-radius:11px; background:linear-gradient(135deg,#3b82f6,#8b5cf6);
  display:flex; align-items:center; justify-content:center; font-weight:800; font-size:20px; box-shadow:0 6px 18px rgba(59,130,246,.4); }
h1 { margin:0; font-size:22px; letter-spacing:.3px; }
.sub { color:#94a3b8; font-size:12px; }
.threat { text-align:right; }
.threat .lvl { font-size:22px; font-weight:800; }
.threat .lbl { color:#94a3b8; font-size:11px; text-transform:uppercase; letter-spacing:1px; }
.cards { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:20px; }
.card { background:#111a2e; border:1px solid #1e293b; border-radius:14px; padding:18px 20px; position:relative; overflow:hidden; }
.card .n { font-size:34px; font-weight:800; }
.card .l { color:#94a3b8; font-size:12px; text-transform:uppercase; letter-spacing:.6px; margin-top:2px; }
.card .bar { position:absolute; left:0; top:0; bottom:0; width:5px; }
.grid { display:grid; grid-template-columns:300px 1fr; gap:16px; margin-bottom:20px; }
.panel { background:#111a2e; border:1px solid #1e293b; border-radius:14px; padding:18px 20px; }
.panel h3 { margin:0 0 14px; font-size:13px; color:#94a3b8; text-transform:uppercase; letter-spacing:1px; }
.donut-wrap { display:flex; flex-direction:column; align-items:center; gap:12px; }
.legend { display:flex; gap:14px; flex-wrap:wrap; justify-content:center; font-size:12px; }
.legend span { display:flex; align-items:center; gap:6px; color:#cbd5e1; }
.dot { width:10px; height:10px; border-radius:3px; display:inline-block; }
.bar-row { display:flex; align-items:center; margin:9px 0; gap:10px; }
.bar-label { width:150px; font-size:13px; }
.bar-track { flex:1; background:#0b1220; border-radius:7px; overflow:hidden; height:22px; }
.bar-fill { height:100%; color:#fff; font-size:12px; font-weight:700; text-align:right;
  padding:0 8px; line-height:22px; border-radius:7px; }
.strip { display:flex; gap:2px; margin-top:6px; height:34px; align-items:flex-end; }
.tick { flex:1; border-radius:2px 2px 0 0; min-width:2px; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th,td { text-align:left; padding:9px 10px; border-bottom:1px solid #1e293b; }
th { color:#94a3b8; font-size:11px; text-transform:uppercase; letter-spacing:.6px; }
td.ip { font-family:monospace; color:#93c5fd; }
.pill { padding:3px 11px; border-radius:20px; color:#fff; font-size:11px; font-weight:700; }
.tag { padding:2px 9px; border-radius:6px; font-size:11px; font-weight:700; }
.risk { font-weight:700; }
"""


def read_rows():
    if not os.path.exists(DECISION_LOG):
        return []
    with open(DECISION_LOG) as f:
        return list(csv.DictReader(f))


def donut(allowed, blocked, limited):
    real_total = allowed + blocked + limited
    total = max(real_total, 1)
    segs = [("#22c55e", allowed), ("#ef4444", blocked), ("#f59e0b", limited)]
    r = 70
    c = 2 * math.pi * r
    off = 0.0
    parts = ""
    for color, val in segs:
        dash = (val / total) * c
        parts += (f'<circle cx="90" cy="90" r="{r}" fill="none" stroke="{color}" '
                  f'stroke-width="26" stroke-dasharray="{dash:.1f} {c-dash:.1f}" '
                  f'stroke-dashoffset="{-off:.1f}" transform="rotate(-90 90 90)"/>')
        off += dash
    return (f'<svg width="180" height="180" viewBox="0 0 180 180">{parts}'
            f'<text x="90" y="84" text-anchor="middle" fill="#e2e8f0" font-size="32" font-weight="800">{real_total}</text>'
            f'<text x="90" y="106" text-anchor="middle" fill="#94a3b8" font-size="12">TOTAL</text></svg>')


@app.get("/", response_class=HTMLResponse)
def dashboard():
    rows = read_rows()
    total = len(rows)
    dec = Counter(r["decision"] for r in rows)
    allowed = dec.get("ALLOW", 0)
    blocked = dec.get("BLOCK", 0)
    limited = dec.get("RATE_LIMIT", 0)

    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    recent_atk = 0
    for r in rows[-300:]:
        try:
            t = datetime.fromisoformat(r["timestamp"])
            if now - t <= timedelta(seconds=30) and r["decision"] in ("BLOCK", "RATE_LIMIT"):
                recent_atk += 1
        except Exception:
            pass
    if recent_atk >= 15:
        level, lc = "CRITICAL", "#ef4444"
    elif recent_atk >= 5:
        level, lc = "HIGH", "#f97316"
    elif recent_atk >= 1:
        level, lc = "ELEVATED", "#f59e0b"
    else:
        level, lc = "LOW", "#22c55e"

    pred = Counter(r["predicted"] for r in rows if r["predicted"] != "normal")
    max_p = max(pred.values()) if pred else 1
    bars = ""
    for lab, cnt in sorted(pred.items(), key=lambda x: -x[1]):
        pct = int(cnt / max_p * 100)
        color = TYPE_COLORS.get(lab, "#64748b")
        bars += (f'<div class="bar-row"><div class="bar-label">{lab}</div>'
                 f'<div class="bar-track"><div class="bar-fill" style="width:{max(pct,8)}%;background:{color}">{cnt}</div></div></div>')
    if not bars:
        bars = '<p style="color:#64748b">No attacks detected yet</p>'

    strip = ""
    for r in rows[-50:]:
        col = DEC_COLORS.get(r["decision"], "#334155")
        hh = 34 if r["decision"] != "ALLOW" else 16
        strip += f'<div class="tick" style="height:{hh}px;background:{col}"></div>'

    trows = ""
    for r in rows[-12:][::-1]:
        dc = DEC_COLORS.get(r["decision"], "#64748b")
        tc = TYPE_COLORS.get(r["predicted"], "#64748b")
        ts = r["timestamp"][11:19] if len(r["timestamp"]) > 19 else r["timestamp"]
        trows += (f'<tr><td>{ts}</td><td class="ip">{r["ip"]}</td><td>{r["method"]}</td>'
                  f'<td>{r["endpoint"]}</td><td><span class="tag" style="background:{tc}22;color:{tc}">{r["predicted"]}</span></td>'
                  f'<td class="risk" style="color:{dc}">{r["risk"]}</td>'
                  f'<td><span class="pill" style="background:{dc}">{r["decision"]}</span></td></tr>')

    html = f"""<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="2"><title>APISentry AI</title><style>{CSS}</style></head><body>
<div class="top">
  <div class="brand"><div class="logo">A</div>
    <div><h1>APISentry AI</h1><div class="sub">Real-time API Security Gateway &middot; live monitoring</div></div></div>
  <div class="threat"><div class="lvl" style="color:{lc}">&#9679; {level}</div><div class="lbl">Threat Level</div></div>
</div>
<div class="cards">
  <div class="card"><div class="bar" style="background:#3b82f6"></div><div class="n">{total}</div><div class="l">Total Requests</div></div>
  <div class="card"><div class="bar" style="background:#22c55e"></div><div class="n" style="color:#22c55e">{allowed}</div><div class="l">Allowed</div></div>
  <div class="card"><div class="bar" style="background:#ef4444"></div><div class="n" style="color:#ef4444">{blocked}</div><div class="l">Blocked</div></div>
  <div class="card"><div class="bar" style="background:#f59e0b"></div><div class="n" style="color:#f59e0b">{limited}</div><div class="l">Rate Limited</div></div>
</div>
<div class="grid">
  <div class="panel"><h3>Decisions</h3><div class="donut-wrap">{donut(allowed, blocked, limited)}
    <div class="legend">
      <span><i class="dot" style="background:#22c55e"></i>Allowed</span>
      <span><i class="dot" style="background:#ef4444"></i>Blocked</span>
      <span><i class="dot" style="background:#f59e0b"></i>Limited</span></div></div></div>
  <div class="panel"><h3>Detected Attacks by Type</h3>{bars}
    <h3 style="margin-top:18px">Live Activity (last 50)</h3><div class="strip">{strip}</div></div>
</div>
<div class="panel"><h3>Recent Decisions</h3>
  <table><tr><th>Time</th><th>Source IP</th><th>Method</th><th>Endpoint</th><th>Detected</th><th>Risk</th><th>Action</th></tr>
  {trows if trows else '<tr><td colspan=7 style="color:#64748b">Waiting for traffic...</td></tr>'}</table></div>
</body></html>"""
    return html
