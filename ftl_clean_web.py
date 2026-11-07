# -*- coding: utf-8 -*-
"""Cleanup page + local server. The page can only send item ids. Server listens on 127.0.0.1 only and checks Host, Origin and a secret token."""
import os, json, html, secrets, threading, subprocess, datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import ftl_clean_core as C
import ftl_clean_act as A
from ftl_clean_core import human, ITEMS, EXPOSURE, HOGS

E = html.escape
TOKEN = secrets.token_urlsafe(24)
GROUPS = ["Malware / suspicious files", "Hidden hijacks & dangerous start-ups", "Task Manager: programs eating your PC", "Block the ways in (hardening)", "Junk files you can remove",
          "Big folders to review", "Programs that start with Windows (slows boot)", "Maintenance & reset (optional)"]
GICON = {"Malware / suspicious files": "☣", "Hidden hijacks & dangerous start-ups": "🕳", "Task Manager: programs eating your PC": "📈", "Block the ways in (hardening)": "🛡",
         "Junk files you can remove": "🧹", "Big folders to review": "📁", "Programs that start with Windows (slows boot)": "🚀", "Maintenance & reset (optional)": "🔧"}
RB = {"high": "FAIL", "medium": "WARN", "low": "PASS"}
RLAB = {"high": "DANGEROUS / MALICIOUS", "medium": "CHECK", "low": "SAFE"}


def exposure_svg():
    def agg(d):
        g = {}
        for e in EXPOSURE:
            if e["dir"] != d: continue
            r = e["route"].split(" on port")[0] if e["route"].startswith("Open door") else e["route"]
            x = g.setdefault(r, {"n": 0, "risk": "low"}); x["n"] += 1
            if {"low": 0, "medium": 1, "high": 2}[e["risk"]] > {"low": 0, "medium": 1, "high": 2}[x["risk"]]: x["risk"] = e["risk"]
        return sorted(g.items(), key=lambda kv: -{"low": 0, "medium": 1, "high": 2}[kv[1]["risk"]])[:8]
    col = {"high": "var(--fail)", "medium": "var(--warn)", "low": "var(--ok)"}
    ins, outs = agg("IN"), agg("OUT"); rows = max(len(ins), len(outs), 3); h = rows * 44 + 40
    o = ["<svg viewBox='0 0 900 %d' width='100%%' role='img' aria-label='Ways in and ways out'>" % h,
         "<text x='10' y='20' font-size='13' font-weight='700' style='fill:var(--text)'>WAYS IN (hackers, worms, remote tools)</text><text x='890' y='20' text-anchor='end' font-size='13' font-weight='700' style='fill:var(--text)'>WAYS OUT (your data leaves)</text>",
         "<rect x='350' y='40' width='200' height='%d' rx='16' style='fill:var(--card);stroke:var(--brand)' stroke-width='3'/><text x='450' y='%d' text-anchor='middle' font-size='34'>💻</text><text x='450' y='%d' text-anchor='middle' font-size='14' font-weight='700' style='fill:var(--text)'>YOUR LAPTOP</text>" % (h - 50, h // 2 + 8, h // 2 + 32)]
    for i, (n, v) in enumerate(ins):
        y = 40 + i * 44
        o.append("<rect x='10' y='%d' width='270' height='34' rx='8' style='fill:%s;opacity:.18;stroke:%s'/><text x='20' y='%d' font-size='12' style='fill:var(--text)'>%s (%d)</text><path d='M282 %d H345' style='stroke:%s' stroke-width='3'/><path d='M338 %d l8 4 l-8 4z' style='fill:%s'/>" % (y, col[v["risk"]], col[v["risk"]], y + 21, E(n[:38]), v["n"], y + 17, col[v["risk"]], y + 13, col[v["risk"]]))
    for i, (n, v) in enumerate(outs):
        y = 40 + i * 44
        o.append("<rect x='620' y='%d' width='270' height='34' rx='8' style='fill:%s;opacity:.18;stroke:%s'/><text x='630' y='%d' font-size='12' style='fill:var(--text)'>%s (%d)</text><path d='M555 %d H615' style='stroke:%s' stroke-width='3'/><path d='M608 %d l8 4 l-8 4z' style='fill:%s'/>" % (y, col[v["risk"]], col[v["risk"]], y + 21, E(n[:38]), v["n"], y + 17, col[v["risk"]], y + 13, col[v["risk"]]))
    o.append("</svg>")
    return "".join(o)


def hog_table(rows, key, fmt):
    t = "".join("<tr><td><b>%s</b>%s</td><td>%s</td><td class='%s'>%s</td></tr>" % (E(g["name"]), (" ×%d" % g["n"]) if g["n"] > 1 else "", fmt(g[key]), "fail" if g["flag"] == "high" else "", E(g["explain"][:150])) for g in rows[:6])
    return "<table><tr><th>Program</th><th>Using</th><th>What it is</th></tr>%s</table>" % t


def build_page(subtitle):
    import findthelaptop as FT, ftl_charts as ch
    n_mal = sum(1 for i in ITEMS if i["group"] == GROUPS[0]); n_hij = sum(1 for i in ITEMS if i["group"] == GROUPS[1])
    junk = sum(i["size"] for i in ITEMS if i["group"] == GROUPS[4] and i["checked"]); hi = sum(1 for e in EXPOSURE if e["risk"] == "high")
    cards = ("<div class='cards'><div class='card'><div class='k'>Malware / suspicious files</div><div class='v %s'>%d</div></div><div class='card'><div class='k'>Hidden hijacks</div><div class='v %s'>%d</div></div>"
             "<div class='card'><div class='k'>Junk you can free</div><div class='v'>%s</div></div><div class='card'><div class='k'>High-risk ways in/out</div><div class='v %s'>%d</div></div></div>" % (
                 "fail" if n_mal else "ok", n_mal, "fail" if n_hij else "ok", n_hij, human(junk), "fail" if hi else "ok", hi))
    s = HOGS.get("system") or {}
    hog = ""
    if s:
        mb = lambda v: human(v); cp = lambda v: "%.0f%%" % v; dk = lambda v: human(v) + "/s"
        hog = ("<h2>📈 Why is Task Manager at 100%%?</h2><div class='panel'><div class='hero'>%s%s<div>%s</div></div></div><div class='grid2'><div class='panel'><h3>Most CPU</h3>%s</div><div class='panel'><h3>Most memory</h3>%s</div><div class='panel'><h3>Most disk activity</h3>%s</div></div>" % (
            ch.donut(s.get("cpu", 0), "CPU", "busy now", 130), ch.donut(s.get("ram", 0), "RAM", "used", 130), "".join("<p>• %s</p>" % E(w) for w in HOGS["why"]),
            hog_table(HOGS["top_cpu"], "cpu", cp), hog_table(HOGS["top_ram"], "mem", mb), hog_table(HOGS["top_disk"], "disk", dk)))
    ex_rows = "".join("<tr><td><b>%s</b></td><td>%s</td><td class='fix'>%s</td><td><span class='b %s'>%s</span></td><td class='fix'>%s</td></tr>" % ("⬇ IN" if e["dir"] == "IN" else "⬆ OUT", E(e["what"]), E(e["evidence"]), RB[e["risk"]], e["risk"].upper(), E(e["fix"])) for e in sorted(EXPOSURE, key=lambda e: -{"low": 0, "medium": 1, "high": 2}[e["risk"]]))
    exp = ("<h2>🕸 Where can you be hacked, and where does your data leave?</h2><div class='panel'>%s</div><div style='max-height:460px;overflow:auto'><table><tr><th>Direction</th><th>What</th><th>Evidence / path</th><th>Risk</th><th>Fix</th></tr>%s</table></div>" % (exposure_svg(), ex_rows or "<tr><td colspan=5>Nothing found.</td></tr>")) if EXPOSURE else ""
    secs = []
    for g in GROUPS:
        its = [i for i in ITEMS if i["group"] == g]
        if not its: continue
        rows = "".join("<tr id='r_%s'><td><input type='checkbox' class='ck' data-id='%s' data-size='%d' %s></td><td><b>%s</b> <span class='b %s'>%s</span><div class='fix'>%s</div>%s%s</td><td class='res' id='res_%s'></td></tr>" % (
            i["id"], i["id"], i["size"], "checked" if i["checked"] else "", E(i["title"]), RB[i["risk"]], RLAB[i["risk"]], E(i["detail"]),
            ("<div class='fix'>➜ %s</div>" % E(i["why"])) if i["why"] else "", ("<div class='note'>📍 Where it came from: %s</div>" % E(i["origin"])) if i["origin"] else "", i["id"]) for i in sorted(its, key=lambda i: ({"high": 0, "medium": 1, "low": 2}[i["risk"]], -i["size"])))
        secs.append("<h2>%s %s <span class='tag'>%d</span></h2><div class='fix'><label><input type='checkbox' onclick=\"tick('%s',this.checked)\"> select / unselect all in this group</label></div><table class='grp' data-g='%s'><tr><th style='width:34px'></th><th>What</th><th style='width:260px'>Result</th></tr>%s</table>" % (GICON.get(g, ""), E(g), len(its), E(g).replace("'", ""), E(g), rows))
    bar = ("<div id='bar'><div><b id='cnt'>0</b> selected &middot; frees about <b id='sz'>0 B</b> &nbsp;|&nbsp; "
           "<label><input type='radio' name='mode' value='quarantine' checked> Quarantine (safe, undoable)</label> "
           "<label><input type='radio' name='mode' value='delete'> Delete malware permanently</label> "
           "<label><input type='checkbox' id='rp' checked> Create restore point first</label> &nbsp; Type <b>CLEAN</b>: <input id='conf' size=6 autocomplete=off></div>"
           "<div><button id='go' onclick='go()'>✅ Approve &amp; clean selected</button> <button class='alt' onclick='undo()'>↩ Undo everything</button></div></div><pre id='log'></pre>")
    dry = "<div class='demo'>DRY RUN: nothing will be changed on this computer (test mode / not Windows).</div>" if C.DRY else ""
    css = ("<style>#bar{position:sticky;bottom:0;background:var(--card);border-top:3px solid var(--brand);padding:10px 5vw;display:flex;flex-wrap:wrap;gap:10px;justify-content:space-between;align-items:center;z-index:9;margin:20px -5vw 0}"
           "#log{background:#0b1020;color:#c9d4ff;padding:12px;border-radius:10px;max-height:260px;overflow:auto;font-size:12px;white-space:pre-wrap;display:none}.res{font-size:12px}.res.ok{color:var(--ok)}.res.bad{color:var(--fail)}label{margin-right:8px}</style>")
    js = ("<script>const TOKEN=%s;"
          "function tick(g,v){document.querySelectorAll('table.grp[data-g=\"'+g+'\"] .ck').forEach(c=>c.checked=v);upd()}"
          "function upd(){let n=0,s=0;document.querySelectorAll('.ck:checked').forEach(c=>{n++;s+=+c.dataset.size});document.getElementById('cnt').textContent=n;document.getElementById('sz').textContent=(s/1048576).toFixed(0)+' MB'}"
          "document.addEventListener('change',e=>{if(e.target.classList.contains('ck'))upd()});upd();"
          "async function api(p,b){const r=await fetch(p,{method:'POST',headers:{'Content-Type':'application/json','X-FTL-Token':TOKEN},body:JSON.stringify(b||{})});return r.json()}"
          "async function go(){const ids=[...document.querySelectorAll('.ck:checked')].map(c=>c.dataset.id);if(!ids.length){alert('Nothing selected.');return}"
          "const conf=document.getElementById('conf').value.trim();if(conf!=='CLEAN'){alert('Type CLEAN in the box to approve.');return}"
          "const mode=document.querySelector('input[name=mode]:checked').value;"
          "if(!confirm('Apply '+ids.length+' change(s)? '+(mode==='delete'?'Malware will be DELETED permanently.':'Malware will be moved to quarantine.'))) return;"
          "document.getElementById('go').disabled=true;document.getElementById('log').style.display='block';"
          "const r=await api('/api/clean',{ids:ids,mode:mode,restore:document.getElementById('rp').checked,confirm:conf});if(r.error){alert(r.error);document.getElementById('go').disabled=false;return}poll()}"
          "async function poll(){const r=await (await fetch('/api/progress')).json();document.getElementById('log').textContent=r.log.join('\\n');document.getElementById('log').scrollTop=1e9;"
          "for(const [id,v] of Object.entries(r.items)){const el=document.getElementById('res_'+id);if(el&&v.state!=='pending'){el.textContent=(v.state==='done'?'✔ ':'✖ ')+v.result;el.className='res '+(v.state==='done'?'ok':'bad')}}"
          "document.getElementById('cnt').textContent=r.state.done+'/'+r.state.total+' done';if(r.state.running)setTimeout(poll,1200);else{document.getElementById('go').disabled=false;if(r.state.finished)document.getElementById('sz').textContent=(r.state.freed/1048576).toFixed(0)+' MB freed'}}"
          "async function undo(){if(!confirm('Undo everything done in this session (restore quarantined files, registry values, tasks...)?'))return;const r=await api('/api/undo');alert(r.result);poll()}"
          "</script>" % json.dumps(TOKEN))
    intro = ("<div class='panel'><b>How this works.</b> Everything below was found by scanning your laptop; <b>nothing has been changed yet.</b> Red items are dangerous and pre-selected, orange items need your judgement, "
             "green items are safe junk. Untick anything you want to keep, type <b>CLEAN</b>, press <b>Approve</b>. Malware is <b>quarantined</b> (made harmless, can be restored) unless you choose permanent delete. "
             "Registry values, tasks and hosts-file lines are backed up first, and a Windows restore point is created.</div>")
    body = dry + FT.header(subtitle) + "<main><div style='height:16px'></div>" + intro + cards + hog + "".join(secs[:4]) + exp + "".join(secs[4:]) + bar + "</main>" + FT.footer()
    return FT.page("Find the Laptop - Cleanup", body + css + js, "")


def serve(page_html, port=0):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _host_ok(self): return self.headers.get("Host", "") in ("127.0.0.1:%d" % self.server.server_address[1], "localhost:%d" % self.server.server_address[1])
        def _send(self, code, body, ctype="application/json"):
            b = body if isinstance(body, bytes) else body.encode("utf-8")
            self.send_response(code); self.send_header("Content-Type", ctype + "; charset=utf-8"); self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store"); self.send_header("X-Frame-Options", "DENY"); self.send_header("Content-Security-Policy", "frame-ancestors 'none'"); self.end_headers(); self.wfile.write(b)
        def do_GET(self):
            if not self._host_ok(): return self._send(403, "{}")
            if self.path in ("/", "/cleanup.html"): return self._send(200, page_html, "text/html")
            if self.path == "/api/progress":
                with C.LOG_LOCK: lg = list(C.LOG)[-250:]
                return self._send(200, json.dumps({"state": A.STATE, "log": lg, "items": {i["id"]: {"state": i["state"], "result": i["result"]} for i in ITEMS}}))
            self._send(404, "{}")
        def do_POST(self):
            if not self._host_ok(): return self._send(403, "{}")
            org = self.headers.get("Origin")
            if org and org not in ("http://127.0.0.1:%d" % self.server.server_address[1], "http://localhost:%d" % self.server.server_address[1]): return self._send(403, "{}")
            if not secrets.compare_digest(self.headers.get("X-FTL-Token", ""), TOKEN): return self._send(403, json.dumps({"error": "bad token"}))
            try:
                n = int(self.headers.get("Content-Length", "0")); data = json.loads(self.rfile.read(min(n, 1 << 20)) or b"{}")
            except Exception:
                return self._send(400, json.dumps({"error": "bad request"}))
            if self.path == "/api/clean":
                if data.get("confirm") != "CLEAN": return self._send(200, json.dumps({"error": "Type CLEAN to confirm."}))
                if A.STATE["running"]: return self._send(200, json.dumps({"error": "A cleanup is already running."}))
                ids = [i for i in data.get("ids", []) if isinstance(i, str)]
                A.run_items(ids, data.get("mode", "quarantine"), bool(data.get("restore", True)))
                return self._send(200, json.dumps({"started": True}))
            if self.path == "/api/undo": return self._send(200, json.dumps({"result": A.undo_all()}))
            if self.path == "/api/open":
                it = C.by_id(str(data.get("id")))
                p = (it or {}).get("params", {}).get("path")
                if p and C.IS_WIN and os.path.exists(p): subprocess.Popen(["explorer", "/select,", p])
                return self._send(200, "{}")
            self._send(404, "{}")
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d/cleanup.html" % srv.server_address[1]
