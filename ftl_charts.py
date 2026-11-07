# -*- coding: utf-8 -*-
"""Pure-SVG charts (no internet, no libraries). Colours come from CSS variables so dark mode works."""
import html, math

E = lambda s: html.escape(str(s))


def col(p):
    return "var(--ok)" if p >= 80 else "var(--warn)" if p >= 55 else "var(--fail)"


def donut(pct, label, sub="", size=170):
    r = 62; c = 2 * math.pi * r
    pct = 0 if pct is None else max(0, min(100, pct))
    dash = c * pct / 100
    return ("<svg viewBox='0 0 170 170' width='%d' height='%d' role='img' aria-label='%s %d%%'>"
            "<circle cx='85' cy='85' r='%d' fill='none' style='stroke:var(--line)' stroke-width='16'/>"
            "<circle cx='85' cy='85' r='%d' fill='none' style='stroke:%s' stroke-width='16' stroke-linecap='round' "
            "stroke-dasharray='%.1f %.1f' transform='rotate(-90 85 85)'/>"
            "<text x='85' y='88' text-anchor='middle' style='fill:var(--text)' font-size='34' font-weight='700'>%d%%</text>"
            "<text x='85' y='110' text-anchor='middle' style='fill:var(--muted)' font-size='12'>%s</text></svg>"
            % (size, size, E(label), pct, r, r, col(pct), dash, c - dash, round(pct), E(sub)))


def hbars(rows, width=640):
    """rows: [(label, pct or None, note)] -> horizontal bar chart. None = no software-visible value."""
    rh, lw = 30, 190
    h = rh * len(rows) + 10
    bw = width - lw - 70
    o = ["<svg viewBox='0 0 %d %d' width='100%%' role='img' aria-label='Component health'>" % (width, h)]
    for i, row in enumerate(rows):
        lab, p, note = row[:3]; soft = len(row) > 3 and row[3] == 'software'
        y = i * rh + 6
        o.append("<text x='0' y='%d' font-size='13' style='fill:var(--text)'>%s</text>" % (y + 15, E(lab)))
        o.append("<rect x='%d' y='%d' width='%d' height='16' rx='8' style='fill:var(--line)'/>" % (lw, y + 3, bw))
        if p is None:
            o.append("<text x='%d' y='%d' font-size='12' style='fill:var(--muted)'>%s</text>" % (lw + 8, y + 16, E(note or "no data")))
        else:
            o.append("<rect x='%d' y='%d' width='%.1f' height='16' rx='8' style='fill:%s;opacity:%s'/>" % (lw, y + 3, max(bw * p / 100, 4), col(p), '.55' if soft else '1'))
            o.append("<text x='%d' y='%d' font-size='13' font-weight='700' style='fill:var(--text)'>%d%%%s</text>" % (lw + bw + 8, y + 16, round(p), '*' if soft else ''))
    o.append("</svg>")
    return "".join(o)


def pie(slices, size=170):
    """slices: [(label, count, cssColour)]"""
    tot = sum(c for _, c, _ in slices) or 1
    r, a0, parts = 70, -math.pi / 2, []
    for lab, c, colr in slices:
        if c <= 0:
            continue
        a1 = a0 + 2 * math.pi * c / tot
        if c == tot:
            parts.append("<circle cx='85' cy='85' r='%d' style='fill:%s'/>" % (r, colr))
        else:
            x0, y0, x1, y1 = 85 + r * math.cos(a0), 85 + r * math.sin(a0), 85 + r * math.cos(a1), 85 + r * math.sin(a1)
            parts.append("<path d='M85 85 L%.1f %.1f A%d %d 0 %d 1 %.1f %.1f Z' style='fill:%s'/>" % (x0, y0, r, r, 1 if a1 - a0 > math.pi else 0, x1, y1, colr))
        a0 = a1
    parts.append("<circle cx='85' cy='85' r='36' style='fill:var(--card)'/><text x='85' y='91' text-anchor='middle' font-size='22' font-weight='700' style='fill:var(--text)'>%d</text>" % tot)
    legend = "".join("<span style='margin-right:12px'><i style='display:inline-block;width:10px;height:10px;border-radius:3px;background:%s'></i> %s %d</span>" % (c, E(l), n) for l, n, c in slices)
    return "<svg viewBox='0 0 170 170' width='%d' height='%d'>%s</svg><div class='fix'>%s</div>" % (size, size, "".join(parts), legend)


def line(points, unit="", width=640, height=220, title=""):
    """points: [(label, value)]"""
    if len(points) < 2:
        return "<p class='fix'>Not enough history to draw a graph.</p>"
    L, R, T, B = 48, 14, 14, 34
    vals = [v for _, v in points]
    lo, hi = min(vals), max(vals)
    if hi == lo:
        hi, lo = hi + 1, lo - 1
    pad = (hi - lo) * 0.15; lo, hi = max(0, lo - pad), hi + pad
    X = lambda i: L + (width - L - R) * i / (len(points) - 1)
    Y = lambda v: T + (height - T - B) * (1 - (v - lo) / (hi - lo))
    pts = " ".join("%.1f,%.1f" % (X(i), Y(v)) for i, (_, v) in enumerate(points))
    o = ["<svg viewBox='0 0 %d %d' width='100%%' role='img' aria-label='%s'>" % (width, height, E(title))]
    for k in range(5):
        v = lo + (hi - lo) * k / 4; y = Y(v)
        o.append("<line x1='%d' x2='%d' y1='%.1f' y2='%.1f' style='stroke:var(--line)'/><text x='%d' y='%.1f' font-size='11' text-anchor='end' style='fill:var(--muted)'>%s</text>" % (L, width - R, y, y, L - 6, y + 4, ("%d" % v) + unit))
    step = max(1, len(points) // 6)
    for i in range(0, len(points), step):
        o.append("<text x='%.1f' y='%d' font-size='11' text-anchor='middle' style='fill:var(--muted)'>%s</text>" % (X(i), height - 10, E(points[i][0][:10])))
    o.append("<polyline points='%s' fill='none' style='stroke:var(--brand)' stroke-width='3' stroke-linejoin='round'/>" % pts)
    o.append("<circle cx='%.1f' cy='%.1f' r='4' style='fill:var(--brand)'/></svg>" % (X(len(points) - 1), Y(points[-1][1])))
    return "".join(o)


def vbars(rows, unit=" mo", width=640, height=230):
    """rows: [(label, value)] -> vertical bars (months in service)"""
    rows = [(l, v) for l, v in rows if v is not None]
    if not rows:
        return "<p class='fix'>Windows did not expose first-use dates for these parts.</p>"
    mx = max(v for _, v in rows) or 1
    n = len(rows); L, B, T = 70, 56, 22
    bw = (width - L * 2) / n
    o = ["<svg viewBox='0 0 %d %d' width='100%%' role='img' aria-label='Months in service'>" % (width, height)]
    for i, (lab, v) in enumerate(rows):
        h = (height - B - T) * v / mx; x = L + i * bw + bw * 0.15; w = bw * 0.7
        o.append("<rect x='%.1f' y='%.1f' width='%.1f' height='%.1f' rx='5' style='fill:var(--brand)'/>" % (x, height - B - h, w, max(h, 2)))
        o.append("<text x='%.1f' y='%.1f' font-size='12' font-weight='700' text-anchor='middle' style='fill:var(--text)'>%s</text>" % (x + w / 2, height - B - h - 5, ("%.0f" % v) + unit))
        o.append("<text x='%.1f' y='%d' font-size='11' text-anchor='end' transform='rotate(-30 %.1f %d)' style='fill:var(--muted)'>%s</text>" % (x + w / 2 + 6, height - B + 16, x + w / 2 + 6, height - B + 16, E(lab[:16])))
    o.append("</svg>")
    return "".join(o)


def stack(rows, width=640):
    """rows: [(label, used_pct, text)] disk-usage bars"""
    o = []
    for lab, used, txt in rows:
        o.append("<div style='margin:8px 0'><div style='display:flex;justify-content:space-between;font-size:13px'><b>%s</b><span class='fix'>%s</span></div>"
                 "<div class='bar'><i style='width:%d%%;background:%s'></i></div></div>" % (E(lab), E(txt), used, col(100 - used if used > 85 else 100)))
    return "".join(o)


def cores(vals):
    if not vals:
        return ""
    w = 640; n = len(vals); bw = (w - 20) / n; h = 120
    o = ["<svg viewBox='0 0 %d %d' width='100%%' role='img' aria-label='CPU load per core'>" % (w, h + 28)]
    for i, v in enumerate(vals):
        x = 10 + i * bw + 4; bh = (h - 10) * v / 100
        o.append("<rect x='%.1f' y='%.1f' width='%.1f' height='%.1f' rx='4' style='fill:%s'/>" % (x, h - bh, bw - 8, max(bh, 2), col(100 - v if v > 70 else 100)))
        o.append("<text x='%.1f' y='%d' font-size='10' text-anchor='middle' style='fill:var(--muted)'>C%d</text>" % (x + (bw - 8) / 2, h + 14, i))
    o.append("</svg>")
    return "".join(o)
