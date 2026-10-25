// Safe DOM helpers: all dynamic text goes through textContent, never innerHTML.
export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'html') throw new Error('html attribute is not allowed');
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

export async function api(path, opts = {}) {
  let res;
  try {
    res = await fetch('/api' + path, {
      method: opts.method || 'GET',
      headers: opts.body !== undefined ? { 'Content-Type': 'application/json' } : {},
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
  } catch {
    throw new Error('Cannot reach the ExamShield server. Check that "python run.py" is still running.');
  }
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON */ }
  if (!res.ok) throw new Error(data?.error?.message || `Request failed (${res.status}).`);
  return data;
}

export function toast(msg, kind = 'ok') {
  const t = h('div', { class: 'toast ' + kind, role: 'status' }, msg);
  document.getElementById('toasts').append(t);
  setTimeout(() => t.remove(), 4200);
}

export async function withBusy(btn, fn) {
  btn.disabled = true; btn.classList.add('busy');
  try { return await fn(); }
  catch (e) { toast(e.message, 'bad'); throw e; }
  finally { btn.disabled = false; btn.classList.remove('busy'); }
}

export const pct = v => (v == null ? 'n/a' : (v * 100).toFixed(1) + '%');
export const num = v => (v == null ? 'n/a' : String(v));
export const when = iso => { try { return new Date(iso).toLocaleString(); } catch { return iso; } };
export const badge = (text, cls) => h('span', { class: 'badge ' + cls }, text);
export const riskBadge = r => badge(r[0].toUpperCase() + r.slice(1), 'b-' + r);
export const decBadge = d => badge(d === 'allow' ? 'Allowed' : 'Denied', d === 'allow' ? 'b-allow' : 'b-deny');
export const empty = (msg, action) => h('div', { class: 'empty' }, msg, action ? h('div', { style: 'margin-top:12px' }, action) : null);
export const loading = () => h('div', { class: 'empty' }, 'Loading…');
export const errorBox = msg => h('div', { class: 'err', role: 'alert' }, msg);

const RANK = { low: 0, medium: 1, high: 2, critical: 3 };
// Render text with finding spans highlighted (overlaps merged, strongest severity wins).
export function highlight(text, findings) {
  const spans = findings.filter(f => f.end > f.start).map(f => ({ s: f.start, e: f.end, sev: f.severity, q: f.quoted }))
    .sort((a, b) => a.s - b.s || b.e - a.e);
  const merged = [];
  for (const sp of spans) {
    const last = merged[merged.length - 1];
    if (last && sp.s < last.e) {
      last.e = Math.max(last.e, sp.e);
      if (!sp.q) { last.q = false; if (RANK[sp.sev] > RANK[last.sev]) last.sev = sp.sev; }
    } else merged.push({ ...sp });
  }
  const out = []; let pos = 0;
  for (const m of merged) {
    if (m.s > pos) out.push(text.slice(pos, m.s));
    out.push(h('mark', { class: m.q ? 'quoted' : 's-' + m.sev, title: m.q ? 'Quoted or educational context' : 'Severity: ' + m.sev }, text.slice(m.s, m.e)));
    pos = m.e;
  }
  if (pos < text.length) out.push(text.slice(pos));
  return out;
}

const NS = 'http://www.w3.org/2000/svg';
const s = (tag, attrs = {}, text) => { const e = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); if (text != null) e.textContent = text; return e; };

// Horizontal bar chart. items: [{label, value, max?, color, valueLabel?}]
export function barChart(items, { width = 560, max = null } = {}) {
  const rowH = 34, lw = 170, w = width, top = 4;
  const m = max ?? Math.max(1, ...items.map(i => i.value || 0));
  const svg = s('svg', { viewBox: `0 0 ${w} ${items.length * rowH + 8}`, width: '100%', role: 'img' });
  items.forEach((it, i) => {
    const y = top + i * rowH, bw = Math.max(0, ((it.value || 0) / m) * (w - lw - 70));
    svg.append(s('text', { x: 0, y: y + 19, fill: '#c9d4f5', 'font-size': 14 }, it.label));
    svg.append(s('rect', { x: lw, y: y + 5, width: w - lw - 70, height: 16, rx: 5, fill: '#ffffff10' }));
    svg.append(s('rect', { x: lw, y: y + 5, width: bw, height: 16, rx: 5, fill: it.color || '#27d7f5' }));
    svg.append(s('text', { x: w - 62, y: y + 19, fill: '#e8eeff', 'font-size': 14, 'font-weight': 600 }, it.valueLabel ?? String(it.value)));
  });
  return svg;
}

// Confusion matrix 2x2.
export function confusion(c) {
  const svg = s('svg', { viewBox: '0 0 360 250', width: '100%', role: 'img' });
  const cells = [[c.tp, 'True positive', '#36d399', 70, 40], [c.fn, 'False negative', '#ff5470', 215, 40], [c.fp, 'False positive', '#f5b84a', 70, 135], [c.tn, 'True negative', '#3d7bff', 215, 135]];
  svg.append(s('text', { x: 142, y: 18, fill: '#8a9ac2', 'font-size': 13, 'text-anchor': 'middle' }, 'Flagged'));
  svg.append(s('text', { x: 287, y: 18, fill: '#8a9ac2', 'font-size': 13, 'text-anchor': 'middle' }, 'Not flagged'));
  svg.append(s('text', { x: 62, y: 90, fill: '#8a9ac2', 'font-size': 13, 'text-anchor': 'end' }, 'Malicious'));
  svg.append(s('text', { x: 62, y: 185, fill: '#8a9ac2', 'font-size': 13, 'text-anchor': 'end' }, 'Benign'));
  for (const [v, l, col, x, y] of cells) {
    svg.append(s('rect', { x, y, width: 140, height: 86, rx: 10, fill: col, 'fill-opacity': .16, stroke: col, 'stroke-opacity': .7 }));
    svg.append(s('text', { x: x + 70, y: y + 42, fill: '#e8eeff', 'font-size': 32, 'font-weight': 700, 'text-anchor': 'middle' }, String(v)));
    svg.append(s('text', { x: x + 70, y: y + 66, fill: '#c9d4f5', 'font-size': 13, 'text-anchor': 'middle' }, l));
  }
  return svg;
}

// Stacked bar per pattern: segments [{value,color}]
export function stacked(rows, width = 560) {
  const rowH = 30, lw = 190, w = width;
  const mx = Math.max(1, ...rows.map(r => r.segs.reduce((a, b) => a + b.value, 0)));
  const svg = s('svg', { viewBox: `0 0 ${w} ${rows.length * rowH + 6}`, width: '100%', role: 'img' });
  rows.forEach((r, i) => {
    const y = i * rowH;
    svg.append(s('text', { x: 0, y: y + 19, fill: '#c9d4f5', 'font-size': 13 }, r.label));
    let x = lw;
    for (const sg of r.segs) {
      const bw = (sg.value / mx) * (w - lw - 10);
      if (bw > 0) { svg.append(s('rect', { x, y: y + 5, width: bw, height: 16, fill: sg.color, rx: 3 })); x += bw; }
    }
  });
  return svg;
}
