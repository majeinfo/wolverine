// Wolverine dashboard: reads the REST API of the embedded server and
// follows /api/v1/alerts/watch for the alerts raised. Every value coming from
// the API (rule ids, log lines...) is inserted with textContent: log lines
// are attacker-controlled.
"use strict";

(function () {
  const SVG = "http://www.w3.org/2000/svg";
  const SLOTS = 8; // categorical palette size: more series fold into "Other"
  const MAX_FEED = 200;
  const RANGES = { "5m": 5 * 60, "15m": 15 * 60, "1h": 3600, "6h": 6 * 3600, "24h": 24 * 3600 };

  const $ = (id) => document.getElementById(id);
  const fmt = new Intl.NumberFormat();
  const fmt1 = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });

  // fmtBytes gives a size in bytes with a binary unit: 1.2 MiB.
  function fmtBytes(n) {
    n = n || 0;
    const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (i === 0 ? fmt.format(n) : fmt1.format(n)) + " " + units[i];
  }
  const state = {
    info: null,
    range: "1h",
    refresh: 30,
    timer: null,
    token: "",
    feed: [],          // alerts shown, newest first
    feedIDs: new Set(),
    open: new Set(),   // alerts whose details are shown
    watchAbort: null,
  };

  // --- storage (may be unavailable) ---------------------------------------
  var storage;
  function makeStorage() {
    return {
      get(k) { try { return window.localStorage.getItem(k); } catch (e) { return null; } },
      set(k, v) { try { window.localStorage.setItem(k, v); } catch (e) { /* ignored */ } },
      del(k) { try { window.localStorage.removeItem(k); } catch (e) { /* ignored */ } },
    };
  }

  // --- API -----------------------------------------------------------------
  class AuthError extends Error {}

  function headers() {
    return state.token ? { Authorization: "Bearer " + state.token } : {};
  }

  async function api(path) {
    const resp = await fetch(path, { headers: headers(), cache: "no-store" });
    if (resp.status === 401) throw new AuthError("token required");
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(body.error || resp.status + " " + resp.statusText);
    return body;
  }

  function askToken() {
    const dlg = $("login");
    if (dlg.open) return;
    $("token").value = "";
    dlg.showModal();
  }

  // --- colors --------------------------------------------------------------
  // Color follows the entity: its position in the configuration, never its
  // rank in the data.
  function slotColor(i) { return "var(--series-" + (i + 1) + ")"; }

  // groups maps ids (in configuration order) to series; past SLOTS, the
  // last slot becomes "Other".
  function categorical(ids) {
    const map = new Map();
    const fold = ids.length > SLOTS;
    ids.forEach((id, i) => {
      if (fold && i >= SLOTS - 1) map.set(id, { name: "Other", color: "var(--series-other)" });
      else map.set(id, { name: id, color: slotColor(i) });
    });
    return map;
  }

  // --- formatting ----------------------------------------------------------
  function timeLabel(d, withDate, withSeconds) {
    const hm = d.toLocaleTimeString([], withSeconds ? { hour: "2-digit", minute: "2-digit", second: "2-digit" } : { hour: "2-digit", minute: "2-digit" });
    if (!withDate) return hm;
    return d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + hm;
  }

  function stepLabel(seconds) {
    if (seconds % 3600 === 0) return seconds / 3600 + "h";
    if (seconds % 60 === 0) return seconds / 60 + "m";
    return seconds + "s";
  }

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function svg(tag, attrs) {
    const e = document.createElementNS(SVG, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }

  function severityLevel(s) {
    switch ((s || "").toLowerCase()) {
      case "critical": return ["critical", "▲"];
      case "high": return ["serious", "◆"];
      case "medium": return ["warning", "●"];
      default: return ["info", "○"];
    }
  }

  function severityBadge(s) {
    const [level, icon] = severityLevel(s);
    const b = el("span", "severity");
    b.dataset.level = level;
    b.append(el("span", "severity-icon", icon), document.createTextNode(s || "–"));
    return b;
  }

  // --- tooltip -------------------------------------------------------------
  const tooltip = {
    show(x, y, title, rows) {
      const t = $("tooltip");
      t.replaceChildren(el("div", "tooltip-title", title));
      for (const r of rows) {
        const row = el("div", "tooltip-row");
        const key = el("span", "key-line");
        key.style.background = r.color;
        row.append(key, el("span", "tooltip-value", fmt.format(r.value)), el("span", "tooltip-name", r.name));
        t.append(row);
      }
      t.hidden = false;
      const w = t.offsetWidth, h = t.offsetHeight;
      let left = x + 14, top = y + 14;
      if (left + w > window.innerWidth - 8) left = x - w - 14;
      if (top + h > window.innerHeight - 8) top = y - h - 14;
      t.style.left = Math.max(8, left) + "px";
      t.style.top = Math.max(8, top) + "px";
    },
    hide() { $("tooltip").hidden = true; },
  };

  // --- charts --------------------------------------------------------------
  // A chart draws series (name, color, values[]) over the bucket times, as
  // stacked bars or lines, with one y axis from 0.
  function niceMax(v) {
    if (v <= 0) return 4;
    const exp = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 2, 2.5, 5, 10]) {
      if (m * exp >= v) return Math.max(4, m * exp);
    }
    return 10 * exp;
  }

  // The series hidden from each chart by a click in its legend, by chart id,
  // remembered in this browser.
  const hiddenSeries = (() => {
    try {
      const saved = JSON.parse(localStorage.getItem("wolverine.hiddenSeries") || "{}");
      const m = {};
      for (const k of Object.keys(saved)) if (Array.isArray(saved[k])) m[k] = new Set(saved[k]);
      return m;
    } catch (e) { return {}; }
  })();
  function saveHiddenSeries() {
    try {
      const o = {};
      for (const k of Object.keys(hiddenSeries)) if (hiddenSeries[k].size) o[k] = Array.from(hiddenSeries[k]);
      localStorage.setItem("wolverine.hiddenSeries", JSON.stringify(o));
    } catch (e) { /* not remembered */ }
  }

  function drawChart(container, times, allSeries, opts) {
    const legendNeeded = allSeries.length >= 2;
    // Hidden series are left out of the plot (and of its scale and tooltip)
    // but stay in the legend, dimmed, to be shown again.
    const hidden = (legendNeeded && hiddenSeries[container.id]) || new Set();
    const series = allSeries.filter((s) => !hidden.has(s.name));
    container.replaceChildren();
    const width = container.clientWidth || 600;
    const height = container.clientHeight || 240;
    const legendH = legendNeeded ? 26 : 0;
    const m = { top: 8, right: opts.kind === "line" && series.length <= 4 ? 72 : 12, bottom: 22 + legendH, left: 44 };
    const w = Math.max(10, width - m.left - m.right);
    const h = Math.max(10, height - m.top - m.bottom);
    const root = svg("svg", { viewBox: "0 0 " + width + " " + (height - legendH), role: "img" });
    root.setAttribute("aria-label", opts.label);
    root.style.height = (height - legendH) + "px";
    const g = svg("g", { transform: "translate(" + m.left + "," + m.top + ")" });
    root.append(g);
    container.append(root);

    const n = times.length;
    let maxV = 0;
    for (let i = 0; i < n; i++) {
      if (opts.kind === "bar") {
        let sum = 0;
        for (const s of series) sum += s.values[i];
        maxV = Math.max(maxV, sum);
      } else {
        for (const s of series) maxV = Math.max(maxV, s.values[i]);
      }
    }
    const top = niceMax(maxV);
    const y = (v) => h - (v / top) * h;
    const band = w / Math.max(1, n);
    const xCenter = (i) => band * i + band / 2;

    // Grid and y ticks.
    for (let k = 0; k <= 4; k++) {
      const v = (top / 4) * k;
      const yy = Math.round(y(v)) + 0.5;
      g.append(svg("line", { class: k === 0 ? "baseline" : "gridline", x1: 0, x2: w, y1: yy, y2: yy }));
      const t = svg("text", { class: "tick", x: -8, y: yy + 4, "text-anchor": "end" });
      t.textContent = Number.isInteger(v) ? fmt.format(v) : v.toFixed(1);
      g.append(t);
    }
    // X ticks: about one per 90px.
    const withDate = n > 0 && times[n - 1] - times[0] > 20 * 3600 * 1000;
    const every = Math.max(1, Math.ceil(n / Math.max(1, Math.floor(w / 90))));
    for (let i = 0; i < n; i += every) {
      const t = svg("text", { class: "tick", x: xCenter(i), y: h + 16, "text-anchor": "middle" });
      t.textContent = timeLabel(times[i], withDate);
      g.append(t);
    }

    const allZero = maxV === 0;
    if (allZero) {
      const t = svg("text", { class: "empty", x: w / 2, y: h / 2, "text-anchor": "middle" });
      t.textContent = series.length || !allSeries.length ? "Nothing in this range" : "All series hidden: click the legend to show them";
      g.append(t);
    }

    const title = (i) => {
      const end = new Date(times[i].getTime() + opts.step * 1000);
      return timeLabel(times[i], withDate) + " – " + timeLabel(end, false);
    };
    const rows = (i) => series.map((s) => ({ name: s.name, color: s.color, value: s.values[i] }));

    if (opts.kind === "bar") {
      const gap = 2;
      const bw = Math.max(1, band - gap);
      for (let i = 0; i < n; i++) {
        const col = svg("g", { class: "column" });
        let acc = 0;
        const segs = series.map((s) => s.values[i]);
        const last = segs.reduce((li, v, k) => (v > 0 ? k : li), -1);
        segs.forEach((v, k) => {
          if (v <= 0) return;
          const y0 = y(acc), y1 = y(acc + v);
          acc += v;
          const x0 = band * i + gap / 2;
          // Separate stacked segments by a surface gap; round the data end.
          const segH = Math.max(1, y0 - y1 - (k === last ? 0 : 1));
          const r = k === last ? Math.min(4, bw / 2, segH) : 0;
          const p = svg("path", { class: "bar", d: roundedTop(x0, y1, bw, segH, r) });
          p.style.fill = series[k].color;
          col.append(p);
        });
        // The hit target is the whole column, wider than the bars.
        const hit = svg("rect", { x: band * i, y: 0, width: band, height: h, fill: "transparent", tabindex: 0 });
        hit.setAttribute("aria-label", title(i) + ": " + rows(i).map((r) => r.name + " " + r.value).join(", "));
        const show = (ev) => {
          col.classList.add("hover");
          const box = hit.getBoundingClientRect();
          tooltip.show(ev.clientX !== undefined ? ev.clientX : box.right, ev.clientY !== undefined ? ev.clientY : box.top, title(i), rows(i));
        };
        hit.addEventListener("pointermove", show);
        hit.addEventListener("focus", show);
        const hide = () => { col.classList.remove("hover"); tooltip.hide(); };
        hit.addEventListener("pointerleave", hide);
        hit.addEventListener("blur", hide);
        col.append(hit);
        g.append(col);
      }
    } else {
      for (const s of series) {
        let d = "";
        s.values.forEach((v, i) => { d += (i ? "L" : "M") + xCenter(i).toFixed(1) + "," + y(v).toFixed(1); });
        const p = svg("path", { class: "series-line", d: d });
        p.style.stroke = s.color;
        g.append(p);
      }
      // Direct labels at the line ends, for a few series, without overlap.
      if (series.length <= 4 && n > 0 && !allZero) {
        const ends = series.map((s) => ({ s: s, y: y(s.values[n - 1]) })).sort((a, b) => a.y - b.y);
        // 13px apart, and above the baseline (the x ticks are below).
        let prev = -Infinity;
        for (const e of ends) { e.y = Math.max(e.y, prev + 13); prev = e.y; }
        let limit = h - 6;
        for (let k = ends.length - 1; k >= 0; k--) {
          ends[k].y = Math.min(ends[k].y, limit);
          limit = ends[k].y - 13;
        }
        for (const e of ends) {
          const yy = e.y;
          const t = svg("text", { class: "direct", x: xCenter(n - 1) + 8, y: yy + 4 });
          t.textContent = e.s.name;
          g.append(t);
        }
      }
      // Crosshair: snaps to the nearest bucket.
      const cross = svg("line", { class: "crosshair", x1: 0, x2: 0, y1: 0, y2: h, visibility: "hidden" });
      const dots = series.map((s) => {
        const c = svg("circle", { class: "dot", r: 4, visibility: "hidden" });
        c.style.fill = s.color;
        return c;
      });
      g.append(cross, ...dots);
      const overlay = svg("rect", { x: 0, y: 0, width: w, height: h, fill: "transparent", tabindex: 0 });
      overlay.setAttribute("aria-label", opts.label + ", " + n + " buckets");
      let focusIndex = n - 1;
      const at = (i, cx, cy) => {
        if (n === 0) return;
        i = Math.max(0, Math.min(n - 1, i));
        focusIndex = i;
        const xx = Math.round(xCenter(i)) + 0.5;
        cross.setAttribute("x1", xx); cross.setAttribute("x2", xx);
        cross.setAttribute("visibility", "visible");
        series.forEach((s, k) => {
          dots[k].setAttribute("cx", xCenter(i));
          dots[k].setAttribute("cy", y(s.values[i]));
          dots[k].setAttribute("visibility", "visible");
        });
        tooltip.show(cx, cy, title(i), rows(i));
      };
      overlay.addEventListener("pointermove", (ev) => {
        const box = overlay.getBoundingClientRect();
        at(Math.floor(((ev.clientX - box.left) / box.width) * n), ev.clientX, ev.clientY);
      });
      const hide = () => {
        cross.setAttribute("visibility", "hidden");
        dots.forEach((d) => d.setAttribute("visibility", "hidden"));
        tooltip.hide();
      };
      overlay.addEventListener("pointerleave", hide);
      overlay.addEventListener("blur", hide);
      overlay.addEventListener("keydown", (ev) => {
        if (ev.key !== "ArrowLeft" && ev.key !== "ArrowRight") return;
        ev.preventDefault();
        const i = focusIndex + (ev.key === "ArrowLeft" ? -1 : 1);
        const box = overlay.getBoundingClientRect();
        at(i, box.left + ((i + 0.5) / n) * box.width, box.top + 8);
      });
      overlay.addEventListener("focus", () => {
        const box = overlay.getBoundingClientRect();
        at(focusIndex, box.left + ((focusIndex + 0.5) / n) * box.width, box.top + 8);
      });
      g.append(overlay);
    }

    if (legendNeeded) {
      const legend = el("div", "legend");
      const seen = new Set();
      for (const s of allSeries) {
        if (seen.has(s.name)) continue;
        seen.add(s.name);
        // A button that hides or shows the series.
        const item = el("button", "legend-item");
        item.type = "button";
        const off = hidden.has(s.name);
        item.classList.toggle("off", off);
        item.setAttribute("aria-pressed", String(!off));
        item.title = (off ? "Show " : "Hide ") + s.name;
        const key = el("span", opts.kind === "bar" ? "key-rect" : "key-line");
        key.style.background = s.color;
        item.append(key, document.createTextNode(s.name));
        item.addEventListener("click", () => {
          const set = hiddenSeries[container.id] || (hiddenSeries[container.id] = new Set());
          if (set.has(s.name)) set.delete(s.name); else set.add(s.name);
          saveHiddenSeries();
          tooltip.hide();
          drawChart(container, times, allSeries, opts);
          // Keep the focus on the same item for the keyboard.
          const again = Array.from(container.querySelectorAll(".legend-item")).find((b) => b.dataset.name === s.name);
          if (again) again.focus();
        });
        item.dataset.name = s.name;
        legend.append(item);
      }
      container.append(legend);
    }
  }

  // roundedTop draws a bar with its top corners rounded by r.
  function roundedTop(x, y, w, h, r) {
    if (r <= 0) return "M" + x + "," + y + "h" + w + "v" + h + "h" + -w + "Z";
    return "M" + x + "," + (y + h) +
      "V" + (y + r) + "Q" + x + "," + y + " " + (x + r) + "," + y +
      "H" + (x + w - r) + "Q" + (x + w) + "," + y + " " + (x + w) + "," + (y + r) +
      "V" + (y + h) + "Z";
  }

  // seriesBy builds the series of a field of the sources or rules, folding
  // past SLOTS ids into "Other".
  function seriesBy(buckets, ids, kind, field) {
    const colors = categorical(ids);
    const byName = new Map();
    for (const id of ids) {
      const c = colors.get(id);
      if (!byName.has(c.name)) byName.set(c.name, { name: c.name, color: c.color, values: buckets.map(() => 0) });
      const s = byName.get(c.name);
      buckets.forEach((b, i) => {
        const v = b[kind] && b[kind][id];
        if (v) s.values[i] += v[field] || 0;
      });
    }
    return Array.from(byName.values());
  }

  // --- rendering -----------------------------------------------------------
  let lastSeries = null;

  function renderCharts(series) {
    lastSeries = series;
    const times = series.buckets.map((b) => new Date(b.start));
    const step = series.step_seconds;
    const per = "per " + stepLabel(step);
    const sourceIDs = state.info.sources.map((s) => s.id);
    const ruleIDs = state.info.rules.map((r) => r.id);

    $("sub-lines").textContent = "Parsed into events or not, " + per;
    drawChart($("c-lines"), times, [
      { name: "Parsed", color: slotColor(0), values: series.buckets.map((b) => b.totals.events) },
      { name: "Unparsed", color: slotColor(1), values: series.buckets.map((b) => b.totals.unparsed) },
    ], { kind: "bar", step: step, label: "Log lines " + per });

    $("sub-alerts").textContent = "Alerts raised, " + per;
    drawChart($("c-alerts"), times, ruleIDs.length ? seriesBy(series.buckets, ruleIDs, "rules", "alerts") : [],
      { kind: "bar", step: step, label: "Alerts by rule " + per });

    $("sub-matches").textContent = "Events counted by each rule, " + per;
    drawChart($("c-matches"), times, ruleIDs.length ? seriesBy(series.buckets, ruleIDs, "rules", "matches") : [],
      { kind: "line", step: step, label: "Rule matches " + per });

    $("sub-sources").textContent = "Lines read from each source, " + per;
    drawChart($("c-sources"), times, sourceIDs.length ? seriesBy(series.buckets, sourceIDs, "sources", "lines") : [],
      { kind: "line", step: step, label: "Lines by source " + per });
  }

  function renderTiles(range, total) {
    for (const k of ["lines", "events", "unparsed", "excluded", "matches", "alerts"]) {
      $("t-" + k).textContent = fmt.format(range.totals[k]);
      $("s-" + k).textContent = fmt.format(total.totals[k]) + " since start";
    }
    $("t-bytes").textContent = fmtBytes(range.totals.bytes);
    $("t-bytes").title = fmt.format(range.totals.bytes || 0) + " bytes";
    $("s-bytes").textContent = fmtBytes(total.totals.bytes) + " since start";
  }

  function cell(text, cls) { return el("td", cls, text); }

  function renderTables(range) {
    const srcColors = categorical(state.info.sources.map((s) => s.id));
    const rows = state.info.sources.map((s) => {
      const c = range.sources[s.id] || {};
      const tr = el("tr");
      const name = el("td", "key");
      const key = el("span", "key-line");
      key.style.background = srcColors.get(s.id).color;
      name.append(key, document.createTextNode(s.id));
      tr.append(name, cell(s.type, "muted"), cell(fmt.format(c.lines || 0), "num"), cell(fmtBytes(c.bytes), "num"), cell(fmt.format(c.events || 0), "num"),
        cell(fmt.format(c.unparsed || 0), "num"), cell(fmt.format(c.excluded || 0), "num"));
      return tr;
    });
    $("sources").replaceChildren(...rows);

    const ruleColors = categorical(state.info.rules.map((r) => r.id));
    const ruleRows = state.info.rules.map((r) => {
      const c = range.rules[r.id] || {};
      const tr = el("tr");
      const name = el("td");
      const top = el("div", "key-cell");
      const key = el("span", "key-rect");
      key.style.background = ruleColors.get(r.id).color;
      key.style.display = "inline-block";
      key.style.marginRight = "8px";
      top.append(key, document.createTextNode(r.id));
      name.append(top);
      if (r.description) name.append(el("div", "muted", r.description));
      const sev = el("td");
      sev.append(severityBadge(r.severity));
      tr.append(name, sev, cell(fmt.format(c.matches || 0), "num"), cell(fmt.format(c.alerts || 0), "num"));
      return tr;
    });
    if (!ruleRows.length) {
      const tr = el("tr");
      const td = cell("No enabled rule", "muted");
      td.colSpan = 4;
      tr.append(td);
      ruleRows.push(tr);
    }
    $("rules").replaceChildren(...ruleRows);
  }

  // --- action log ----------------------------------------------------------
  // The status of an action run: its level (for the icon color), icon and
  // label. Never color alone: the label always says it.
  const ACTION_STATUS = {
    ok: ["good", "✓", "done"],
    failed: ["critical", "✕", "failed"],
    dropped: ["critical", "✕", "dropped"],
    planned: ["pending", "◷", "planned"],
    postponed: ["pending", "↷", "postponed"],
    skipped: ["info", "–", "skipped"],
  };

  function actionStatus(run, withDue) {
    const [level, icon, label] = ACTION_STATUS[run.Status] || ["info", "?", run.Status || "?"];
    const b = el("span", "status");
    b.dataset.level = level;
    let text = label;
    if (withDue && run.Due && (run.Status === "planned" || run.Status === "failed")) {
      text += (run.Status === "failed" ? ", retry " : " ") + timeLabel(new Date(run.Due), !sameDay(new Date(run.Due)), true);
    }
    b.append(el("span", "status-icon", icon), document.createTextNode(text));
    return b;
  }

  function sameDay(d) { return d.toDateString() === new Date().toDateString(); }

  function actionName(run) { return run.UndoOf ? run.Action + " (undo)" : run.Action; }

  // latestRuns returns the last run of each action (an undo action apart
  // from the same action run directly), in the order they first appear.
  function latestRuns(runs) {
    const latest = new Map();
    for (const r of runs || []) {
      const k = r.Action + "\u0000" + (r.UndoOf || "");
      latest.delete(k);
      latest.set(k, r);
    }
    const order = new Map();
    (runs || []).forEach((r, i) => { const k = r.Action + "\u0000" + (r.UndoOf || ""); if (!order.has(k)) order.set(k, i); });
    return [...latest.entries()].sort((a, b) => order.get(a[0]) - order.get(b[0])).map((e) => e[1]);
  }

  // undoRuns returns the planned runs of an alert's pending undo, for an
  // alert whose action log is not available (no longer kept).
  function undoRuns(a) {
    if (!a.Undo) return [];
    return a.Undo.Actions.map((id) => ({ Action: id, UndoOf: a.Undo.Action, Status: "planned", Due: a.Undo.Due }));
  }

  function actionsSummary(a) {
    const td = el("td", "actions");
    const runs = latestRuns((a.Actions && a.Actions.length) ? a.Actions : undoRuns(a));
    if (!runs.length) {
      td.append(el("span", "muted", ruleActions(a.RuleID).length ? "pending" : "none"));
      return td;
    }
    for (const r of runs) {
      const item = el("span", "action-item");
      item.append(el("span", "action-name", actionName(r)), actionStatus(r, false));
      // Why it failed, cut to one line; all of it on hover and in the
      // action log of the alert.
      if (r.Status === "failed" || r.Status === "dropped") {
        const why = r.Error || r.Detail;
        if (why) {
          item.append(el("span", "action-error", why));
          item.title = actionName(r) + ": " + why;
        }
      }
      td.append(item);
    }
    return td;
  }

  function ruleActions(ruleID) {
    const r = state.info && (state.info.rules || []).find((x) => x.id === ruleID);
    return (r && r.actions) || [];
  }

  // actionLog renders the action log of an alert, oldest first.
  function actionLog(a) {
    const wrap = el("div", "action-log");
    wrap.append(el("h3", "", "Actions"));
    const runs = a.Actions || [];
    if (!runs.length && a.Undo) {
      wrap.append(el("p", "muted", "No longer kept (max_lifetime), so its action log is gone; its undo is still planned: " +
        a.Undo.Actions.join(", ") + " at " + new Date(a.Undo.Due).toLocaleString() + "."));
      return wrap;
    }
    if (!runs.length) {
      const acts = ruleActions(a.RuleID);
      wrap.append(el("p", "muted", acts.length ? "Not run yet: " + acts.join(", ") + "." : "The rule has no action."));
      return wrap;
    }
    const table = el("table", "data log");
    const head = el("tr");
    for (const h of ["Time", "Action", "Status", "Details"]) head.append(el("th", "", h));
    const thead = el("thead");
    thead.append(head);
    const body = el("tbody");
    for (const r of runs) {
      const tr = el("tr");
      const status = el("td");
      status.append(actionStatus(r, true));
      const details = [];
      if (r.UndoOf) details.push("undoes " + r.UndoOf);
      if (r.Duration) details.push("took " + durationLabel(r.Duration));
      if (r.Detail) details.push(r.Detail);
      const det = el("td", "detail", details.join(" · "));
      if (r.Error) {
        const e = el("div", "error");
        e.append(el("span", "error-label", "Error: "), document.createTextNode(r.Error));
        det.append(e);
      }
      tr.append(cell(timeLabel(new Date(r.Time), !sameDay(new Date(r.Time)), true), "time"), cell(r.Action), status, det);
      body.append(tr);
    }
    table.append(thead, body);
    const tw = el("div", "table-wrap");
    tw.append(table);
    wrap.append(tw);
    return wrap;
  }

  // durationLabel formats a Go duration in nanoseconds.
  function durationLabel(ns) {
    const ms = ns / 1e6;
    if (ms < 1000) return Math.round(ms) + " ms";
    return (ms / 1000).toFixed(ms < 10000 ? 1 : 0) + " s";
  }

  // addRun adds a run reported by the watch stream to the alert shown.
  function addRun(n) {
    const a = state.feed.find((x) => x.ID === n.AlertID);
    if (!a) return;
    const run = Object.assign({}, n);
    delete run.AlertID;
    delete run.RuleID;
    a.Actions = a.Actions || [];
    // The feed may have been loaded after this run was recorded.
    if (a.Actions.some((r) => r.Time === run.Time && r.Action === run.Action && r.Status === run.Status && (r.UndoOf || "") === (run.UndoOf || ""))) return;
    a.Actions.push(run);
    renderFeed(null, new Set([a.ID]));
  }

  function alertValue(a) {
    const v = a.Metadata && a.Metadata.value;
    return v === undefined || v === null ? "" : String(v);
  }

  function renderFeed(newIDs, updatedIDs) {
    const rows = [];
    for (const a of state.feed) {
      const tr = el("tr", "alert-row");
      if (newIDs && newIDs.has(a.ID)) tr.classList.add("new");
      tr.tabIndex = 0;
      tr.setAttribute("aria-expanded", state.open.has(a.ID) ? "true" : "false");
      const sev = el("td");
      sev.append(severityBadge(a.Severity));
      const summary = actionsSummary(a);
      if (updatedIDs && updatedIDs.has(a.ID)) summary.classList.add("new");
      tr.append(cell(timeLabel(raisedAt(a), true), "time"), sev, cell(a.RuleID), cell(alertValue(a)), cell(a.Message, "message"), summary);
      const toggle = () => {
        if (state.open.has(a.ID)) state.open.delete(a.ID); else state.open.add(a.ID);
        renderFeed();
      };
      tr.addEventListener("click", toggle);
      tr.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); } });
      rows.push(tr);
      if (state.open.has(a.ID)) {
        const d = el("tr", "details");
        const td = el("td");
        td.colSpan = 6;
        const evs = a.Events || [];
        const last = evs.length ? evs[evs.length - 1] : null;
        const lines = ["Alert " + a.ID + (a.Raised ? ", raised " + raisedAt(a).toLocaleString() : "")];
        if (a.Timestamp) lines.push("Event time: " + new Date(a.Timestamp).toLocaleString());
        if (last) {
          lines.push("Last event: " + [last.Source, last.Hostname, last.Service].filter(Boolean).join(" / "));
          lines.push(last.Raw || last.Message || "");
        } else {
          lines.push("No event included.");
        }
        if (a.Metadata && a.Metadata.count !== undefined) lines.push(a.Metadata.count + " events in total");
        td.append(el("pre", "", lines.join("\n")), actionLog(a));
        d.append(td);
        rows.push(d);
      }
    }
    if (!rows.length) {
      const tr = el("tr");
      const td = cell("No alert in this range", "muted");
      td.colSpan = 6;
      tr.append(td);
      rows.push(tr);
    }
    $("feed").replaceChildren(...rows);
  }

  function addAlert(a) {
    if (state.feedIDs.has(a.ID)) return;
    state.feedIDs.add(a.ID);
    state.feed.unshift(a);
    while (state.feed.length > MAX_FEED) state.feedIDs.delete(state.feed.pop().ID);
    renderFeed(new Set([a.ID]));
  }

  function notice(text) {
    const n = $("notice");
    n.textContent = text || "";
    n.hidden = !text;
  }

  // --- loading -------------------------------------------------------------
  function rangeParam() { return "-" + state.range; }

  // raisedAt is when wolverine raised an alert (its Timestamp, from the log,
  // for an alert no longer kept).
  function raisedAt(a) { return new Date(a.Raised || a.Timestamp); }

  // loadFeed loads the alerts raised in the range, and those whose undo is
  // still planned, whatever their age: what they did is still in effect.
  async function loadFeed() {
    const [r, pending] = await Promise.all([
      api("/api/v1/alerts?events=last&limit=" + MAX_FEED + "&from=" + encodeURIComponent(rangeParam())),
      api("/api/v1/alerts?events=last&undo=pending&limit=" + MAX_FEED),
    ]);
    const ids = new Set(r.alerts.map((a) => a.ID));
    const older = pending.alerts.filter((a) => !ids.has(a.ID));
    state.feed = r.alerts.concat(older).sort((a, b) => raisedAt(b) - raisedAt(a));
    state.feedIDs = new Set(state.feed.map((a) => a.ID));
    renderFeed();
    let text = (r.total > r.alerts.length ? "Latest " + r.alerts.length + " of " + fmt.format(r.total) : fmt.format(r.total)) + " raised in this range";
    if (older.length) text += ", and " + older.length + " older with an undo still planned";
    $("sub-feed").textContent = text + ", newest first; new alerts and actions appear as they happen. Select a row for its last log line and its action log.";
  }

  async function load(withFeed) {
    document.querySelectorAll(".chart").forEach((c) => c.classList.add("loading"));
    try {
      if (!state.info) {
        state.info = await api("/api/v1/info");
        // Without rules (or sources), the server sends null.
        state.info.rules = state.info.rules || [];
        state.info.sources = state.info.sources || [];
      }
      const from = encodeURIComponent(rangeParam());
      const [range, total, series] = await Promise.all([
        api("/api/v1/stats?from=" + from),
        api("/api/v1/stats"),
        api("/api/v1/stats/series?from=" + from),
      ]);
      renderTiles(range, total);
      renderTables(range);
      renderCharts(series);
      const avail = new Date(range.available_since);
      if (avail > new Date(range.from)) {
        notice("Counters are kept from " + timeLabel(avail, true) + " (wolverine start or max_lifetime): the beginning of the range is empty.");
      } else {
        notice("");
      }
      if (withFeed) await loadFeed();
      if (!state.watchAbort) watch();
    } catch (e) {
      if (e instanceof AuthError) askToken();
      else notice("Cannot reach wolverine: " + e.message);
    } finally {
      document.querySelectorAll(".chart").forEach((c) => c.classList.remove("loading"));
    }
  }

  function schedule() {
    clearInterval(state.timer);
    if (state.refresh > 0) state.timer = setInterval(() => load(false), state.refresh * 1000);
  }

  // --- live alerts ---------------------------------------------------------
  function setLive(s, text) {
    $("live").dataset.state = s;
    $("live-text").textContent = text;
  }

  // watch follows the server-sent events with fetch (EventSource cannot send
  // the token), and reconnects when the stream ends.
  async function watch() {
    const ctrl = new AbortController();
    state.watchAbort = ctrl;
    let retry = 3000;
    while (!ctrl.signal.aborted) {
      try {
        const resp = await fetch("/api/v1/alerts/watch?events=last", { headers: headers(), signal: ctrl.signal, cache: "no-store" });
        if (resp.status === 401) { setLive("down", "token required"); state.watchAbort = null; askToken(); return; }
        if (!resp.ok || !resp.body) throw new Error(resp.status);
        setLive("live", "live");
        const reader = resp.body.pipeThrough(new TextDecoderStream()).getReader();
        let buf = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += value;
          let sep;
          while ((sep = buf.indexOf("\n\n")) >= 0) {
            const block = buf.slice(0, sep);
            buf = buf.slice(sep + 2);
            let type = "message", data = "";
            for (const line of block.split("\n")) {
              if (line.startsWith("event:")) type = line.slice(6).trim();
              else if (line.startsWith("data:")) data += line.slice(5).trim();
              else if (line.startsWith("retry:")) retry = parseInt(line.slice(6), 10) || retry;
            }
            if (type === "alert" && data) {
              try { addAlert(JSON.parse(data)); } catch (e) { /* ignored */ }
            } else if (type === "action" && data) {
              try { addRun(JSON.parse(data)); } catch (e) { /* ignored */ }
            }
          }
        }
      } catch (e) {
        if (ctrl.signal.aborted) return;
      }
      setLive("down", "disconnected");
      await new Promise((r) => setTimeout(r, retry));
      // Catch up with what was missed while disconnected.
      if (!ctrl.signal.aborted) loadFeed().catch(() => {});
    }
  }

  // --- controls ------------------------------------------------------------
  function currentTheme() {
    const t = document.documentElement.dataset.theme;
    if (t) return t;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function init() {
    const saved = storage.get("wolverine-theme");
    if (saved === "light" || saved === "dark") document.documentElement.dataset.theme = saved;
    const savedRange = storage.get("wolverine-range");
    if (savedRange && RANGES[savedRange]) { state.range = savedRange; $("range").value = savedRange; }

    $("range").addEventListener("change", (e) => {
      state.range = e.target.value;
      storage.set("wolverine-range", state.range);
      load(true);
    });
    $("refresh").addEventListener("change", (e) => { state.refresh = parseInt(e.target.value, 10); schedule(); });
    $("reload").addEventListener("click", () => load(true));
    $("theme").addEventListener("click", () => {
      const next = currentTheme() === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      storage.set("wolverine-theme", next);
    });
    $("login-form").addEventListener("submit", () => {
      state.token = $("token").value.trim();
      storage.set("wolverine-token", state.token);
      state.info = null;
      load(true);
    });
    let resizeTimer;
    window.addEventListener("resize", () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => { if (lastSeries) renderCharts(lastSeries); }, 150);
    });
    setLive("", "connecting");
    schedule();
    load(true);
  }

  storage = makeStorage();
  state.token = storage.get("wolverine-token") || "";
  document.addEventListener("DOMContentLoaded", init);
})();
