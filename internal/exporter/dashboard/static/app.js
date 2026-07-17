(function () {
  "use strict";

  const TOKEN_KEY = "ebpf-guard-token";
  const state = { alerts: [], selectedId: null, incidents: [], selectedIncidentId: null };

  const el = (id) => document.getElementById(id);

  function getToken() {
    return localStorage.getItem(TOKEN_KEY) || "";
  }

  function setToken(token) {
    if (token) {
      localStorage.setItem(TOKEN_KEY, token);
    } else {
      localStorage.removeItem(TOKEN_KEY);
    }
  }

  async function api(path, opts) {
    const headers = {};
    const token = getToken();
    if (token) headers["Authorization"] = "Bearer " + token;
    if (opts && opts.body) headers["Content-Type"] = "application/json";
    const res = await fetch(path, Object.assign({ headers }, opts));
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      const err = new Error(`${res.status} ${text}`);
      err.status = res.status;
      throw err;
    }
    return res.json();
  }

  function setStatus(text, cls) {
    const s = el("status");
    s.textContent = text;
    s.className = "status" + (cls ? " " + cls : "");
  }

  function currentFilters() {
    return {
      severity: el("f-severity").value,
      rule_id: el("f-rule").value.trim(),
      comm: el("f-comm").value.trim(),
      since: el("f-since").value,
    };
  }

  // buildFilterParams builds the shared filter params (severity/rule/since)
  // without a row limit.
  function buildFilterParams(f) {
    const params = new URLSearchParams();
    if (f.since) params.set("since", f.since);
    if (f.severity) params.set("severity", f.severity);
    if (f.rule_id) params.set("rule_id", f.rule_id);
    return params;
  }

  // buildQuery is for the alert LIST, which is intentionally paged.
  function buildQuery(f, extra) {
    const params = buildFilterParams(f);
    params.set("limit", "500");
    if (extra) {
      for (const k in extra) params.set(k, extra[k]);
    }
    return params.toString();
  }

  // buildSummaryQuery is for /api/v1/summary. It must NOT send a limit: summary
  // counts reflect the whole window, so a client-side cap of 500 would peg the
  // "Alerts (window)" stat at 500 during a real storm (issue #303).
  function buildSummaryQuery(f) {
    return buildFilterParams(f).toString();
  }

  function fmtTime(ts) {
    if (!ts) return "";
    const d = new Date(ts);
    return d.toLocaleString(undefined, {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    });
  }

  // escapeHTML escapes the five HTML-significant characters, INCLUDING both
  // quote characters. The previous textContent→innerHTML trick escaped only
  // & < >, leaving " and ' intact — which let attacker-controlled values (comm,
  // file paths in message) break out of the HTML attributes they are
  // interpolated into (title="…", href="…"). This explicit map closes that.
  const HTML_ESCAPES = {
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&#34;", "'": "&#39;",
  };
  function escapeHTML(str) {
    if (str == null) return "";
    return String(str).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
  }

  // safeURL returns u only if it is an http/https URL, otherwise "#". Used for
  // reference/MITRE links so a javascript:/data: URL in attacker-controlled
  // data cannot become a live link even if the CSP is ever relaxed.
  function safeURL(u) {
    const s = String(u == null ? "" : u).trim();
    return /^https?:\/\//i.test(s) ? s : "#";
  }

  function renderSummary(summary) {
    const total = summary.total ?? 0;
    // Truncated is only set by the Query-based fallback path; show "≥N" so the
    // operator knows the real count is at least this high.
    el("stat-total").textContent = summary.truncated ? "≥" + total : total;
    el("stat-critical").textContent = (summary.by_severity && summary.by_severity.critical) || 0;
    el("stat-warning").textContent = (summary.by_severity && summary.by_severity.warning) || 0;

    const topRulesEl = el("top-rules");
    topRulesEl.innerHTML = "";
    const rules = summary.top_rules || [];
    const max = rules.reduce((m, r) => Math.max(m, r.count), 1);
    for (const r of rules.slice(0, 8)) {
      const li = document.createElement("li");
      const pct = Math.round((r.count / max) * 100);
      li.innerHTML = `<span class="name" title="${escapeHTML(r.rule_id)}">${escapeHTML(r.rule_id)}</span>
        <span class="bar"><span style="width:${pct}%"></span></span>
        <span class="count">${r.count}</span>`;
      topRulesEl.appendChild(li);
    }

    const timelineEl = el("timeline");
    timelineEl.innerHTML = "";
    const buckets = summary.timeline || [];
    const tmax = buckets.reduce((m, b) => Math.max(m, b.count), 1);
    for (const b of buckets) {
      const div = document.createElement("div");
      div.className = "bucket";
      const height = Math.max(2, Math.round((b.count / tmax) * 100));
      div.style.height = height + "%";
      div.title = `${b.hour}: ${b.count}`;
      timelineEl.appendChild(div);
    }
  }

  // alertSortKey returns the timestamp that should govern feed ordering: for
  // an aggregated alert (count > 1) that is last_seen, so a still-firing
  // storm stays at the top of the feed instead of sinking to where its first
  // occurrence landed (issue #307).
  function alertSortKey(a) {
    return a.last_seen || a.timestamp;
  }

  function sortAlertsByRecency(alerts) {
    return alerts.slice().sort((a, b) => new Date(alertSortKey(b)) - new Date(alertSortKey(a)));
  }

  function renderAlerts(alerts) {
    const container = el("alerts");
    container.innerHTML = "";
    if (alerts.length === 0) {
      container.innerHTML = '<p class="muted">No alerts match the current filters.</p>';
      return;
    }
    for (const a of alerts) {
      const row = document.createElement("div");
      row.className = "alert-row" + (a.id === state.selectedId ? " selected" : "");
      row.dataset.id = a.id;
      const countBadge = a.count > 1
        ? `<span class="count-badge" title="Aggregated: ${a.count} occurrences">×${a.count}</span>`
        : "";
      row.innerHTML = `
        <span class="sev-badge ${escapeHTML(a.severity)}">${escapeHTML(a.severity)}</span>
        <span class="rule" title="${escapeHTML(a.message)}">${escapeHTML(a.rule_id)}</span>
        ${countBadge}
        <span class="comm">${escapeHTML(a.comm)}</span>
        <span class="time">${fmtTime(alertSortKey(a))}</span>`;
      row.addEventListener("click", () => selectAlert(a.id));
      container.appendChild(row);
    }
  }

  function applyClientFilters(alerts) {
    const comm = el("f-comm").value.trim().toLowerCase();
    if (!comm) return alerts;
    return alerts.filter((a) => (a.comm || "").toLowerCase().includes(comm));
  }

  async function selectAlert(id) {
    state.selectedId = id;
    document.querySelectorAll(".alert-row").forEach((r) => {
      r.classList.toggle("selected", r.dataset.id === id);
    });

    const alert = state.alerts.find((a) => a.id === id);
    const detail = el("alert-detail");
    detail.innerHTML = "<h2>Details</h2><p class=\"muted\">Loading…</p>";
    try {
      const explanation = await api(`/api/v1/alerts/${encodeURIComponent(id)}/explain`);
      renderDetail(explanation, alert);
    } catch (err) {
      detail.innerHTML = `<h2>Details</h2><p class="muted">Could not load explanation: ${escapeHTML(err.message)}</p>`;
    }
  }

  // durationBetween formats the span between two ISO timestamps as a compact
  // "1h 12m" / "45s" string for the aggregation window display.
  function durationBetween(a, b) {
    const ms = Math.max(0, new Date(b) - new Date(a));
    const totalSec = Math.round(ms / 1000);
    const h = Math.floor(totalSec / 3600);
    const m = Math.floor((totalSec % 3600) / 60);
    const s = totalSec % 60;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }

  // renderAggregation shows the "×N occurrences over a first_seen…last_seen
  // window" callout for an aggregated alert, so an operator can tell a single
  // hit apart from a storm that fired hundreds of times (issue #307). Alert
  // rows carry these fields directly — no extra API call is needed.
  function renderAggregation(alert) {
    if (!alert || !(alert.count > 1)) return "";
    const dur = durationBetween(alert.first_seen, alert.last_seen);
    return `
      <div class="detail-field">
        <div class="label">Aggregation</div>
        <div class="value">
          <span class="count-badge">×${alert.count}</span>
          ${fmtTime(alert.first_seen)} &rarr; ${fmtTime(alert.last_seen)} (${dur})
        </div>
      </div>`;
  }

  function renderDetail(exp, alert) {
    const detail = el("alert-detail");
    const mitre = exp.mitre || {};
    const mitigations = (exp.mitigations || [])
      .map((m) => `<li>${escapeHTML(m)}</li>`)
      .join("");
    const references = (exp.references || [])
      .map((r) => `<div><a class="mitre-link" href="${escapeHTML(safeURL(r))}" target="_blank" rel="noopener noreferrer">${escapeHTML(r)}</a></div>`)
      .join("");

    detail.innerHTML = `
      <h2>Details</h2>
      ${renderAggregation(alert)}
      <div class="detail-field">
        <div class="label">Summary</div>
        <div class="value">${escapeHTML(exp.summary)}</div>
      </div>
      <div class="detail-field">
        <div class="label">Detail</div>
        <div class="value">${escapeHTML(exp.detail)}</div>
      </div>
      <div class="detail-field">
        <div class="label">Severity</div>
        <div class="value">${escapeHTML(exp.severity)} — ${escapeHTML(exp.severity_why)}</div>
      </div>
      ${mitre.technique_id ? `
      <div class="detail-field">
        <div class="label">MITRE ATT&amp;CK</div>
        <div class="value">${escapeHTML(mitre.tactic)} / ${escapeHTML(mitre.technique_id)} — ${escapeHTML(mitre.technique)}</div>
        ${mitre.url ? `<a class="mitre-link" href="${escapeHTML(safeURL(mitre.url))}" target="_blank" rel="noopener noreferrer">${escapeHTML(mitre.url)}</a>` : ""}
      </div>` : ""}
      ${mitigations ? `
      <div class="detail-field">
        <div class="label">Mitigations</div>
        <ul class="mitigations">${mitigations}</ul>
      </div>` : ""}
      ${references ? `
      <div class="detail-field">
        <div class="label">References</div>
        ${references}
      </div>` : ""}
      ${renderFeedbackSection(alert)}
    `;
    if (alert) initFeedbackHandlers(alert);
  }

  // --- False-positive feedback + exception generation (issue #308) -----
  // Closes the loop "saw noise in the dashboard → suppressed it" without a
  // curl command: the operator clicks a verdict, gets a ready-to-paste (or
  // one-click-save) exception, instead of hand-writing local-tuning.yaml.

  function renderFeedbackSection(alert) {
    if (!alert) return "";
    return `
      <div class="detail-field feedback-section">
        <div class="label">Feedback</div>
        <div class="feedback-buttons">
          <button class="btn-ghost" id="fb-fp-btn" type="button">False positive</button>
          <button class="btn-ghost" id="fb-tp-btn" type="button">True positive</button>
        </div>
        <div id="fb-result" class="fb-result"></div>
      </div>`;
  }

  async function submitFeedback(alert, verdict) {
    const resultEl = el("fb-result");
    resultEl.innerHTML = '<p class="muted">Submitting…</p>';
    try {
      await api(`/api/v1/alerts/${encodeURIComponent(alert.id)}/feedback`, {
        method: "POST",
        body: JSON.stringify({ verdict }),
      });
    } catch (err) {
      resultEl.innerHTML = `<p class="muted">Could not submit feedback: ${escapeHTML(err.message)}</p>`;
      if (err.status === 401) openTokenDialog();
      return;
    }

    if (verdict !== "false_positive") {
      resultEl.innerHTML = '<p class="muted">Recorded. Thanks.</p>';
      return;
    }
    await generateException(alert, resultEl);
  }

  async function generateException(alert, resultEl) {
    resultEl.innerHTML = '<p class="muted">Generating exception…</p>';
    const body = {
      rule_id: alert.rule_id,
      name: "fp_" + (alert.comm || "unknown") + "_" + alert.id.slice(0, 8),
      comm: alert.comm || "",
      persist: false,
    };
    let resp;
    try {
      resp = await api("/api/v1/tuning/exceptions", { method: "POST", body: JSON.stringify(body) });
    } catch (err) {
      resultEl.innerHTML = `<p class="muted">Recorded as false positive. Exception could not be generated: ${escapeHTML(err.message)}</p>`;
      return;
    }

    resultEl.innerHTML = `
      <p class="muted">Recorded as false positive. Paste into local-tuning.yaml, or save it directly:</p>
      <pre class="exception-yaml">${escapeHTML(resp.yaml)}</pre>
      <div class="feedback-buttons">
        <button class="btn-ghost" id="fb-copy-btn" type="button">Copy YAML</button>
        <button class="btn" id="fb-save-btn" type="button">Save to tuning file</button>
      </div>
      <div id="fb-save-result"></div>`;

    el("fb-copy-btn").addEventListener("click", () => {
      navigator.clipboard.writeText(resp.yaml).catch(() => {});
    });
    el("fb-save-btn").addEventListener("click", async () => {
      const saveResult = el("fb-save-result");
      saveResult.textContent = "Saving…";
      try {
        const saved = await api("/api/v1/tuning/exceptions", {
          method: "POST",
          body: JSON.stringify({ ...body, persist: true }),
        });
        saveResult.textContent = saved.persisted
          ? "Saved — rules will hot-reload the new exception."
          : "Not persisted (no local-tuning path configured on the agent). Use the snippet above.";
      } catch (err) {
        saveResult.textContent = err.status === 403
          ? "Admin token required to save directly; use the snippet above instead."
          : "Save failed: " + err.message;
      }
    });
  }

  function initFeedbackHandlers(alert) {
    el("fb-fp-btn").addEventListener("click", () => submitFeedback(alert, "false_positive"));
    el("fb-tp-btn").addEventListener("click", () => submitFeedback(alert, "true_positive"));
  }

  async function refresh() {
    setStatus("loading…");
    const filters = currentFilters();
    try {
      const [status, summary, alerts] = await Promise.all([
        api("/api/v1/status"),
        api("/api/v1/summary?" + buildSummaryQuery(filters)),
        api("/api/v1/alerts?" + buildQuery(filters)),
      ]);
      setStatus(status.healthy ? "connected" : "degraded", status.healthy ? "ok" : "error");
      renderSummary(summary);
      state.alerts = sortAlertsByRecency(applyClientFilters(alerts || []));
      renderAlerts(state.alerts);
    } catch (err) {
      setStatus("error: " + err.message, "error");
      // The static shell loads without a token, but the data API is
      // authenticated. On the first 401, prompt for a token so the operator
      // isn't left staring at a bare "401 Unauthorized" string.
      if (err.status === 401) openTokenDialog();
    }
  }

  // --- Incidents tab (issue #307) -------------------------------------
  // Surfaces /api/v1/incidents (already implemented server-side and already
  // in the viewer-role allowlist) in the dashboard, which previously had no
  // tab or link pointing at it.

  function switchTab(name) {
    for (const tab of ["alerts", "incidents"]) {
      el("view-" + tab).classList.toggle("hidden", tab !== name);
      el("tab-" + tab).classList.toggle("active", tab === name);
    }
    if (name === "incidents") refreshIncidents();
  }

  function renderIncidents(incidents) {
    const container = el("incidents");
    container.innerHTML = "";
    if (incidents.length === 0) {
      container.innerHTML = '<p class="muted">No incidents match the current filters.</p>';
      return;
    }
    for (const inc of incidents) {
      const row = document.createElement("div");
      row.className = "alert-row" + (inc.id === state.selectedIncidentId ? " selected" : "");
      row.dataset.id = inc.id;
      row.innerHTML = `
        <span class="sev-badge ${escapeHTML(inc.severity)}">${escapeHTML(inc.severity)}</span>
        <span class="rule" title="${escapeHTML((inc.rule_ids || []).join(", "))}">${escapeHTML(inc.namespace || "(no namespace)")}</span>
        <span class="count-badge" title="${inc.alert_count} alerts">×${inc.alert_count}</span>
        <span class="comm">${escapeHTML(inc.status)}</span>
        <span class="time">${fmtTime(inc.last_seen)}</span>`;
      row.addEventListener("click", () => selectIncident(inc.id));
      container.appendChild(row);
    }
  }

  function selectIncident(id) {
    state.selectedIncidentId = id;
    document.querySelectorAll("#incidents .alert-row").forEach((r) => {
      r.classList.toggle("selected", r.dataset.id === id);
    });

    const inc = state.incidents.find((i) => i.id === id);
    const detail = el("incident-detail");
    if (!inc) {
      detail.innerHTML = "<h2>Incident</h2><p class=\"muted\">Not found.</p>";
      return;
    }
    const dur = durationBetween(inc.first_seen, inc.last_seen);
    const alertIds = (inc.alert_ids || [])
      .map((id) => `<li>${escapeHTML(id)}</li>`)
      .join("");
    detail.innerHTML = `
      <h2>Incident</h2>
      <div class="detail-field">
        <div class="label">Status</div>
        <div class="value">${escapeHTML(inc.status)} — ${escapeHTML(inc.severity)}</div>
      </div>
      <div class="detail-field">
        <div class="label">Namespace</div>
        <div class="value">${escapeHTML(inc.namespace || "(none)")}</div>
      </div>
      <div class="detail-field">
        <div class="label">Window</div>
        <div class="value">${fmtTime(inc.first_seen)} &rarr; ${fmtTime(inc.last_seen)} (${dur})</div>
      </div>
      <div class="detail-field">
        <div class="label">Rules involved</div>
        <div class="value">${escapeHTML((inc.rule_ids || []).join(", "))}</div>
      </div>
      <div class="detail-field">
        <div class="label">Alerts (${inc.alert_count})</div>
        <ul class="mitigations">${alertIds}</ul>
      </div>`;
  }

  async function refreshIncidents() {
    const params = new URLSearchParams();
    const status = el("inc-status").value;
    const namespace = el("inc-namespace").value.trim();
    if (status) params.set("status", status);
    if (namespace) params.set("namespace", namespace);
    const container = el("incidents");
    container.innerHTML = "<p class=\"muted\">Loading…</p>";
    try {
      const incidents = await api("/api/v1/incidents?" + params.toString());
      state.incidents = incidents || [];
      renderIncidents(state.incidents);
    } catch (err) {
      container.innerHTML = `<p class="muted">Could not load incidents: ${escapeHTML(err.message)}</p>`;
      if (err.status === 401) openTokenDialog();
    }
  }

  function initTabs() {
    for (const tab of ["alerts", "incidents"]) {
      el("tab-" + tab).addEventListener("click", () => switchTab(tab));
    }
    el("inc-refresh-btn").addEventListener("click", refreshIncidents);
    el("inc-status").addEventListener("change", refreshIncidents);
    el("inc-namespace").addEventListener("keydown", (e) => {
      if (e.key === "Enter") refreshIncidents();
    });
  }

  function openTokenDialog() {
    const dialog = el("token-dialog");
    if (dialog.open) return;
    el("token-input").value = getToken();
    dialog.showModal();
  }

  function initTokenDialog() {
    const dialog = el("token-dialog");
    el("token-btn").addEventListener("click", openTokenDialog);
    el("token-form").addEventListener("submit", () => {
      setToken(el("token-input").value.trim());
      refresh();
    });
    el("token-clear").addEventListener("click", () => {
      setToken("");
      el("token-input").value = "";
      dialog.close();
      refresh();
    });
  }

  function init() {
    initTokenDialog();
    initTabs();
    el("refresh-btn").addEventListener("click", refresh);
    ["f-severity", "f-since"].forEach((id) =>
      el(id).addEventListener("change", refresh)
    );
    ["f-rule", "f-comm"].forEach((id) =>
      el(id).addEventListener("keydown", (e) => {
        if (e.key === "Enter") refresh();
      })
    );
    refresh();
  }

  document.addEventListener("DOMContentLoaded", init);

  // Export the pure string helpers for unit testing under Node. Guarded by a
  // typeof check so this is a no-op in the browser (there is no `module`).
  if (typeof module !== "undefined" && module.exports) {
    module.exports = { escapeHTML, safeURL, durationBetween, alertSortKey };
  }
})();
