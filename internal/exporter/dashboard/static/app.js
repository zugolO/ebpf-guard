(function () {
  "use strict";

  const TOKEN_KEY = "ebpf-guard-token";
  const state = { alerts: [], selectedId: null };

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

  async function api(path) {
    const headers = {};
    const token = getToken();
    if (token) headers["Authorization"] = "Bearer " + token;
    const res = await fetch(path, { headers });
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

  function buildQuery(f, extra) {
    const params = new URLSearchParams();
    if (f.since) params.set("since", f.since);
    if (f.severity) params.set("severity", f.severity);
    if (f.rule_id) params.set("rule_id", f.rule_id);
    params.set("limit", "500");
    if (extra) {
      for (const k in extra) params.set(k, extra[k]);
    }
    return params.toString();
  }

  function fmtTime(ts) {
    if (!ts) return "";
    const d = new Date(ts);
    return d.toLocaleString(undefined, {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    });
  }

  function escapeHTML(str) {
    const div = document.createElement("div");
    div.textContent = str == null ? "" : String(str);
    return div.innerHTML;
  }

  function renderSummary(summary) {
    el("stat-total").textContent = summary.total ?? 0;
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
      row.innerHTML = `
        <span class="sev-badge ${escapeHTML(a.severity)}">${escapeHTML(a.severity)}</span>
        <span class="rule" title="${escapeHTML(a.message)}">${escapeHTML(a.rule_id)}</span>
        <span class="comm">${escapeHTML(a.comm)}</span>
        <span class="time">${fmtTime(a.timestamp)}</span>`;
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

    const detail = el("alert-detail");
    detail.innerHTML = "<h2>Details</h2><p class=\"muted\">Loading…</p>";
    try {
      const explanation = await api(`/api/v1/alerts/${encodeURIComponent(id)}/explain`);
      renderDetail(explanation);
    } catch (err) {
      detail.innerHTML = `<h2>Details</h2><p class="muted">Could not load explanation: ${escapeHTML(err.message)}</p>`;
    }
  }

  function renderDetail(exp) {
    const detail = el("alert-detail");
    const mitre = exp.mitre || {};
    const mitigations = (exp.mitigations || [])
      .map((m) => `<li>${escapeHTML(m)}</li>`)
      .join("");
    const references = (exp.references || [])
      .map((r) => `<div><a class="mitre-link" href="${escapeHTML(r)}" target="_blank" rel="noopener noreferrer">${escapeHTML(r)}</a></div>`)
      .join("");

    detail.innerHTML = `
      <h2>Details</h2>
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
        ${mitre.url ? `<a class="mitre-link" href="${escapeHTML(mitre.url)}" target="_blank" rel="noopener noreferrer">${escapeHTML(mitre.url)}</a>` : ""}
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
    `;
  }

  async function refresh() {
    setStatus("loading…");
    const filters = currentFilters();
    try {
      const [status, summary, alerts] = await Promise.all([
        api("/api/v1/status"),
        api("/api/v1/summary?" + buildQuery(filters)),
        api("/api/v1/alerts?" + buildQuery(filters)),
      ]);
      setStatus(status.healthy ? "connected" : "degraded", status.healthy ? "ok" : "error");
      renderSummary(summary);
      state.alerts = applyClientFilters(alerts || []);
      renderAlerts(state.alerts);
    } catch (err) {
      setStatus("error: " + err.message, "error");
      // The static shell loads without a token, but the data API is
      // authenticated. On the first 401, prompt for a token so the operator
      // isn't left staring at a bare "401 Unauthorized" string.
      if (err.status === 401) openTokenDialog();
    }
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
})();
