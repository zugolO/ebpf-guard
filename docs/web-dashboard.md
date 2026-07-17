# Embedded web dashboard

ebpf-guard ships a self-contained, read-only web dashboard served by the agent's
HTTP server at `/ui/`. It has no external dependencies (all HTML/JS/CSS is
embedded in the binary) and shows a live alert feed, severity/rule/timeline
summaries, and per-alert explanations with MITRE ATT&CK mappings.

```
http://<agent-host>:19090/ui/
```

The bare root path `/` redirects to `/ui/`.

## Opening the dashboard when auth is enabled

On production/VPS deployments the HTTP API is protected by a bearer token
(`auth.enabled: true`, recommended). A browser cannot attach an `Authorization`
header on the initial page navigation, so the dashboard is split into two layers:

- **Static shell** (`/ui/`, `/ui/app.js`, `/ui/style.css`) — served **without**
  authentication. These assets contain no alert data, only the UI code. This is
  what lets the page load in the first place.
- **Alert data** (`/api/v1/*`) — stays **behind** the bearer token. The dashboard
  JavaScript attaches the token to every data request.

To use it on a secured agent:

1. Navigate to `http://<agent-host>:19090/ui/`. The page loads immediately.
2. The first data fetch returns `401`, and the dashboard automatically opens the
   **Token** dialog (you can also open it any time with the **Token** button in
   the top bar).
3. Paste a viewer or admin bearer token and click **Save**. The token is stored
   in the browser's `localStorage` and sent as `Authorization: Bearer <token>`
   on every subsequent `/api/v1/*` request.

The token is the same one used for Prometheus scraping and API access — see the
generated-token note printed once to stderr on first start, or configure it
explicitly under `auth` / `alerting`.

> **Note:** because the static assets are public, do not expose the agent's HTTP
> port directly to untrusted networks. Front it with your ingress/mTLS setup as
> you would any other internal service; the token protects the data, not the
> shell.

## Fleet view (multiple agents in one dashboard)

If you run several standalone agents (the typical "3-10 VPS" setup), the
**Fleet** tab lets you watch all of them from any one agent's dashboard,
without deploying extra infrastructure:

1. Open the **Fleet** tab. This node is always listed first.
2. Add each additional agent's URL (e.g. `https://vps-2.example.com:19090`)
   and its own bearer token under **Agents**. The token is stored only in this
   browser's `localStorage`, scoped to that one agent — it is never sent to
   any other node.
3. The **Fleet summary** section polls every configured agent directly from
   the browser (`/api/v1/status`, `/api/v1/summary`, `/api/v1/alerts`) and
   shows total/critical counts per node, plus a merged feed of critical
   alerts across the whole fleet, sorted by recency.
4. An agent that is unreachable, misconfigured, or returns an error is shown
   as **offline** with the error — it does not prevent the rest of the fleet
   from rendering.

Because this is a browser-side, cross-origin fetch, each agent must allow the
requesting origin via `server.cors_allowed_origins` in its config (default is
`["*"]`, i.e. any origin, matching the pre-existing OpenAPI CORS default). Set
it to an explicit allowlist of your dashboard origins for a tighter policy;
CORS is only ever applied to the read-only `/api/v1/*` endpoints (status,
summary, alerts, incidents, rules, feedback) — write endpoints are never
reachable cross-origin.

This is stage 1 of the fleet roadmap (issue #312): a client-side merge with no
server-side aggregation. A shared store (all agents writing to one OpenSearch/
SQLite backend) or a gossip-based hub aggregator are tracked as later stages,
should the need for them come up.
