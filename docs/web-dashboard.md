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
