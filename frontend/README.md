# Agent Vardøger — Dashboard

A React + TypeScript + Vite single-page app for monitoring AI agent session
security. It talks to the Agent Vardøger control plane API and visualizes
sessions, detections, prompt history, and Tier 3 cross-session findings, and
exposes the admin controls (security policy, signatures, evaluation, sources,
settings).

## Contents

- [Prerequisites](#prerequisites)
- [The scope and source model](#the-scope-and-source-model)
- [Roles and access](#roles-and-access)
- [Project layout](#project-layout)
- [Environment variables](#environment-variables)
- [Local development](#local-development)
- [Building for production](#building-for-production)
- [Serving the built app](#serving-the-built-app)
  - [Self-hosted (Model 1)](#self-hosted-model-1)
  - [Managed backend (Model 2)](#managed-backend-model-2)
- [Authentication](#authentication)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- Node.js 18+ and npm 9+
- A running Agent Vardøger control plane (the `control_plane` FastAPI app),
  reachable from the browser. See the repository docs for the quickstart.

## The scope and source model

The UI is built around the two-axis identity model (see
[`DESIGN-DECISIONS.md`](../DESIGN-DECISIONS.md)):

- **scope** — the isolation boundary. Self-hosted deployments are always the
  single scope `"local"`, so the UI never asks you to pick one; the backend
  supplies it.
- **source** — `"<aws_account_id>/<agent>"`. A central security team can point
  several accounts and agents at one control plane; each is a distinct source.
  Monitoring pages have a **Source picker** in the header. Pick a source to
  filter the view (adds `?source=` to API calls); leave it on **All sources**
  for the rollup across everything in the scope. The selection is remembered in
  `localStorage`.

## Roles and access

Access is role-based, with three ascending roles read from the signed-in
identity (Cognito groups `viewer` / `operator` / `admin`):

| Area | viewer | operator | admin |
|------|:------:|:--------:|:-----:|
| Dashboard, Detections, Prompt History, Health | ✅ | ✅ | ✅ |
| Sources, Evaluation (read), Security Policy (read), Signatures (read) | ✅ | ✅ | ✅ |
| Test Console (live chat) | — | ✅ | ✅ |
| Edit Security Policy, add Signatures, run Evaluation, record managed-upgrade intent | — | — | ✅ |

The UI hides or disables controls a role cannot use, but this is only a mirror:
the **control plane enforces every permission server-side**. A hidden button is
never the security boundary.

## Project layout

```
frontend/
├── index.html            App entry HTML
├── package.json          Dependencies and scripts
├── vite.config.ts        Vite config (dev server, /api proxy, build)
├── tailwind.config.js    Tailwind CSS config
├── postcss.config.js     PostCSS (tailwind + autoprefixer)
├── tsconfig*.json        TypeScript config
├── .env.example          Copy to .env.local and edit
└── src/
    ├── main.tsx              React root + router + auth provider
    ├── App.tsx               Route definitions + role guards
    ├── auth.tsx              Role-aware auth context (viewer/operator/admin)
    ├── sourceSelection.ts    Persisted source-filter selection
    ├── styles/globals.css    Tailwind entry + app styling
    ├── hooks/usePolling.ts   Polling data hook
    ├── api/client.ts         Axios client + typed API functions
    ├── components/
    │   ├── shared/           Layout, SourcePicker, LoadingSpinner, StatusBadge
    │   └── dashboard/        Dashboard panels (timeline, charts, tables, Tier 3)
    └── pages/
        ├── DashboardPage.tsx       Sessions, timeline, categories, Tier 3 (embedded)
        ├── DetectionsPage.tsx      Layer 1 / Tier 2 / Tier 3 detections
        ├── PromptHistoryPage.tsx   Prompt search
        ├── HealthPage.tsx          Deployment status + health checks
        ├── TestConsolePage.tsx     Live chat test console (operator+admin)
        ├── SecurityPolicyPage.tsx  Tier 2/3 policy (admin edits)
        ├── SignaturesPage.tsx      Community + premium signatures (admin adds)
        ├── EvaluationPage.tsx      TP/TN/FP/FN summary (admin runs)
        ├── SourcesPage.tsx         Distinct sources seen in the scope
        └── SettingsPage.tsx        Deployment settings + managed-upgrade
```

## Environment variables

All frontend config is compiled in at **build time** via Vite's `VITE_`
convention. Copy `.env.example` to `.env.local` for development, or set these
in your CI/deploy environment for production builds.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VITE_API_BASE_URL` | Yes (prod) | `/api` | Base URL of the control plane API. With `AuthMode=none`/`token`: the Lambda Function URL (`ControlPlaneFunctionUrl`) + `/api`. With Cognito: the API Gateway invoke URL (`ControlPlaneApiUrl`) + `/api`. In dev, `/api` behind the Vite proxy. |
| `VITE_TEST_CONSOLE_GATEWAY_URL` | No | — | Optional default gateway URL pre-filled in the Test Console. The operator can override it in the UI. **Baked into the public JS bundle at build time — it becomes publicly visible. Never put a secret-bearing URL here.** |
| `VITE_TEST_CONSOLE_TOOL_NAME` | No | — | Optional default MCP tool name pre-filled in the Test Console. Also baked into the public bundle. |
| `VITE_DEV_PROXY` | No | `http://localhost:8000` | Dev-only. The backend origin the dev server proxies `/api` to. Set this to target a backend on a different host/port. |

Because these are build-time values, **rebuild after changing them**. They are
embedded in the compiled JS, so never put secrets in `VITE_` variables — the
authentication token is obtained at runtime via Cognito, not baked into the build.

## Local development

```bash
cd frontend
cp .env.example .env.local        # then edit values
npm install
npm run dev
```

The dev server runs at `http://localhost:5173`.

Two ways to point it at a backend:

1. **Proxy (default)** — leave `VITE_API_BASE_URL` as `/api`. The dev server
   (see `vite.config.ts`) forwards `/api/*` to `http://localhost:8000`,
   sidestepping CORS. Run the control plane on port 8000 (below) and it just works.
   To target a different port/host, set `VITE_DEV_PROXY` (e.g.
   `VITE_DEV_PROXY=http://localhost:9000`) in `.env.local`.

2. **Direct** — set `VITE_API_BASE_URL=http://localhost:8000/api` in `.env.local`.
   The control plane must allow the dev origin via `VARDOGER_CORS_ORIGINS`
   (it already includes `http://localhost:5173` by default).

To run the control plane locally with auth disabled (you are treated as an
admin for local dev):

```bash
# from the repository root
pip install -e ".[api]"
VARDOGER_AUTH_MODE=none uvicorn control_plane.main:app --port 8000
```

## Building for production

```bash
cd frontend
VITE_API_BASE_URL="https://<your-control-plane>/api" npm run build
```

Output is written to `frontend/dist/` — static HTML, JS, and CSS with no server
runtime required.

## Serving the built app

The dashboard is a static SPA. Because it uses client-side routing, whatever
serves it must fall back to `index.html` for unknown paths.

### Self-hosted (Model 1)

`infra/self-hosted.yaml` provisions a UI S3 bucket (`UiBucketName` output) and
the control plane. Recommended options:

**Option A — S3 + CloudFront (recommended):**

```bash
# Build pointing at your control plane API URL
VITE_API_BASE_URL="https://<control-plane-api>/api" npm run build

# Upload to the UI bucket
aws s3 sync dist/ s3://<your-ui-bucket>/ --delete

# Front it with CloudFront and set the SPA fallback:
#   - Default root object: index.html
#   - Custom error response: 403/404 -> /index.html (HTTP 200)
```

Set `VARDOGER_CORS_ORIGINS` on the control plane to include your CloudFront/S3
origin so the browser can call the API.

**Option B — any static host** (Netlify, Vercel, nginx, Caddy): serve `dist/`
with an SPA fallback rewrite to `index.html`. Example nginx:

```nginx
location / {
  root /var/www/vardoger;
  try_files $uri /index.html;
}
```

### Managed backend (Model 2)

In managed mode the dashboard is typically hosted by the managed service and you
do not self-host it. If you do want your own UI against the managed API, build
with `VITE_API_BASE_URL` set to the managed API URL and serve `dist/` as in
Option A/B above.

## Authentication

The SPA's sign-in surface depends on `VITE_AUTH_MODE` (set to match the control
plane's `VARDOGER_AUTH_MODE`):

- **`token`** (default) — single-operator self-host. The SPA shows an
  access-token screen; you paste the shared secret `deploy.sh` printed, and it
  is sent as `Authorization: Bearer <secret>` on each request. Served over the
  Lambda Function URL.
- **`none`** (local/dev only) — no sign-in; the API sends no `Authorization`
  header and the backend treats the caller as admin. Also uses the Function URL.
- **`cognito`** (and `cognito+identity-center`) — an API Gateway JWT authorizer
  verifies a Cognito token. The SPA runs the Hosted UI OAuth PKCE flow; the role
  is read from the `cognito:groups` claim (`viewer` / `operator` / `admin`).

No API keys, account IDs, or role ARNs are baked into the build.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Blank page, console shows CORS error | Control plane origin not allowed | Add the UI origin to `VARDOGER_CORS_ORIGINS` and redeploy |
| `Network Error` on every request | `VITE_API_BASE_URL` wrong or backend down | Verify the URL resolves and `/api/health` returns 200 |
| 401/403 on every request | Not signed in, or role lacks access | Sign in via Cognito; confirm your user is in a `viewer`/`operator`/`admin` group |
| 404 on refresh of a sub-page | SPA fallback not configured | Configure `try_files`/error-response rewrite to `index.html` |
| Env change had no effect | Vite bakes env at build time | Rebuild after changing any `VITE_` variable |
| Test Console / admin buttons missing | Your role is below the requirement | Test Console needs operator+; policy/signature/evaluation edits need admin |

## License

Part of Agent Vardøger, licensed under the [Elastic License 2.0](../LICENSE).
