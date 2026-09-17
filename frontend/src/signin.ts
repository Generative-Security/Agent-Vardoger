// Cognito Hosted UI sign-in via the OAuth 2.0 authorization code flow with
// PKCE. Used only when AuthMode=cognito (the backend gate is the API Gateway
// JWT authorizer; this just obtains a token for the SPA to send).
//
// Config comes from build-time env (VITE_COGNITO_*). When it is absent the app
// is in none/token mode and this module is inert.

import { setToken } from "./auth";

const DOMAIN = import.meta.env.VITE_COGNITO_DOMAIN || "";
const CLIENT_ID = import.meta.env.VITE_COGNITO_CLIENT_ID || "";
const REDIRECT_URI =
  import.meta.env.VITE_COGNITO_REDIRECT_URI ||
  (typeof window !== "undefined" ? window.location.origin : "");

const VERIFIER_KEY = "vardoger.pkce_verifier";
const STATE_KEY = "vardoger.oauth_state";

// signOut: End the session properly.
//
// Order matters. Local state is cleared FIRST so that a failure to reach the
// Hosted UI still leaves this browser without a usable token, rather than
// leaving the operator signed in because a redirect did not happen.
//
// Then, in cognito mode, redirect to the Hosted UI /logout endpoint. Clearing
// localStorage alone would leave the Cognito session cookie intact on the
// Hosted UI domain, so the next sign-in would complete silently with no
// prompt — a sign-out that looks like it worked and did not. On a shared or
// abandoned machine that is the whole point of the button.
export function signOut(): void {
  clearLocalSession();

  if (!cognitoConfigured()) {
    // token / none mode: no IdP session exists, so clearing local state IS the
    // sign-out. Reload to drop any in-memory state and show the sign-in view.
    window.location.replace(window.location.origin);
    return;
  }

  const url =
    `${DOMAIN.replace(/\/$/, "")}/logout` +
    `?client_id=${encodeURIComponent(CLIENT_ID)}` +
    `&logout_uri=${encodeURIComponent(REDIRECT_URI)}`;
  window.location.replace(url);
}

// clearLocalSession: Remove every credential this app stores, not just the
// token. The PKCE verifier and OAuth state are single-use, and leaving them
// behind lets a stale in-flight exchange complete after a sign-out.
function clearLocalSession(): void {
  setToken("");
  try {
    window.sessionStorage.removeItem(VERIFIER_KEY);
    window.sessionStorage.removeItem(STATE_KEY);
    window.localStorage.removeItem(VERIFIER_KEY);
    window.localStorage.removeItem(STATE_KEY);
  } catch {
    // Storage can throw in private-browsing modes. A failure to clear these
    // must not prevent the token removal above or the redirect below.
  }
}

export function cognitoConfigured(): boolean {
  return Boolean(DOMAIN && CLIENT_ID && REDIRECT_URI);
}

function base64UrlEncode(bytes: Uint8Array): string {
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomString(length = 64): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes).slice(0, length);
}

async function sha256(input: string): Promise<Uint8Array> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(digest);
}

// beginSignIn: Redirect to the Cognito Hosted UI to authenticate. Stores the
// PKCE verifier and a CSRF state value for the callback to validate.
export async function beginSignIn(): Promise<void> {
  if (!cognitoConfigured()) return;
  const verifier = randomString(64);
  const challenge = base64UrlEncode(await sha256(verifier));
  const state = randomString(32);
  window.sessionStorage.setItem(VERIFIER_KEY, verifier);
  window.sessionStorage.setItem(STATE_KEY, state);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: "openid email profile",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  window.location.assign(`${DOMAIN}/oauth2/authorize?${params.toString()}`);
}

// completeSignInFromRedirect: If the current URL carries an OAuth ?code, and
// the state matches, exchange it for tokens using the stored PKCE verifier and
// store the id token. Returns true when a sign-in was completed.
export async function completeSignInFromRedirect(): Promise<boolean> {
  if (!cognitoConfigured() || typeof window === "undefined") return false;
  const url = new URL(window.location.href);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code) return false;

  const expectedState = window.sessionStorage.getItem(STATE_KEY);
  const verifier = window.sessionStorage.getItem(VERIFIER_KEY);
  if (!expectedState || state !== expectedState || !verifier) {
    // State mismatch or missing verifier — do not exchange. Clean the URL.
    cleanUrl(url);
    return false;
  }

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: CLIENT_ID,
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
  });

  try {
    const resp = await fetch(`${DOMAIN}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (!resp.ok) return false;
    const tokens = await resp.json();
    // Use the id token: it carries cognito:groups for role resolution.
    const idToken = tokens.id_token || tokens.access_token || "";
    if (idToken) setToken(idToken);
    return Boolean(idToken);
  } finally {
    window.sessionStorage.removeItem(VERIFIER_KEY);
    window.sessionStorage.removeItem(STATE_KEY);
    cleanUrl(url);
  }
}

function cleanUrl(url: URL): void {
  url.searchParams.delete("code");
  url.searchParams.delete("state");
  window.history.replaceState({}, document.title, url.pathname + url.search + url.hash);
}
