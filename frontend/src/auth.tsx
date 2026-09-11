import { createContext, ReactNode, useContext, useMemo } from "react";

// Ascending privilege: viewer < operator < admin. Mirrors the backend RBAC in
// control_plane/dependencies.py. The backend is the real gate; the UI only uses
// this to hide/disable controls the caller's role cannot use.
export type AppRole = "viewer" | "operator" | "admin";

const ROLE_RANK: Record<AppRole, number> = { viewer: 1, operator: 2, admin: 3 };

// Where the bearer token lives, when auth is enabled (Cognito via API Gateway).
// In local dev (VARDOGER_AUTH_MODE=none) there is no token and the caller is
// treated as admin, mirroring the backend.
const TOKEN_KEY = "vardoger.token";

export interface AuthUser {
  role: AppRole;
  subject: string;
}

interface AuthContextValue {
  user: AuthUser;
  role: AppRole;
  hasRole: (min: AppRole) => boolean;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

// authMode: the deployment's auth mode, baked in at build time. Drives which
// sign-in surface the SPA shows. "none" (dev) needs no sign-in; "token" shows
// the access-token entry; "cognito" uses the Hosted UI (see signin.ts).
export type AuthMode = "none" | "token" | "cognito";
export function authMode(): AuthMode {
  const m = (import.meta.env.VITE_AUTH_MODE || "none").toLowerCase();
  if (m === "token") return "token";
  if (m === "cognito" || m === "cognito+identity-center") return "cognito";
  return "none";
}

// getToken: Returns the stored bearer token, or "" when none (local dev).
export function getToken(): string {
  if (typeof window === "undefined") return "";
  return window.localStorage.getItem(TOKEN_KEY) || "";
}

// setToken: Store the bearer token (token mode: the shared secret; cognito
// mode: the id/access token from the sign-in flow).
export function setToken(token: string): void {
  if (typeof window === "undefined") return;
  if (token) window.localStorage.setItem(TOKEN_KEY, token);
  else window.localStorage.removeItem(TOKEN_KEY);
}

// logout: Clear the stored token and return to a clean state. Callers should
// redirect to the sign-in view afterwards.
export function logout(): void {
  setToken("");
}

// isJwtExpired: True when a JWT's exp claim is in the past. Non-JWT tokens
// (e.g. the token-mode shared secret) have no exp and are treated as valid.
export function isJwtExpired(token: string): boolean {
  const claims = decodeJwtClaims(token);
  const exp = typeof claims["exp"] === "number" ? (claims["exp"] as number) : 0;
  if (!exp) return false;
  return Date.now() >= exp * 1000;
}

// decodeJwtClaims: Best-effort decode of a JWT payload WITHOUT verifying the
// signature. Verification is the API Gateway Cognito authorizer's job; here we
// only read claims to render role-appropriate UI. Returns {} when unparseable.
function decodeJwtClaims(token: string): Record<string, unknown> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return {};
    const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = payload + "=".repeat((4 - (payload.length % 4)) % 4);
    const decoded = atob(padded);
    const parsed = JSON.parse(decoded);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

// roleFromClaims: Map Cognito claims to one of viewer/operator/admin from the
// cognito:groups claim only (highest group wins). Mirrors backend
// _role_from_claims, which likewise ignores any custom role claim.
function roleFromClaims(claims: Record<string, unknown>): AppRole | "" {
  const resolved: AppRole[] = [];

  const groups = claims["cognito:groups"];
  let groupValues: string[] = [];
  if (typeof groups === "string") {
    groupValues = groups.replace(/,/g, " ").split(/\s+/).filter(Boolean);
  } else if (Array.isArray(groups)) {
    groupValues = groups.map((g) => String(g).trim());
  }
  for (const group of groupValues) {
    const lower = group.toLowerCase();
    if (lower === "viewer" || lower === "operator" || lower === "admin") resolved.push(lower);
  }

  // Role comes ONLY from cognito:groups, matching the backend. A user-writable
  // role / custom:role claim is deliberately NOT honored — the backend refuses
  // it, so honoring it here would only surface admin controls that then 403.

  if (resolved.length === 0) return "";
  return resolved.reduce((best, r) => (ROLE_RANK[r] > ROLE_RANK[best] ? r : best), resolved[0]);
}

// isJwt: A JWT has exactly three dot-separated segments. The token-mode shared
// secret is not a JWT, so we can distinguish the two auth modes by shape.
function isJwt(token: string): boolean {
  return token.split(".").length === 3;
}

// resolveUser: Reads the caller's role from a bearer token if present, else
// defaults to "admin" for local dev (mirrors backend VARDOGER_AUTH_MODE=none).
function resolveUser(): AuthUser {
  const token = getToken();
  if (!token) return { role: "admin", subject: "local-dev" };

  // Token mode: the stored value is the shared secret, not a JWT. The backend
  // maps a valid secret to admin, so the UI mirrors that. (A wrong secret still
  // 401s server-side — this only controls which controls are shown.)
  if (!isJwt(token)) {
    return { role: "admin", subject: "token-operator" };
  }

  // Cognito mode: the token is a JWT. An expired one cannot be recovered here;
  // drop it so the user is prompted to re-authenticate instead of silent 401s.
  if (isJwtExpired(token)) {
    logout();
    return { role: "viewer", subject: "" };
  }
  const claims = decodeJwtClaims(token);
  const role = roleFromClaims(claims);
  const subject = String(
    claims["sub"] || claims["username"] || claims["cognito:username"] || "",
  );
  // If a JWT is present but carries no resolvable role, fall back to viewer
  // (least privilege) on the client. The backend still enforces the real gate.
  return { role: role || "viewer", subject };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const value = useMemo<AuthContextValue>(() => {
    const user = resolveUser();
    return {
      user,
      role: user.role,
      hasRole: (min: AppRole) => ROLE_RANK[user.role] >= ROLE_RANK[min],
      logout: () => {
        logout();
        if (typeof window !== "undefined") window.location.reload();
      },
    };
  }, []);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}
