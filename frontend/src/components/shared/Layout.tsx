import { Link, useLocation } from "react-router-dom";
import { ReactNode } from "react";
import { AppRole, authMode, useAuth } from "../../auth";
import { signOut } from "../../signin";

interface NavItem {
  path: string;
  label: string;
  // Minimum role required to see the item. Omitted => visible to all roles.
  minRole?: AppRole;
}

const MONITORING: NavItem[] = [
  { path: "/dashboard", label: "Dashboard" },
  { path: "/detections", label: "Detections" },
  { path: "/prompt-history", label: "Prompt History" },
  { path: "/health", label: "Health" },
  { path: "/test-console", label: "Test Console", minRole: "operator" },
];

const ADMIN: NavItem[] = [
  { path: "/policy", label: "Security Policy" },
  { path: "/signatures", label: "Signatures" },
  { path: "/evaluation", label: "Evaluation" },
  { path: "/sources", label: "Sources" },
  { path: "/settings", label: "Settings" },
];

const ROLE_LABEL: Record<AppRole, string> = {
  viewer: "Viewer",
  operator: "Operator",
  admin: "Admin",
};

const ROLE_BADGE: Record<AppRole, string> = {
  viewer: "bg-slate-100 text-slate-700 ring-1 ring-slate-200",
  operator: "bg-blue-50 text-blue-700 ring-1 ring-blue-200",
  admin: "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200",
};

// NavGroup: Renders one labelled cluster of nav links, filtered by role.
function NavGroup({ label, items, pathname, hasRole }: {
  label: string;
  items: NavItem[];
  pathname: string;
  hasRole: (min: AppRole) => boolean;
}) {
  const visible = items.filter((item) => !item.minRole || hasRole(item.minRole));
  if (visible.length === 0) return null;
  return (
    <div className="flex items-center gap-1">
      <span className="px-2 text-[11px] font-semibold uppercase tracking-wide text-slate-400">{label}</span>
      <div className="flex flex-wrap gap-1 rounded-lg bg-slate-100 p-1">
        {visible.map((n) => (
          <Link
            key={n.path}
            to={n.path}
            className={`rounded-md px-3 py-2 text-sm font-semibold transition ${
              pathname === n.path || pathname.startsWith(`${n.path}/`)
                ? "bg-white text-slate-950 shadow-sm"
                : "text-slate-500 hover:text-slate-950"
            }`}
          >
            {n.label}
          </Link>
        ))}
      </div>
    </div>
  );
}

// Layout: Renders the layout UI section.
export default function Layout({ children }: { children: ReactNode }) {
  const location = useLocation();
  const { role, hasRole } = useAuth();

  return (
    <div className="min-h-screen bg-slate-50 text-slate-950">
      <nav className="border-b border-slate-200 bg-white">
        <div className="mx-auto max-w-7xl px-6 py-4">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
            <Link to="/" className="flex items-center gap-3">
              <span className="text-xl font-semibold tracking-tight text-slate-950">Agent Vardøger</span>
              <span className="rounded-full bg-slate-950 px-3 py-1 text-xs font-semibold text-white">
                Self-hosted
              </span>
            </Link>

            <div className="flex flex-wrap items-center gap-3">
              <NavGroup label="Monitoring" items={MONITORING} pathname={location.pathname} hasRole={hasRole} />
              <NavGroup label="Admin" items={ADMIN} pathname={location.pathname} hasRole={hasRole} />
              <div className="flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2">
                <span className="text-[11px] font-medium text-slate-500">Role</span>
                <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${ROLE_BADGE[role]}`}>
                  {ROLE_LABEL[role]}
                </span>
              </div>
              {authMode() !== "none" && (
                <button
                  type="button"
                  onClick={signOut}
                  className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-600 hover:bg-slate-50 hover:text-slate-900"
                >
                  Sign out
                </button>
              )}
            </div>
          </div>
        </div>
      </nav>
      <main className="mx-auto max-w-7xl px-6 py-8">{children}</main>
    </div>
  );
}
