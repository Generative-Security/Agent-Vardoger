import { Routes, Route, Navigate } from "react-router-dom";
import { ReactNode } from "react";
import Layout from "./components/shared/Layout";
import { AppRole, authMode, getToken, useAuth } from "./auth";
import TokenSignIn from "./pages/TokenSignIn";
import DashboardPage from "./pages/DashboardPage";
import DetectionsPage from "./pages/DetectionsPage";
import PromptHistoryPage from "./pages/PromptHistoryPage";
import HealthPage from "./pages/HealthPage";
import TestConsolePage from "./pages/TestConsolePage";
import SecurityPolicyPage from "./pages/SecurityPolicyPage";
import SignaturesPage from "./pages/SignaturesPage";
import EvaluationPage from "./pages/EvaluationPage";
import SourcesPage from "./pages/SourcesPage";
import SettingsPage from "./pages/SettingsPage";

// RequireRole: Client-side mirror of the backend RBAC. Redirects to the
// dashboard when the caller's role is below the minimum. The backend is the
// real gate — this only keeps the UI honest.
function RequireRole({ min, children }: { min: AppRole; children: ReactNode }) {
  const { hasRole } = useAuth();
  if (!hasRole(min)) return <Navigate to="/dashboard" replace />;
  return <>{children}</>;
}

// App: Renders the app UI section — a single console, no owner/customer split.
export default function App() {
  // Token mode with no stored token: show the access-token entry screen. (none
  // mode needs no sign-in; cognito mode is handled by the Hosted UI redirect in
  // main.tsx before the app renders.)
  if (authMode() === "token" && !getToken()) {
    return <TokenSignIn />;
  }

  return (
    <Layout>
      <Routes>
        {/* Monitoring — all roles. */}
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/detections" element={<DetectionsPage />} />
        <Route path="/prompt-history" element={<PromptHistoryPage />} />
        <Route path="/health" element={<HealthPage />} />
        <Route
          path="/test-console"
          element={<RequireRole min="operator"><TestConsolePage /></RequireRole>}
        />

        {/* Admin section. */}
        <Route path="/policy" element={<SecurityPolicyPage />} />
        <Route path="/signatures" element={<SignaturesPage />} />
        <Route path="/evaluation" element={<EvaluationPage />} />
        <Route path="/sources" element={<SourcesPage />} />
        <Route path="/settings" element={<SettingsPage />} />

        {/* Defaults. */}
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Layout>
  );
}
