import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// The dev-server /api proxy target is configurable via VITE_DEV_PROXY so you
// can point the dev server at a backend on a different host/port without
// editing this file. Defaults to the local control plane on :8000.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const proxyTarget = env.VITE_DEV_PROXY || "http://localhost:8000";
  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        "/api": {
          target: proxyTarget,
          changeOrigin: true,
        },
      },
    },
  };
});
