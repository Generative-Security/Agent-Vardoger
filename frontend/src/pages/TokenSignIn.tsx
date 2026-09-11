import { FormEvent, useState } from "react";
import { setToken } from "../auth";

// TokenSignIn: minimal access-token entry for token auth mode. The operator
// pastes the shared secret printed by deploy.sh; it is stored and the app
// reloads with the token attached to every request. This exists because token
// mode has no Cognito Hosted UI — it is the single-operator sign-in surface.
export default function TokenSignIn() {
  const [value, setValue] = useState("");

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    const token = value.trim();
    if (!token) return;
    setToken(token);
    window.location.reload();
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-md rounded-lg border border-slate-800 bg-slate-900 p-6 shadow-lg"
      >
        <h1 className="text-lg font-semibold text-slate-100">Agent Vardøger</h1>
        <p className="mt-1 text-sm text-slate-400">
          Enter your access token to continue. This is the secret printed by the
          deployment (token auth mode).
        </p>
        <input
          type="password"
          autoFocus
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="Access token"
          className="mt-4 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-blue-600"
        />
        <button
          type="submit"
          className="mt-4 w-full rounded-md bg-blue-700 px-3 py-2 text-sm font-semibold text-white hover:bg-blue-600"
        >
          Continue
        </button>
      </form>
    </div>
  );
}
