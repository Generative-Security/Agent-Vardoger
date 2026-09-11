import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { AuthProvider, getToken, isJwtExpired } from "./auth";
import { beginSignIn, cognitoConfigured, completeSignInFromRedirect } from "./signin";
import "./styles/globals.css";

// Bootstrap auth before rendering. In cognito mode: finish any OAuth redirect,
// and if we still have no token, send the user to the Hosted UI to sign in.
// In none/token mode this is a no-op and the app renders immediately.
async function bootstrap() {
  if (cognitoConfigured()) {
    const signedIn = await completeSignInFromRedirect();
    // Re-trigger sign-in when there is no token OR the stored token is expired
    // (an expired token is non-empty, so a plain existence check would leave
    // the user stuck on silent 401s).
    const token = getToken();
    if (!signedIn && (!token || isJwtExpired(token))) {
      await beginSignIn();
      return; // navigating away to the Hosted UI
    }
  }

  ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <BrowserRouter>
        <AuthProvider>
          <App />
        </AuthProvider>
      </BrowserRouter>
    </React.StrictMode>
  );
}

void bootstrap();
