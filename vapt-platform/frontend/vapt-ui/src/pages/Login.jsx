import { useState } from "react";

export default function Login({ onLogin, onStartSso, isSubmitting, errorMessage, awaitingMfa, authConfig }) {
  const [form, setForm] = useState({ username: "", password: "", otpCode: "", captchaToken: "", deviceName: "Primary browser" });
  const policy = authConfig?.policy || {};
  const providers = authConfig?.providers || [];

  const handleSubmit = async (event) => {
    event.preventDefault();
    await onLogin(form);
  };

  return (
    <div className="auth-shell">
      <div className="auth-shell__background" />
      <section className="auth-card">
        <div className="auth-card__hero">
          <p className="eyebrow">Enterprise Security Operations</p>
          <h1>Sign in to VAPTICOM</h1>
          <p>
            Access network assessments, findings, threat context, and operator workflows from a
            single control plane.
          </p>
        </div>

        <form className="auth-form" onSubmit={handleSubmit}>
          {!policy.allow_local_login ? (
            <p className="scan-feedback scan-feedback--loading">
              Local sign-in is disabled by policy. Use one of the configured SSO providers.
            </p>
          ) : null}

          <label className="auth-field">
            <span>Username</span>
            <input
              autoComplete="username"
              value={form.username}
              onChange={(event) => setForm((current) => ({ ...current, username: event.target.value }))}
              placeholder="admin"
              disabled={!policy.allow_local_login}
            />
          </label>

          <label className="auth-field">
            <span>Password</span>
            <input
              type="password"
              autoComplete="current-password"
              value={form.password}
              onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
              placeholder="Enter your password"
              disabled={!policy.allow_local_login}
            />
          </label>

          <label className="auth-field">
            <span>Verification code {awaitingMfa ? "(required now)" : "(used when MFA is enabled)"}</span>
            <input
              inputMode="numeric"
              value={form.otpCode}
              onChange={(event) => setForm((current) => ({ ...current, otpCode: event.target.value }))}
              placeholder="123456"
              disabled={!policy.allow_local_login}
            />
          </label>

          <label className="auth-field">
            <span>Device label</span>
            <input
              value={form.deviceName}
              onChange={(event) => setForm((current) => ({ ...current, deviceName: event.target.value }))}
              placeholder="Primary browser"
              disabled={!policy.allow_local_login}
            />
          </label>

          <label className="auth-field">
            <span>Captcha token {policy.captcha_enabled ? "(required)" : "(optional)"}</span>
            <input
              value={form.captchaToken}
              onChange={(event) => setForm((current) => ({ ...current, captchaToken: event.target.value }))}
              placeholder="Only required when captcha protection is enabled"
              disabled={!policy.allow_local_login}
            />
          </label>

          {errorMessage ? <p className="auth-error">{errorMessage}</p> : null}

          {awaitingMfa ? (
            <p className="scan-feedback scan-feedback--loading">
              Primary credentials accepted. Enter your authenticator code to complete sign-in.
            </p>
          ) : null}

          <button className="auth-submit" type="submit" disabled={isSubmitting || !policy.allow_local_login}>
            {isSubmitting ? "Signing in..." : awaitingMfa ? "Verify MFA" : "Sign In"}
          </button>

          {providers.length ? (
            <div className="coverage-list">
              {providers.map((provider) => (
                <button key={provider.id} type="button" className="scan-action scan-action--resume" onClick={() => onStartSso(provider.id)}>
                  Continue with {provider.name} ({provider.provider_type.toUpperCase()})
                </button>
              ))}
            </div>
          ) : null}

          <div className="auth-meta">
            <span>JWT session</span>
            <span>Role-based access</span>
            <span>{policy.mfa_required ? "MFA enforced" : "TOTP + session tracking"}</span>
          </div>
        </form>
      </section>
    </div>
  );
}
