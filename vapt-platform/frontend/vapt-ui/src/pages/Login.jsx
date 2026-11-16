import { useEffect, useRef, useState } from "react";

import { useThreeScene } from "../components/cc/ccHooks";
import "../login.css";

function deviceLabel() {
  const ua = typeof navigator !== "undefined" ? navigator.userAgent : "";
  const browser = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS X/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
}

/** Decorative wireframe globe with a sweeping scan ring. No data is shown here. */
function ScanGlobe() {
  const ref = useRef(null);
  useThreeScene(
    ref,
    ({ scene, camera, THREE }) => {
      camera.position.set(0, 0, 11);
      const group = new THREE.Group();
      scene.add(group);

      const globe = new THREE.LineSegments(
        new THREE.WireframeGeometry(new THREE.IcosahedronGeometry(2.6, 3)),
        new THREE.LineBasicMaterial({ color: 0x2e7bff, transparent: true, opacity: 0.34 }),
      );
      group.add(globe);
      group.add(new THREE.Mesh(
        new THREE.SphereGeometry(2.52, 48, 48),
        new THREE.MeshBasicMaterial({ color: 0x061227, transparent: true, opacity: 0.9 }),
      ));

      const pointGeometry = new THREE.BufferGeometry();
      const positions = [];
      for (let i = 0; i < 90; i += 1) {
        const phi = Math.acos(1 - (2 * (i + 0.5)) / 90);
        const theta = Math.PI * (1 + Math.sqrt(5)) * i;
        positions.push(2.62 * Math.sin(phi) * Math.cos(theta), 2.62 * Math.cos(phi), 2.62 * Math.sin(phi) * Math.sin(theta));
      }
      pointGeometry.setAttribute("position", new THREE.Float32BufferAttribute(positions, 3));
      group.add(new THREE.Points(pointGeometry, new THREE.PointsMaterial({ color: 0x5ce1ff, size: 0.06, transparent: true, opacity: 0.9 })));

      const rings = [3.1, 3.5].map((radius, index) => {
        const ring = new THREE.Mesh(
          new THREE.TorusGeometry(radius, 0.012, 8, 160),
          new THREE.MeshBasicMaterial({ color: index ? 0x2e7bff : 0x5ce1ff, transparent: true, opacity: index ? 0.35 : 0.7 }),
        );
        ring.rotation.x = Math.PI / 2.3 + index * 0.5;
        scene.add(ring);
        return ring;
      });
      const sweep = new THREE.Mesh(
        new THREE.TorusGeometry(2.66, 0.02, 8, 120),
        new THREE.MeshBasicMaterial({ color: 0x5ce1ff, transparent: true, opacity: 0.85 }),
      );
      sweep.rotation.x = Math.PI / 2;
      group.add(sweep);

      return {
        update(t, _dt, size) {
          // Pull the camera back on narrow or short panels so the rings always fit.
          const aspect = size && size.height ? size.width / size.height : 1;
          camera.position.z = 11 / Math.min(1, Math.max(0.45, aspect * 0.95));
          group.rotation.y = t * 0.12;
          group.rotation.x = 0.25 + Math.sin(t * 0.2) * 0.05;
          rings[0].rotation.z = t * 0.25;
          rings[1].rotation.z = -t * 0.16;
          const y = Math.sin(t * 0.7) * 2.5;
          sweep.position.y = y;
          sweep.scale.setScalar(Math.max(0.05, Math.sqrt(Math.max(0, 1 - (y / 2.66) ** 2))));
        },
      };
    },
    [],
  );
  return <div ref={ref} className="lg-globe" aria-hidden="true" />;
}

export default function Login({ onLogin, onStartSso, onCancelMfa, isSubmitting = false, errorMessage = "", awaitingMfa = false, authConfig }) {
  const [form, setForm] = useState({ username: "", password: "", otpCode: "", captchaToken: "" });
  const [showPassword, setShowPassword] = useState(false);
  const [localError, setLocalError] = useState("");
  const codeRef = useRef(null);

  const policy = authConfig?.policy || {};
  const providers = authConfig?.providers || [];
  const allowLocal = policy.allow_local_login !== false;
  const needsCode = Boolean(policy.captcha_enabled);
  const error = localError || errorMessage;

  useEffect(() => {
    if (awaitingMfa) codeRef.current?.focus();
  }, [awaitingMfa]);

  const set = (key) => (event) => {
    setLocalError("");
    setForm((current) => ({ ...current, [key]: event.target.value }));
  };

  const submit = (event) => {
    event.preventDefault();
    if (!form.username.trim() || !form.password) return setLocalError("Enter your username and password.");
    if (awaitingMfa && !/^\d{6,8}$/.test(form.otpCode.trim())) return setLocalError("Enter the 6-digit verification code.");
    if (needsCode && !form.captchaToken.trim()) return setLocalError("Enter the access code your administrator gave you.");
    return onLogin?.({ ...form, deviceName: deviceLabel() });
  };

  const backToPassword = () => {
    setForm((current) => ({ ...current, otpCode: "" }));
    setLocalError("");
    onCancelMfa?.();
  };

  return (
    <div className="lg">
      <aside className="lg-side">
        <div className="lg-brand">
          <svg width="26" height="26" viewBox="0 0 22 22" aria-hidden="true">
            <circle cx="11" cy="11" r="9" stroke="#5ce1ff" strokeWidth="2" fill="none" />
            <circle cx="11" cy="11" r="3" fill="#5ce1ff" />
          </svg>
          VAPTICOM
        </div>
        <ScanGlobe />
        <div className="lg-side__copy">
          <h2>Vulnerability assessment and penetration testing, in one console.</h2>
          <ul>
            <li>Network, web and mobile scanning</li>
            <li>Findings ranked by real-world exploitation</li>
            <li>Reports your auditors can read</li>
          </ul>
        </div>
      </aside>

      <main className="lg-main">
        <form className="lg-card" onSubmit={submit} noValidate>
          <div className="lg-brand lg-brand--mobile">
            <svg width="22" height="22" viewBox="0 0 22 22" aria-hidden="true">
              <circle cx="11" cy="11" r="9" stroke="#5ce1ff" strokeWidth="2" fill="none" />
              <circle cx="11" cy="11" r="3" fill="#5ce1ff" />
            </svg>
            VAPTICOM
          </div>
          <h1>{awaitingMfa ? "Verify it's you" : "Sign in"}</h1>
          <p className="lg-lead">
            {awaitingMfa
              ? "Enter the 6-digit code from your authenticator app, or the code we emailed you."
              : allowLocal ? "Use your Vapticom account." : "Password sign-in is turned off. Use single sign-on."}
          </p>

          {error ? <p className="lg-error" role="alert">{error}</p> : null}

          {allowLocal && !awaitingMfa ? (
            <>
              <label className="lg-field">
                <span>Username</span>
                <input name="username" autoComplete="username" autoCapitalize="none" spellCheck="false" autoFocus value={form.username} onChange={set("username")} />
              </label>
              <label className="lg-field">
                <span>Password</span>
                <span className="lg-password">
                  <input name="password" type={showPassword ? "text" : "password"} autoComplete="current-password" value={form.password} onChange={set("password")} />
                  <button type="button" onClick={() => setShowPassword((v) => !v)} aria-pressed={showPassword}>{showPassword ? "Hide" : "Show"}</button>
                </span>
              </label>
              {needsCode ? (
                <label className="lg-field">
                  <span>Access code</span>
                  <input name="access-code" autoComplete="off" value={form.captchaToken} onChange={set("captchaToken")} />
                  <small>Required by your administrator for every sign-in.</small>
                </label>
              ) : null}
            </>
          ) : null}

          {allowLocal && awaitingMfa ? (
            <label className="lg-field">
              <span>Verification code</span>
              <input ref={codeRef} className="lg-code" name="one-time-code" inputMode="numeric" autoComplete="one-time-code" maxLength={8} value={form.otpCode}
                onChange={(event) => { setLocalError(""); setForm((current) => ({ ...current, otpCode: event.target.value.replace(/\D/g, "") })); }} />
              <small>Signing in as <strong>{form.username}</strong></small>
            </label>
          ) : null}

          {allowLocal ? (
            <button className="lg-submit" type="submit" disabled={isSubmitting}>
              {isSubmitting ? "Signing in…" : awaitingMfa ? "Verify and sign in" : "Sign in"}
            </button>
          ) : null}
          {awaitingMfa ? <button type="button" className="lg-link" onClick={backToPassword}>Use a different account</button> : null}

          {providers.length && !awaitingMfa ? (
            <div className="lg-sso">
              {allowLocal ? <p className="lg-or"><span>or</span></p> : null}
              {providers.map((provider) => (
                <button key={provider.id} type="button" className="lg-sso__btn" onClick={() => onStartSso?.(provider.id)}>
                  Continue with {provider.name}
                </button>
              ))}
            </div>
          ) : null}

          <p className="lg-foot">
            No account? Ask your Vapticom administrator to create one.
            <br />
            Authorized users only. Sign-ins are logged.
          </p>
        </form>
      </main>
    </div>
  );
}
