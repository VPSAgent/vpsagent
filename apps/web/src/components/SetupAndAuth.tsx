import { useCallback, useEffect, useState } from "react";
import {
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  Loader2,
  Lock,
  RefreshCw,
} from "lucide-react";
import { api, type SessionInfo, type TailscaleStatus } from "../api";
import { describeTailscaleConflict } from "../tailscale-conflict";
import { Logo } from "../brand/Logo";

interface SetupAndAuthProps {
  session: SessionInfo;
  onAuthenticated: () => Promise<void>;
}

const TAILSCALE_INSTALL_CMD =
  "curl -fsSL https://tailscale.com/install.sh | sudo sh && sudo tailscale up";

function extractClaimFromHash(): string {
  const hash = window.location.hash || "";
  const match = hash.match(/claim=([^&]+)/);
  return match?.[1] ? decodeURIComponent(match[1]) : "";
}

export function SetupAndAuth({ session, onAuthenticated }: SetupAndAuthProps) {
  const [step, setStep] = useState<1 | 2>(session.claimed ? 2 : 1);
  const [claimToken, setClaimToken] = useState(() => extractClaimFromHash());
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [domain, setDomain] = useState(session.setup.domain ?? "");
  const [acmeEmail, setAcmeEmail] = useState(session.setup.acmeEmail ?? "");
  const [accessMode, setAccessMode] = useState<"domain" | "tailscale">(() =>
    session.setup.domain
      ? "domain"
      : session.setup.tailscaleServeEnabled || session.setup.tailscaleDomain
        ? "tailscale"
        : "domain",
  );
  const [tsStatus, setTsStatus] = useState<TailscaleStatus | null>(null);
  const [tsBridgeSupported, setTsBridgeSupported] = useState(true);
  const [tsLoading, setTsLoading] = useState(false);
  const [tsLoginUrl, setTsLoginUrl] = useState<string | null>(null);
  const [tsCopied, setTsCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fromHash = extractClaimFromHash();
    if (fromHash) {
      setClaimToken(fromHash);
      window.history.replaceState(null, "", window.location.pathname);
    }
  }, []);

  const refreshTailscaleStatus = useCallback(async () => {
    setTsLoading(true);
    try {
      const res = await api.getTailscaleStatus();
      setTsStatus(res.status);
      setTsBridgeSupported(res.bridgeSupported);
      if (res.status.loginUrl) {
        setTsLoginUrl(res.status.loginUrl);
      }
      if (
        !session.setup.domain &&
        (res.status.serveEnabled || res.status.connected)
      ) {
        setAccessMode((prev) => (prev === "domain" && domain.trim() ? prev : "tailscale"));
      }
    } catch {
      // Non-fatal during setup
    } finally {
      setTsLoading(false);
    }
  }, [domain, session.setup.domain]);

  useEffect(() => {
    if (step === 2) {
      void refreshTailscaleStatus();
    }
  }, [step, refreshTailscaleStatus]);

  if (session.claimed && !session.authenticated) {
    const handleLogin = async (e: React.FormEvent) => {
      e.preventDefault();
      setError(null);
      setBusy(true);
      try {
        await api.login(passphrase);
        await onAuthenticated();
      } catch (err) {
        setError(err instanceof Error ? err.message : "Could not sign in.");
      } finally {
        setBusy(false);
      }
    };

    return (
      <div className="min-h-screen flex items-center justify-center p-6 bg-canvas">
        <div className="surface-panel w-full max-w-md rounded-lg p-8">
          <div className="mb-8 space-y-5">
            <Logo markSize={48} textClassName="text-[32px]" className="gap-3.5" />
            <h1 className="text-sm text-muted">Sign in to your server</h1>
          </div>

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-muted mb-1.5">
                Owner password
              </label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Enter your dashboard password"
                required
                autoFocus
                className="field-input w-full rounded-lg px-3.5 py-2.5 text-sm"
              />
            </div>

            {error && (
              <div className="rounded-lg border border-line-strong px-3.5 py-2.5 text-xs text-muted hover:text-bad">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={busy}
              className="btn-press w-full rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer"
            >
              {busy ? "Signing in..." : "Sign in"}
            </button>
          </form>
        </div>
      </div>
    );
  }

  const handleClaim = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (passphrase.length < 8) {
      setError("Choose a password with at least 8 characters.");
      return;
    }
    if (passphrase !== confirmPassphrase) {
      setError("Passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      await api.claimSetup(claimToken, passphrase);
      setStep(2);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not claim server.");
    } finally {
      setBusy(false);
    }
  };

  const handleDomainSave = async (skip: boolean) => {
    setError(null);
    setBusy(true);
    try {
      if (!skip && domain.trim()) {
        await api.updateSetupDomain(
          domain.trim(),
          acmeEmail.trim() || null,
        );
      }
      await onAuthenticated();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save domain.");
    } finally {
      setBusy(false);
    }
  };

  const handleTailscaleConnect = async () => {
    setError(null);
    setBusy(true);
    try {
      const res = await api.connectTailscale({ mode: "login" });
      setTsStatus(res.status);
      setTsLoginUrl(res.loginUrl ?? res.status.loginUrl);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not start Tailscale sign-in.",
      );
    } finally {
      setBusy(false);
    }
  };

  const handleEnableTailscaleAndFinish = async () => {
    setError(null);
    setBusy(true);
    try {
      const res = await api.setTailscaleServe(true, false);
      setTsStatus(res.status);
      await onAuthenticated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Could not enable Tailscale private HTTPS.",
      );
      void refreshTailscaleStatus();
    } finally {
      setBusy(false);
    }
  };

  const tsConflict = tsStatus ? describeTailscaleConflict(tsStatus) : null;

  const copyInstallCmd = async () => {
    await navigator.clipboard.writeText(TAILSCALE_INSTALL_CMD);
    setTsCopied(true);
    setTimeout(() => setTsCopied(false), 2000);
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-6 bg-canvas">
      <div className="surface-panel w-full max-w-lg rounded-lg p-8">
        <div className="mb-7 space-y-5">
          <Logo markSize={48} textClassName="text-[32px]" className="gap-3.5" />
          <div>
            <h1 className="text-base font-medium text-fg">Set up your server</h1>
            <p className="text-xs text-muted">Two quick steps to secure it.</p>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-2.5 mb-6">
          <div
            className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-medium ${
              step === 1
                ? "border-line-strong bg-fill text-fg"
                : "border-line bg-well text-muted"
            }`}
          >
            {step > 1 ? (
              <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
            ) : (
              <Lock className="h-3.5 w-3.5 shrink-0" />
            )}
            <span>1. Set login password</span>
          </div>
          <div
            className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-medium ${
              step === 2
                ? "border-line-strong bg-fill text-fg"
                : "border-line bg-well text-subtle"
            }`}
          >
            <span>2. Private HTTPS access</span>
          </div>
        </div>

        {step === 1 ? (
          <form onSubmit={handleClaim} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-muted mb-1.5">
                Private setup code
              </label>
              <input
                type="text"
                value={claimToken}
                onChange={(e) => setClaimToken(e.target.value)}
                placeholder="Auto-filled from your #claim= installer link"
                required
                className="field-input w-full rounded-lg px-3.5 py-2.5 text-sm font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-muted mb-1.5">
                Choose your dashboard password
              </label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="At least 8 characters"
                required
                className="field-input w-full rounded-lg px-3.5 py-2.5 text-sm"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-muted mb-1.5">
                Confirm password
              </label>
              <input
                type="password"
                value={confirmPassphrase}
                onChange={(e) => setConfirmPassphrase(e.target.value)}
                placeholder="Type your password again"
                required
                className="field-input w-full rounded-lg px-3.5 py-2.5 text-sm"
              />
            </div>

            {error && (
              <div className="rounded-lg border border-line-strong px-3.5 py-2.5 text-xs text-muted hover:text-bad">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={busy}
              className="btn-press w-full rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer"
            >
              {busy ? "Claiming server..." : "Save password & continue"}
            </button>
          </form>
        ) : (
          <div className="space-y-4">
            <div
              role="tablist"
              aria-label="HTTPS access method"
              className="grid grid-cols-2 rounded-lg border border-line bg-well p-1 gap-1"
            >
              <button
                type="button"
                role="tab"
                aria-selected={accessMode === "domain"}
                onClick={() => {
                  setAccessMode("domain");
                  setError(null);
                }}
                className={`btn-press inline-flex items-center justify-center gap-1.5 rounded-md px-3 py-2 text-xs font-medium cursor-pointer ${
                  accessMode === "domain"
                    ? "bg-fill text-fg"
                    : "text-muted hover:text-fg"
                }`}
              >
                <span>Custom domain</span>
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={accessMode === "tailscale"}
                onClick={() => {
                  setAccessMode("tailscale");
                  setError(null);
                }}
                className={`btn-press inline-flex items-center justify-center gap-1.5 rounded-md px-3 py-2 text-xs font-medium cursor-pointer ${
                  accessMode === "tailscale"
                    ? "bg-fill text-fg"
                    : "text-muted hover:text-fg"
                }`}
              >
                <span>Tailscale (no domain)</span>
              </button>
            </div>

            {accessMode === "domain" ? (
              <>
                <p className="text-sm text-muted leading-relaxed">
                  Connect a domain name so your dashboard and AI connection get
                  automatic <code className="text-fg">https://</code>{" "}
                  security.
                  {session.publicIp && (
                    <>
                      {" "}
                      Point your domain&apos;s DNS{" "}
                      <strong className="text-fg">A record</strong> to{" "}
                      <code className="rounded bg-fill px-1.5 py-0.5 text-fg">
                        {session.publicIp}
                      </code>
                      .
                    </>
                  )}
                </p>

                <div>
                  <label className="block text-xs font-medium text-muted mb-1.5">
                    Dashboard domain name
                  </label>
                  <input
                    type="text"
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                    placeholder="vps.yourdomain.com"
                    className="field-input w-full rounded-lg px-3.5 py-2.5 text-sm"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-muted mb-1.5">
                    Email for security certificate notices (optional)
                  </label>
                  <input
                    type="email"
                    value={acmeEmail}
                    onChange={(e) => setAcmeEmail(e.target.value)}
                    placeholder="you@yourdomain.com"
                    className="field-input w-full rounded-lg px-3.5 py-2.5 text-sm"
                  />
                </div>

                {error && (
                  <div className="rounded-lg border border-line-strong px-3.5 py-2.5 text-xs text-muted hover:text-bad">
                    {error}
                  </div>
                )}

                <div className="flex gap-3 pt-1">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => handleDomainSave(false)}
                    className="btn-press flex-1 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer"
                  >
                    {busy ? "Saving..." : "Connect domain & finish"}
                  </button>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => handleDomainSave(true)}
                    className="btn-press rounded-lg border border-line-strong bg-surface px-4 py-2.5 text-sm font-medium text-muted hover:text-fg hover:bg-surface-2 cursor-pointer"
                  >
                    Skip for now
                  </button>
                </div>
              </>
            ) : (
              <div className="space-y-4">
                <p className="text-sm text-muted leading-relaxed">
                  Use Tailscale for private{" "}
                  <code className="text-fg">https://</code> access to
                  your dashboard and AI connection without buying a domain or
                  configuring DNS.
                </p>

                {tsLoading && !tsStatus ? (
                  <div className="surface-well rounded-lg px-4 py-3 text-xs text-muted flex items-center gap-2">
                    <Loader2 className="h-3.5 w-3.5 animate-spin text-muted" />
                    Checking Tailscale on this server...
                  </div>
                ) : !tsBridgeSupported ? (
                  <div className="surface-well rounded-lg px-4 py-3 text-xs text-muted">
                    {tsStatus?.detail ||
                      "Re-run the installer with --tailscale or skip for now to enable Tailscale in Settings."}
                  </div>
                ) : tsStatus?.serveEnabled && tsStatus.serveUrl ? (
                  <div className="rounded-lg border border-line bg-surface-2 px-4 py-3 text-xs text-fg-2 space-y-1.5">
                    <p className="font-medium text-ok">
                      Tailscale private HTTPS is active
                    </p>
                    <p className="font-mono break-all text-fg">
                      {tsStatus.serveUrl}
                    </p>
                    {tsStatus.tailscaleIp && (
                      <p className="text-fg font-mono">
                        Tailscale IP: {tsStatus.tailscaleIp}
                      </p>
                    )}
                  </div>
                ) : tsStatus?.connected ? (
                  <div className="surface-well rounded-lg p-4 space-y-2.5 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium text-ok">
                        Tailscale connected
                      </span>
                      <button
                        type="button"
                        disabled={tsLoading}
                        onClick={() => void refreshTailscaleStatus()}
                        className="inline-flex items-center gap-1 text-muted hover:text-fg cursor-pointer"
                      >
                        <RefreshCw
                          className={`h-3 w-3 ${tsLoading ? "animate-spin" : ""}`}
                        />
                        Refresh
                      </button>
                    </div>
                    {tsStatus.tailscaleIp && (
                      <p className="text-muted">
                        Tailscale IP:{" "}
                        <code className="font-mono text-fg">
                          {tsStatus.tailscaleIp}
                        </code>
                      </p>
                    )}
                    {tsStatus.dnsName && (
                      <p className="text-muted">
                        MagicDNS address:{" "}
                        <code className="font-mono text-fg">
                          {tsStatus.dnsName}
                        </code>
                      </p>
                    )}
                    {!tsStatus.httpsCertsAvailable && (
                      <div className="rounded-md border border-warn-line bg-warn-soft px-3 py-2 text-warn">
                        Enable MagicDNS and HTTPS Certificates in{" "}
                        <a
                          href="https://login.tailscale.com/admin/dns"
                          target="_blank"
                          rel="noreferrer"
                          className="underline font-medium text-warn"
                        >
                          Tailscale DNS settings
                        </a>{" "}
                        before turning on private HTTPS.
                      </div>
                    )}
                    {tsConflict && (
                      <div className="rounded-md border border-warn-line bg-warn-soft px-3 py-2.5 text-warn space-y-2">
                        <p>{tsConflict.headline}</p>
                        <ul className="space-y-1.5">
                          {tsConflict.effects.map((effect) => (
                            <li
                              key={`${effect.kind}:${effect.routes}`}
                              className="rounded border border-warn-line bg-well px-2.5 py-1.5 space-y-0.5"
                            >
                              <div className="font-medium text-warn">
                                {effect.label}
                              </div>
                              <div className="font-mono text-[11px] text-warn break-all">
                                {effect.routes}
                              </div>
                              <div className="text-[11px] text-warn">
                                {effect.explanation}
                              </div>
                            </li>
                          ))}
                        </ul>
                        <p className="text-[11px] text-warn">
                          Setup leaves your existing port 443 routes untouched.
                          Move those services and click Refresh, or continue to
                          the dashboard and confirm the exact changes in AI Keys
                          &amp; Settings &rarr; Tailscale private access.
                        </p>
                      </div>
                    )}
                  </div>
                ) : tsStatus?.installed ? (
                  <div className="surface-well rounded-lg p-4 space-y-3 text-xs">
                    <p className="text-fg-2">
                      Tailscale is installed on this server. Sign in to connect
                      it to your tailnet, then turn on private HTTPS.
                    </p>
                    {tsLoginUrl && (
                      <a
                        href={tsLoginUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="btn-press inline-flex items-center gap-1.5 rounded-lg border border-line-strong px-3 py-2 font-medium text-fg hover:bg-fill"
                      >
                        <span>Open Tailscale sign-in</span>
                        <ExternalLink className="h-3.5 w-3.5" />
                      </a>
                    )}
                    <div className="flex flex-wrap gap-2">
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => void handleTailscaleConnect()}
                        className="btn-press rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer"
                      >
                        {busy ? "Starting..." : "Sign in to Tailscale"}
                      </button>
                      <button
                        type="button"
                        disabled={tsLoading}
                        onClick={() => void refreshTailscaleStatus()}
                        className="btn-press inline-flex items-center gap-1 rounded-lg border border-line-strong bg-surface px-3 py-1.5 text-xs font-medium text-fg-2 hover:text-fg cursor-pointer"
                      >
                        <RefreshCw
                          className={`h-3 w-3 ${tsLoading ? "animate-spin" : ""}`}
                        />
                        Refresh status
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="surface-well rounded-lg p-4 space-y-3 text-xs">
                    <p className="text-fg-2">
                      Tailscale isn&apos;t installed on this server yet. Run
                      this command on your server, or skip for now and enable it
                      anytime in Settings:
                    </p>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 overflow-x-auto rounded-md bg-canvas border border-line px-3 py-2 font-mono text-[11px] text-fg-2">
                        {TAILSCALE_INSTALL_CMD}
                      </code>
                      <button
                        type="button"
                        onClick={() => void copyInstallCmd()}
                        className="btn-press inline-flex items-center gap-1 rounded-md border border-line-strong bg-surface px-2.5 py-2 text-xs font-medium text-fg hover:bg-surface-2 cursor-pointer shrink-0"
                      >
                        {tsCopied ? (
                          <Check className="h-3.5 w-3.5 text-ok" />
                        ) : (
                          <Copy className="h-3.5 w-3.5" />
                        )}
                        {tsCopied ? "Copied" : "Copy"}
                      </button>
                    </div>
                    <button
                      type="button"
                      disabled={tsLoading}
                      onClick={() => void refreshTailscaleStatus()}
                      className="btn-press inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-surface px-3 py-1.5 text-xs font-medium text-fg-2 hover:text-fg cursor-pointer"
                    >
                      <RefreshCw
                        className={`h-3 w-3 ${tsLoading ? "animate-spin" : ""}`}
                      />
                      Check again
                    </button>
                  </div>
                )}

                {error && (
                  <div className="rounded-lg border border-line-strong px-3.5 py-2.5 text-xs text-muted hover:text-bad">
                    {error}
                  </div>
                )}

                <div className="flex gap-3 pt-1">
                  {tsStatus?.serveEnabled ? (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => void onAuthenticated()}
                      className="btn-press flex-1 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer"
                    >
                      Continue to dashboard
                    </button>
                  ) : tsStatus?.connected && tsStatus.serveConflict ? (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => handleDomainSave(true)}
                      className="btn-press flex-1 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer"
                    >
                      Continue to dashboard
                    </button>
                  ) : tsStatus?.connected && tsStatus.dnsName ? (
                    <>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => void handleEnableTailscaleAndFinish()}
                        className="btn-press flex-1 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer"
                      >
                        {busy ? "Enabling..." : "Enable private HTTPS & finish"}
                      </button>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => handleDomainSave(true)}
                        className="btn-press rounded-lg border border-line-strong bg-surface px-4 py-2.5 text-sm font-medium text-muted hover:text-fg hover:bg-surface-2 cursor-pointer"
                      >
                        Skip for now
                      </button>
                    </>
                  ) : (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => handleDomainSave(true)}
                      className="btn-press flex-1 rounded-lg border border-line-strong bg-surface px-4 py-2.5 text-sm font-medium text-muted hover:text-fg hover:bg-surface-2 cursor-pointer"
                    >
                      Skip for now
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
