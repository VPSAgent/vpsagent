import { useCallback, useEffect, useState } from "react";
import {
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  Globe,
  Loader2,
  Lock,
  Network,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import { api, type SessionInfo, type TailscaleStatus } from "../api";

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
      <div className="min-h-screen flex items-center justify-center p-6 bg-[#090A0C]">
        <div className="surface-panel panel-enter w-full max-w-md rounded-2xl p-8">
          <div className="flex items-center gap-3 mb-7">
            <div className="h-10 w-10 rounded-xl bg-emerald-500/12 border border-emerald-500/30 flex items-center justify-center">
              <ShieldCheck className="h-5 w-5 text-emerald-400" />
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-[-0.02em] text-white">
                VPSAgent
              </h1>
              <p className="text-xs text-[#9CA3AF]">Sign in to your server</p>
            </div>
          </div>

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
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
              <div className="rounded-lg border border-rose-500/35 bg-rose-500/10 px-3.5 py-2.5 text-xs text-rose-200">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={busy}
              className="btn-press w-full rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-[#042F1E] hover:bg-emerald-400 disabled:opacity-50 cursor-pointer"
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

  const handleEnableTailscaleAndFinish = async (force = false) => {
    setError(null);
    setBusy(true);
    try {
      const res = await api.setTailscaleServe(true, force);
      setTsStatus(res.status);
      await onAuthenticated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Could not enable Tailscale private HTTPS.",
      );
    } finally {
      setBusy(false);
    }
  };

  const copyInstallCmd = async () => {
    await navigator.clipboard.writeText(TAILSCALE_INSTALL_CMD);
    setTsCopied(true);
    setTimeout(() => setTsCopied(false), 2000);
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-6 bg-[#090A0C]">
      <div className="surface-panel panel-enter w-full max-w-lg rounded-2xl p-8">
        <div className="flex items-center gap-3 mb-6">
          <div className="h-10 w-10 rounded-xl bg-emerald-500/12 border border-emerald-500/30 flex items-center justify-center">
            <ShieldCheck className="h-5 w-5 text-emerald-400" />
          </div>
          <div>
            <h1 className="text-lg font-semibold tracking-[-0.02em] text-white">
              Welcome to VPSAgent
            </h1>
            <p className="text-xs text-[#9CA3AF]">
              Quick 2-step setup to lock down your server
            </p>
          </div>
        </div>

        {/* Stepper */}
        <div className="grid grid-cols-2 gap-2.5 mb-6">
          <div
            className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-medium ${
              step === 1
                ? "border-emerald-500/45 bg-emerald-500/10 text-emerald-300"
                : "border-white/[0.08] bg-[#0C0E12] text-emerald-400"
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
                ? "border-emerald-500/45 bg-emerald-500/10 text-emerald-300"
                : "border-white/[0.08] bg-[#0C0E12] text-[#6B7280]"
            }`}
          >
            <Globe className="h-3.5 w-3.5 shrink-0" />
            <span>2. Private HTTPS access</span>
          </div>
        </div>

        {step === 1 ? (
          <form onSubmit={handleClaim} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
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
              <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
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
              <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
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
              <div className="rounded-lg border border-rose-500/35 bg-rose-500/10 px-3.5 py-2.5 text-xs text-rose-200">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={busy}
              className="btn-press w-full rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-[#042F1E] hover:bg-emerald-400 disabled:opacity-50 cursor-pointer"
            >
              {busy ? "Claiming server..." : "Save password & continue"}
            </button>
          </form>
        ) : (
          <div className="space-y-4">
            {/* Access Method Switcher */}
            <div
              role="tablist"
              aria-label="HTTPS access method"
              className="grid grid-cols-2 rounded-lg border border-white/[0.08] bg-[#0C0E12] p-1 gap-1"
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
                    ? "bg-white/[0.1] text-white"
                    : "text-[#9CA3AF] hover:text-white"
                }`}
              >
                <Globe className="h-3.5 w-3.5 text-sky-400" />
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
                    ? "bg-white/[0.1] text-white"
                    : "text-[#9CA3AF] hover:text-white"
                }`}
              >
                <Network className="h-3.5 w-3.5 text-emerald-400" />
                <span>Tailscale (no domain)</span>
              </button>
            </div>

            {accessMode === "domain" ? (
              <>
                <p className="text-sm text-[#9CA3AF] leading-relaxed">
                  Connect a domain name so your dashboard and AI doorway get
                  automatic <code className="text-emerald-400">https://</code>{" "}
                  security.
                  {session.publicIp && (
                    <>
                      {" "}
                      Point your domain&apos;s DNS{" "}
                      <strong className="text-[#F4F5F7]">A record</strong> to{" "}
                      <code className="rounded bg-white/[0.06] px-1.5 py-0.5 text-emerald-300">
                        {session.publicIp}
                      </code>
                      .
                    </>
                  )}
                </p>

                <div>
                  <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
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
                  <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
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
                  <div className="rounded-lg border border-rose-500/35 bg-rose-500/10 px-3.5 py-2.5 text-xs text-rose-200">
                    {error}
                  </div>
                )}

                <div className="flex gap-3 pt-1">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => handleDomainSave(false)}
                    className="btn-press flex-1 rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-[#042F1E] hover:bg-emerald-400 disabled:opacity-50 cursor-pointer"
                  >
                    {busy ? "Saving..." : "Connect domain & finish"}
                  </button>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => handleDomainSave(true)}
                    className="btn-press rounded-lg border border-white/[0.1] bg-[#111317] px-4 py-2.5 text-sm font-medium text-[#9CA3AF] hover:text-white hover:bg-[#161920] cursor-pointer"
                  >
                    Skip for now
                  </button>
                </div>
              </>
            ) : (
              <div className="space-y-4">
                <p className="text-sm text-[#9CA3AF] leading-relaxed">
                  Use Tailscale for private{" "}
                  <code className="text-emerald-400">https://</code> access to
                  your dashboard and AI doorway without buying a domain or
                  configuring DNS.
                </p>

                {tsLoading && !tsStatus ? (
                  <div className="surface-well rounded-lg px-4 py-3 text-xs text-[#9CA3AF] flex items-center gap-2">
                    <Loader2 className="h-3.5 w-3.5 animate-spin text-emerald-400" />
                    Checking Tailscale on this server...
                  </div>
                ) : !tsBridgeSupported ? (
                  <div className="surface-well rounded-lg px-4 py-3 text-xs text-[#9CA3AF]">
                    {tsStatus?.detail ||
                      "Re-run the installer with --tailscale or skip for now to enable Tailscale in Settings."}
                  </div>
                ) : tsStatus?.serveEnabled && tsStatus.serveUrl ? (
                  <div className="rounded-lg border border-emerald-500/35 bg-emerald-500/10 px-4 py-3 text-xs text-emerald-200 space-y-1.5">
                    <p className="font-semibold text-emerald-300">
                      Tailscale private HTTPS is active
                    </p>
                    <p className="font-mono break-all text-white">
                      {tsStatus.serveUrl}
                    </p>
                    {tsStatus.tailscaleIp && (
                      <p className="text-emerald-200/80 font-mono">
                        Tailscale IP: {tsStatus.tailscaleIp}
                      </p>
                    )}
                  </div>
                ) : tsStatus?.connected ? (
                  <div className="surface-well rounded-lg p-4 space-y-2.5 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-emerald-300">
                        Tailscale connected
                      </span>
                      <button
                        type="button"
                        disabled={tsLoading}
                        onClick={() => void refreshTailscaleStatus()}
                        className="inline-flex items-center gap-1 text-[#9CA3AF] hover:text-white cursor-pointer"
                      >
                        <RefreshCw
                          className={`h-3 w-3 ${tsLoading ? "animate-spin" : ""}`}
                        />
                        Refresh
                      </button>
                    </div>
                    {tsStatus.tailscaleIp && (
                      <p className="text-[#9CA3AF]">
                        Tailscale IP:{" "}
                        <code className="font-mono text-[#F4F5F7]">
                          {tsStatus.tailscaleIp}
                        </code>
                      </p>
                    )}
                    {tsStatus.dnsName && (
                      <p className="text-[#9CA3AF]">
                        MagicDNS address:{" "}
                        <code className="font-mono text-emerald-300">
                          {tsStatus.dnsName}
                        </code>
                      </p>
                    )}
                    {!tsStatus.httpsCertsAvailable && (
                      <div className="rounded-md border border-amber-500/35 bg-amber-500/10 px-3 py-2 text-amber-200">
                        Enable MagicDNS and HTTPS Certificates in{" "}
                        <a
                          href="https://login.tailscale.com/admin/dns"
                          target="_blank"
                          rel="noreferrer"
                          className="underline font-medium text-amber-100"
                        >
                          Tailscale DNS settings
                        </a>{" "}
                        before turning on private HTTPS.
                      </div>
                    )}
                    {tsStatus.serveConflict && (
                      <div className="rounded-md border border-amber-500/35 bg-amber-500/10 px-3 py-2 text-amber-200">
                        Port 443 is currently forwarding to{" "}
                        <code className="font-mono">{tsStatus.serveConflict}</code>.
                      </div>
                    )}
                  </div>
                ) : tsStatus?.installed ? (
                  <div className="surface-well rounded-lg p-4 space-y-3 text-xs">
                    <p className="text-[#D1D5DB]">
                      Tailscale is installed on this server. Sign in to connect
                      it to your tailnet, then turn on private HTTPS.
                    </p>
                    {tsLoginUrl && (
                      <a
                        href={tsLoginUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500/15 border border-emerald-500/40 px-3 py-2 font-medium text-emerald-200 hover:bg-emerald-500/25"
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
                        className="btn-press rounded-lg bg-[#F4F5F7] px-3 py-1.5 text-xs font-semibold text-[#090A0C] hover:bg-white disabled:opacity-50 cursor-pointer"
                      >
                        {busy ? "Starting..." : "Sign in to Tailscale"}
                      </button>
                      <button
                        type="button"
                        disabled={tsLoading}
                        onClick={() => void refreshTailscaleStatus()}
                        className="btn-press inline-flex items-center gap-1 rounded-lg border border-white/[0.1] bg-[#111317] px-3 py-1.5 text-xs font-medium text-[#D1D5DB] hover:text-white cursor-pointer"
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
                    <p className="text-[#D1D5DB]">
                      Tailscale isn&apos;t installed on this server yet. Run
                      this command on your server, or skip for now and enable it
                      anytime in AI Keys &amp; Settings:
                    </p>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 overflow-x-auto rounded-md bg-[#090A0C] border border-white/[0.08] px-3 py-2 font-mono text-[11px] text-emerald-300">
                        {TAILSCALE_INSTALL_CMD}
                      </code>
                      <button
                        type="button"
                        onClick={() => void copyInstallCmd()}
                        className="btn-press inline-flex items-center gap-1 rounded-md border border-white/[0.1] bg-[#111317] px-2.5 py-2 text-xs font-medium text-[#F4F5F7] hover:bg-[#161920] cursor-pointer shrink-0"
                      >
                        {tsCopied ? (
                          <Check className="h-3.5 w-3.5 text-emerald-400" />
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
                      className="btn-press inline-flex items-center gap-1.5 rounded-lg border border-white/[0.1] bg-[#111317] px-3 py-1.5 text-xs font-medium text-[#D1D5DB] hover:text-white cursor-pointer"
                    >
                      <RefreshCw
                        className={`h-3 w-3 ${tsLoading ? "animate-spin" : ""}`}
                      />
                      Check again
                    </button>
                  </div>
                )}

                {error && (
                  <div className="rounded-lg border border-rose-500/35 bg-rose-500/10 px-3.5 py-2.5 text-xs text-rose-200">
                    {error}
                  </div>
                )}

                <div className="flex gap-3 pt-1">
                  {tsStatus?.serveEnabled ? (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => void onAuthenticated()}
                      className="btn-press flex-1 rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-[#042F1E] hover:bg-emerald-400 disabled:opacity-50 cursor-pointer"
                    >
                      Continue to dashboard
                    </button>
                  ) : tsStatus?.connected && tsStatus.dnsName ? (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() =>
                        void handleEnableTailscaleAndFinish(
                          Boolean(tsStatus.serveConflict),
                        )
                      }
                      className="btn-press flex-1 rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-[#042F1E] hover:bg-emerald-400 disabled:opacity-50 cursor-pointer"
                    >
                      {busy
                        ? "Enabling..."
                        : tsStatus.serveConflict
                          ? "Replace port 443 & finish"
                          : "Enable private HTTPS & finish"}
                    </button>
                  ) : null}
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => handleDomainSave(true)}
                    className={`btn-press rounded-lg border border-white/[0.1] bg-[#111317] px-4 py-2.5 text-sm font-medium text-[#9CA3AF] hover:text-white hover:bg-[#161920] cursor-pointer ${
                      !(tsStatus?.serveEnabled || (tsStatus?.connected && tsStatus.dnsName))
                        ? "flex-1"
                        : ""
                    }`}
                  >
                    Skip for now
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
