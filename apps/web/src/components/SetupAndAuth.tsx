import { useEffect, useState } from "react";
import { CheckCircle2, Globe, Lock, ShieldCheck } from "lucide-react";
import { api, type SessionInfo } from "../api";

interface SetupAndAuthProps {
  session: SessionInfo;
  onAuthenticated: () => Promise<void>;
}

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
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fromHash = extractClaimFromHash();
    if (fromHash) {
      setClaimToken(fromHash);
      window.history.replaceState(null, "", window.location.pathname);
    }
  }, []);

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
            <span>2. Connect domain (HTTPS)</span>
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
          </div>
        )}
      </div>
    </div>
  );
}
