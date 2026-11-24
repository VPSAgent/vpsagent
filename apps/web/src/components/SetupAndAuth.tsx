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
      // Clean the private claim token from the browser address bar once read
      window.history.replaceState(null, "", window.location.pathname);
    }
  }, []);

  // Returning user login screen
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
      <div className="min-h-screen flex items-center justify-center p-6 bg-slate-950">
        <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/90 p-8 shadow-2xl">
          <div className="flex items-center gap-3 mb-6">
            <div className="h-11 w-11 rounded-xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center">
              <ShieldCheck className="h-6 w-6 text-emerald-400" />
            </div>
            <div>
              <h1 className="text-xl font-semibold text-white">VPSAgent</h1>
              <p className="text-sm text-slate-400">Sign in to your server</p>
            </div>
          </div>

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">
                Owner Password
              </label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Enter your dashboard password"
                required
                autoFocus
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
              />
            </div>

            {error && (
              <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3.5 py-2.5 text-sm text-rose-300">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={busy}
              className="w-full rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50 transition cursor-pointer"
            >
              {busy ? "Signing in..." : "Sign In"}
            </button>
          </form>
        </div>
      </div>
    );
  }

  // 2-step first-time setup wizard
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
    <div className="min-h-screen flex items-center justify-center p-6 bg-slate-950">
      <div className="w-full max-w-lg rounded-2xl border border-slate-800 bg-slate-900/90 p-8 shadow-2xl">
        <div className="flex items-center gap-3 mb-6">
          <div className="h-11 w-11 rounded-xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center">
            <ShieldCheck className="h-6 w-6 text-emerald-400" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-white">
              Welcome to VPSAgent
            </h1>
            <p className="text-sm text-slate-400">
              Quick 2-step setup to lock down your server
            </p>
          </div>
        </div>

        {/* Stepper */}
        <div className="grid grid-cols-2 gap-3 mb-6">
          <div
            className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-medium ${
              step === 1
                ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-300"
                : "border-slate-800 bg-slate-950/60 text-emerald-400"
            }`}
          >
            {step > 1 ? (
              <CheckCircle2 className="h-4 w-4 shrink-0" />
            ) : (
              <Lock className="h-4 w-4 shrink-0" />
            )}
            <span>1. Set Login Password</span>
          </div>
          <div
            className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-medium ${
              step === 2
                ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-300"
                : "border-slate-800 bg-slate-950/60 text-slate-500"
            }`}
          >
            <Globe className="h-4 w-4 shrink-0" />
            <span>2. Connect Domain (HTTPS)</span>
          </div>
        </div>

        {step === 1 ? (
          <form onSubmit={handleClaim} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">
                Private Setup Code
              </label>
              <input
                type="text"
                value={claimToken}
                onChange={(e) => setClaimToken(e.target.value)}
                placeholder="Auto-filled from your #claim= installer link"
                required
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm font-mono text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">
                Choose Your Dashboard Password
              </label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="At least 8 characters"
                required
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">
                Confirm Password
              </label>
              <input
                type="password"
                value={confirmPassphrase}
                onChange={(e) => setConfirmPassphrase(e.target.value)}
                placeholder="Type your password again"
                required
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
              />
            </div>

            {error && (
              <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3.5 py-2.5 text-sm text-rose-300">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={busy}
              className="w-full rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50 transition cursor-pointer"
            >
              {busy ? "Claiming server..." : "Save Password & Continue"}
            </button>
          </form>
        ) : (
          <div className="space-y-4">
            <p className="text-sm text-slate-300">
              Connect a domain name so your dashboard and AI doorway get
              automatic <code className="text-emerald-400">https://</code>{" "}
              padlock security.
              {session.publicIp && (
                <>
                  {" "}
                  Point your domain&apos;s DNS <strong>A record</strong> to{" "}
                  <code className="rounded bg-slate-800 px-1.5 py-0.5 text-emerald-300">
                    {session.publicIp}
                  </code>
                  .
                </>
              )}
            </p>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">
                Dashboard Domain Name
              </label>
              <input
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="vps.yourdomain.com"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">
                Email for Security Certificate Notices (Optional)
              </label>
              <input
                type="email"
                value={acmeEmail}
                onChange={(e) => setAcmeEmail(e.target.value)}
                placeholder="you@yourdomain.com"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
              />
            </div>

            {error && (
              <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3.5 py-2.5 text-sm text-rose-300">
                {error}
              </div>
            )}

            <div className="flex gap-3 pt-1">
              <button
                type="button"
                disabled={busy}
                onClick={() => handleDomainSave(false)}
                className="flex-1 rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50 transition cursor-pointer"
              >
                {busy ? "Saving..." : "Connect Domain & Finish"}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => handleDomainSave(true)}
                className="rounded-lg border border-slate-700 px-4 py-2.5 text-sm font-medium text-slate-300 hover:bg-slate-800 transition cursor-pointer"
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
