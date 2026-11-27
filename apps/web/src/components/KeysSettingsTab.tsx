import { useCallback, useEffect, useRef, useState } from "react";
import {
  Check,
  ChevronDown,
  ChevronUp,
  Copy,
  Download,
  ExternalLink,
  Loader2,
  Lock,
  RefreshCw,
} from "lucide-react";
import {
  api,
  type AppRecord,
  type GitCredentialRecord,
  type McpConnectionTestResult,
  type McpSnippets,
  type McpTokenRecord,
  type McpTokenScope,
  type NotificationChannel,
  type NotificationSettings,
  type SetupState,
  type SystemUpdateStatus,
  type TailscaleStatus,
} from "../api";
import type { ResourceDisplayMode } from "../resource-display";
import { describeTailscaleConflict } from "../tailscale-conflict";
import { PageHeader, buttonPrimary, buttonSecondary } from "./PageHeader";

const TAILSCALE_INSTALL_CMD =
  "curl -fsSL https://tailscale.com/install.sh | sudo sh && sudo tailscale up";

interface KeysSettingsTabProps {
  tokens: McpTokenRecord[];
  apps: AppRecord[];
  gitCredentials: GitCredentialRecord[];
  snippets: McpSnippets | null;
  setup: SetupState;
  publicIp: string | null;
  resourceDisplay: ResourceDisplayMode;
  onResourceDisplayChange: (mode: ResourceDisplayMode) => void;
  focusSection?:
    | "general"
    | "access"
    | "github"
    | "updates"
    | "alerts"
    | "backups"
    | "account"
    | null;
  onConsumeFocusSection?: () => void;
  initialUpdateStatus?: SystemUpdateStatus | null;
  onUpdateStatusChange?: (status: SystemUpdateStatus) => void;
  onRefresh: () => Promise<void>;
  onSignedOut?: () => void;
}

const RELEASE_UPDATE_STEPS = [
  { key: "downloading", label: "Download release" },
  { key: "verifying", label: "Verify SHA-256" },
  { key: "building", label: "Rebuild VPSAgent" },
  { key: "restarting", label: "Restart & reconnect" },
] as const;

const GIT_UPDATE_STEPS = [
  { key: "fetching", label: "Download code" },
  { key: "syncing", label: "Update config" },
  { key: "building", label: "Rebuild VPSAgent" },
  { key: "restarting", label: "Restart & reconnect" },
] as const;

function getUpdateStepIndex(
  phase: string | null,
  reconnecting: boolean,
  isRelease: boolean,
): number {
  if (reconnecting || phase === "restarting" || phase === "completed") {
    return 3;
  }
  if (isRelease) {
    if (phase === "building") return 2;
    if (phase === "verifying" || phase === "extracting" || phase === "syncing") {
      return 1;
    }
    return 0;
  }
  if (phase === "building") return 2;
  if (phase === "syncing") return 1;
  return 0;
}

function isSafeHttpsUrl(raw: string | null | undefined): raw is string {
  if (!raw) return false;
  try {
    const u = new URL(raw);
    return u.protocol === "https:";
  } catch {
    return false;
  }
}

type SettingsPane =
  | "general"
  | "access"
  | "network"
  | "github"
  | "alerts"
  | "backups"
  | "account"
  | "updates";

const SETTINGS_PANES: Array<{ id: SettingsPane; label: string }> = [
  { id: "general", label: "General" },
  { id: "access", label: "AI access" },
  { id: "network", label: "Domains & network" },
  { id: "github", label: "GitHub" },
  { id: "alerts", label: "Alerts" },
  { id: "backups", label: "Backups" },
  { id: "account", label: "Account" },
  { id: "updates", label: "Updates" },
];

const RESET_PASSWORD_CMD =
  "sudo python3 /var/lib/vpsagent/runtime-bridge.py --reset-password";

const SCOPE_LABELS: Record<
  McpTokenScope,
  { title: string; desc: string; dot: string; text: string }
> = {
  "read-only": {
    title: "Read only",
    desc: "Check server health, inspect GitHub repos, and read logs. Can never change or delete anything.",
    dot: "bg-muted",
    text: "text-fg-2",
  },
  "approval-required": {
    title: "Ask first",
    desc: "Check health and logs, and queue every deploy or change for your Approve click.",
    dot: "bg-warn",
    text: "text-warn",
  },
  "safe-auto-deploy": {
    title: "Deploy freely",
    desc: "Launch, rebuild, restart, and update apps right away, while always asking your approval before deleting an app.",
    dot: "bg-info",
    text: "text-info",
  },
  "auto-approve": {
    title: "Trusted",
    desc: "Launch, update, and delete isolated apps right away. Host-level commands, files, and services still ask for your Approve click.",
    dot: "bg-ok",
    text: "text-ok",
  },
  "host-admin": {
    title: "Full admin (root)",
    desc: "Full hands-free VPS administration: runs shell commands directly on the server as root, edits allowed files, and manages system services without waiting for approval.",
    dot: "bg-bad",
    text: "text-bad",
  },
};

export function KeysSettingsTab({
  tokens,
  apps,
  gitCredentials,
  snippets,
  setup,
  publicIp,
  resourceDisplay,
  onResourceDisplayChange,
  focusSection,
  onConsumeFocusSection,
  initialUpdateStatus = null,
  onUpdateStatusChange,
  onRefresh,
  onSignedOut,
}: KeysSettingsTabProps) {
  const [name, setName] = useState("");
  const [scope, setScope] = useState<McpTokenScope>("safe-auto-deploy");
  const [restrictApps, setRestrictApps] = useState(false);
  const [selectedSlugs, setSelectedSlugs] = useState<string[]>([]);
  const [customSlugsText, setCustomSlugsText] = useState("");
  const [newCreatedToken, setNewCreatedToken] = useState<{
    id: string;
    rawToken: string;
  } | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [activeClient, setActiveClient] = useState<
    "claudeCode" | "t3AndAgy" | "cursor" | "codex" | "genericHttp" | "curlTest"
  >("claudeCode");
  const [endpointSource, setEndpointSource] = useState<
    "auto" | "domain" | "tailscale"
  >("auto");
  const [testResult, setTestResult] = useState<McpConnectionTestResult | null>(
    null,
  );
  const [testing, setTesting] = useState(false);
  const [domain, setDomain] = useState(setup.domain ?? "");
  const [acmeEmail, setAcmeEmail] = useState(setup.acmeEmail ?? "");
  const [appsBaseDomain, setAppsBaseDomain] = useState(
    setup.appsBaseDomain ?? "",
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [updateStatus, setUpdateStatus] = useState<SystemUpdateStatus | null>(
    initialUpdateStatus,
  );
  const [updateLoading, setUpdateLoading] = useState(!initialUpdateStatus);
  const [checkingUpdate, setCheckingUpdate] = useState(false);
  const [startingUpdate, setStartingUpdate] = useState(false);
  const [reconnectingUpdate, setReconnectingUpdate] = useState(false);
  const [updateLoadError, setUpdateLoadError] = useState<string | null>(null);
  const [showUpdateLogs, setShowUpdateLogs] = useState(false);
  const baselineBuildRef = useRef<{
    version: string | null;
    commit: string | null;
  } | null>(null);

  const [pane, setPane] = useState<SettingsPane>(() =>
    focusSection ? focusSection : "general",
  );
  const githubSectionRef = useRef<HTMLElement | null>(null);
  const updatesSectionRef = useRef<HTMLElement | null>(null);
  const [githubToken, setGithubToken] = useState("");
  const [githubLabel, setGithubLabel] = useState("");
  const [githubBusy, setGithubBusy] = useState(false);
  const [testingCredId, setTestingCredId] = useState<string | null>(null);

  // Instant Alerts state
  const [alertSettings, setAlertSettings] =
    useState<NotificationSettings | null>(null);
  const [alertEnabled, setAlertEnabled] = useState(false);
  const [alertChannel, setAlertChannel] = useState<NotificationChannel>("none");
  const [alertWebhookUrl, setAlertWebhookUrl] = useState("");
  const [alertTelegramToken, setAlertTelegramToken] = useState("");
  const [alertTelegramChatId, setAlertTelegramChatId] = useState("");
  const [notifyOnApproval, setNotifyOnApproval] = useState(true);
  const [notifyOnAppDown, setNotifyOnAppDown] = useState(true);
  const [notifyOnDeployFailure, setNotifyOnDeployFailure] = useState(true);
  const [alertBusy, setAlertBusy] = useState(false);
  const [alertTesting, setAlertTesting] = useState(false);

  // Server Backup state
  const [includeBackupAppData, setIncludeBackupAppData] = useState(true);
  const [backupDownloading, setBackupDownloading] = useState(false);

  // Account & Password state
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");
  const [accountBusy, setAccountBusy] = useState(false);

  const [tailscaleStatus, setTailscaleStatus] =
    useState<TailscaleStatus | null>(null);
  const [tailscaleBridgeSupported, setTailscaleBridgeSupported] =
    useState(true);
  const [tailscaleLoading, setTailscaleLoading] = useState(true);
  const [tailscaleBusy, setTailscaleBusy] = useState(false);
  const [tailscaleLoginUrl, setTailscaleLoginUrl] = useState<string | null>(
    null,
  );
  const [showTailscaleAuthKey, setShowTailscaleAuthKey] = useState(false);
  const [tailscaleAuthKey, setTailscaleAuthKey] = useState("");

  const applyLocalUpdateStatus = useCallback(
    (next: SystemUpdateStatus) => {
      setUpdateStatus(next);
      onUpdateStatusChange?.(next);
    },
    [onUpdateStatusChange],
  );

  useEffect(() => {
    if (!focusSection) return;
    setPane(focusSection);
    if (focusSection === "github") {
      githubSectionRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    } else if (focusSection === "updates") {
      updatesSectionRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }
    onConsumeFocusSection?.();
  }, [focusSection, onConsumeFocusSection]);

  const applyLoadedAlerts = useCallback((settings: NotificationSettings) => {
    setAlertSettings(settings);
    setAlertEnabled(settings.enabled);
    setAlertChannel(settings.channel);
    setAlertTelegramChatId(settings.telegramChatId ?? "");
    setNotifyOnApproval(settings.notifyOnApproval);
    setNotifyOnAppDown(settings.notifyOnAppDown);
    setNotifyOnDeployFailure(settings.notifyOnDeployFailure);
  }, []);

  const loadNotificationSettings = useCallback(async () => {
    try {
      const res = await api.getNotifications();
      applyLoadedAlerts(res.settings);
    } catch {
      // Non-fatal on initial mount
    }
  }, [applyLoadedAlerts]);

  useEffect(() => {
    void loadNotificationSettings();
  }, [loadNotificationSettings]);

  const loadUpdateStatus = useCallback(async () => {
    try {
      const res = await api.getSystemUpdateStatus();
      applyLocalUpdateStatus(res.status);
      setReconnectingUpdate(false);
      setUpdateLoadError(null);
    } catch (err) {
      // Keep previous status if the server is restarting mid-update; otherwise surface why updates are unavailable
      setUpdateLoadError(
        err instanceof Error
          ? err.message
          : "Could not load VPSAgent update status from the server.",
      );
    } finally {
      setUpdateLoading(false);
    }
  }, [applyLocalUpdateStatus]);

  useEffect(() => {
    void loadUpdateStatus();
  }, [loadUpdateStatus]);

  const loadTailscaleStatus = useCallback(async () => {
    setTailscaleLoading(true);
    try {
      const res = await api.getTailscaleStatus();
      setTailscaleStatus(res.status);
      setTailscaleBridgeSupported(res.bridgeSupported);
      if (res.status.loginUrl) {
        setTailscaleLoginUrl(res.status.loginUrl);
      } else if (res.status.connected) {
        setTailscaleLoginUrl(null);
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Could not check Tailscale status on this server.",
      );
    } finally {
      setTailscaleLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadTailscaleStatus();
  }, [loadTailscaleStatus]);

  const handleTailscaleConnect = async (mode: "login" | "authkey") => {
    setTailscaleBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await api.connectTailscale(
        mode === "authkey"
          ? { mode: "authkey", authKey: tailscaleAuthKey.trim() }
          : { mode: "login" },
      );
      setTailscaleStatus(res.status);
      setTailscaleLoginUrl(res.loginUrl ?? res.status.loginUrl);
      if (mode === "authkey") {
        setTailscaleAuthKey("");
        setShowTailscaleAuthKey(false);
      }
      if (res.status.connected) {
        setNotice(
          `Connected Tailscale (${res.status.dnsName || res.status.tailscaleIp || "tailnet"}).`,
        );
      } else if (res.loginUrl || res.status.loginUrl) {
        setNotice(
          "Tailscale sign-in link ready. Open it in your browser, approve this server, then click Refresh.",
        );
      }
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not connect Tailscale.",
      );
    } finally {
      setTailscaleBusy(false);
    }
  };

  const handleToggleTailscaleServe = async (enabled: boolean, force = false) => {
    setTailscaleBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await api.setTailscaleServe(enabled, force);
      setTailscaleStatus(res.status);
      setNotice(
        enabled
          ? `Tailscale private HTTPS enabled at ${res.status.serveUrl || "port 443"}.`
          : "Tailscale private HTTPS turned off.",
      );
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Could not update Tailscale private HTTPS.",
      );
      void loadTailscaleStatus();
    } finally {
      setTailscaleBusy(false);
    }
  };

  const tailscaleConflict = tailscaleStatus
    ? describeTailscaleConflict(tailscaleStatus)
    : null;

  useEffect(() => {
    if (updateStatus?.state !== "updating") {
      return;
    }
    let cancelled = false;
    let sawDrop = false;
    let inFlight = false;
    const baseline = baselineBuildRef.current ?? {
      version: updateStatus.currentVersion,
      commit: updateStatus.currentCommit,
    };
    baselineBuildRef.current = baseline;

    const timer = window.setInterval(async () => {
      if (inFlight || cancelled) return;
      inFlight = true;
      try {
        const res = await api.getSystemUpdateStatus();
        if (cancelled) return;
        setReconnectingUpdate(false);
        applyLocalUpdateStatus(res.status);
        const versionOrCommitChanged =
          (res.status.currentVersion &&
            res.status.currentVersion !== baseline.version) ||
          (res.status.currentCommit &&
            res.status.currentCommit !== baseline.commit);
        if (
          res.status.state === "succeeded" ||
          (sawDrop &&
            res.status.state === "idle" &&
            Boolean(versionOrCommitChanged))
        ) {
          setNotice(
            res.status.message ||
              "VPSAgent updated! Reloading the dashboard...",
          );
          window.setTimeout(() => {
            window.location.reload();
          }, 1800);
        } else if (res.status.state === "failed") {
          setError(res.status.error || "VPSAgent update failed.");
        }
      } catch {
        if (!cancelled) {
          sawDrop = true;
          setReconnectingUpdate(true);
        }
      } finally {
        inFlight = false;
      }
    }, 2500);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [
    updateStatus?.state,
    updateStatus?.currentVersion,
    updateStatus?.currentCommit,
    applyLocalUpdateStatus,
  ]);

  const handleCheckUpdates = async () => {
    setCheckingUpdate(true);
    setError(null);
    setNotice(null);
    try {
      const res = await api.checkSystemUpdate();
      applyLocalUpdateStatus(res.status);
      if (res.status.updateAvailable) {
        setNotice(
          res.status.message ||
            "A new version of VPSAgent is ready to install.",
        );
      } else if (res.status.canUpdate) {
        setNotice(res.status.message || "VPSAgent is already up to date.");
      }
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not check for updates.",
      );
    } finally {
      setCheckingUpdate(false);
    }
  };

  const handleApplyUpdate = async () => {
    setStartingUpdate(true);
    setError(null);
    setNotice(null);
    setShowUpdateLogs(true);
    baselineBuildRef.current = {
      version: updateStatus?.currentVersion ?? null,
      commit: updateStatus?.currentCommit ?? null,
    };
    try {
      const source =
        updateStatus?.updateAvailable &&
        (updateStatus?.updateSource === "release" ||
          updateStatus?.updateSource === "git")
          ? updateStatus.updateSource
          : "auto";
      const res = await api.applySystemUpdate(source);
      applyLocalUpdateStatus(res.status);
      setNotice(
        "Update started. VPSAgent will rebuild and restart automatically in 1–2 minutes.",
      );
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not start VPSAgent update.",
      );
    } finally {
      setStartingUpdate(false);
    }
  };

  const copyText = async (id: string, text: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const toggleAllowedSlug = (slug: string) => {
    setSelectedSlugs((prev) =>
      prev.includes(slug) ? prev.filter((s) => s !== slug) : [...prev, slug],
    );
  };

  const handleCreateToken = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      const extraSlugs = customSlugsText
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      const allowedSlugs = restrictApps
        ? Array.from(new Set([...selectedSlugs, ...extraSlugs]))
        : [];
      if (restrictApps && allowedSlugs.length === 0) {
        setError(
          "Pick at least one app or enter an app short ID when app lock is turned on.",
        );
        return;
      }
      const res = await api.createToken(name.trim(), scope, allowedSlugs);
      setNewCreatedToken({ id: res.token.id, rawToken: res.rawToken });
      setName("");
      setRestrictApps(false);
      setSelectedSlugs([]);
      setCustomSlugsText("");
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create key.");
    } finally {
      setBusy(false);
    }
  };

  const handleRevoke = async (id: string) => {
    setError(null);
    try {
      await api.revokeToken(id);
      if (newCreatedToken?.id === id) {
        setNewCreatedToken(null);
      }
      setNotice("Access key revoked.");
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not revoke pass.");
    }
  };

  const handleUpdateDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await api.updateSetupDomain(
        domain.trim() || null,
        acmeEmail.trim() || null,
      );
      setNotice("Saved dashboard domain settings.");
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not update domain.");
    } finally {
      setBusy(false);
    }
  };

  const handleUpdateAppsBaseDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await api.updateAppsBaseDomain(appsBaseDomain.trim() || null);
      setNotice(
        appsBaseDomain.trim()
          ? `Default app addresses enabled for *.${appsBaseDomain.trim()}.`
          : "Cleared default apps base domain.",
      );
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Could not save default apps base domain.",
      );
    } finally {
      setBusy(false);
    }
  };

  const handleCheckGatewayStatus = async () => {
    setTesting(true);
    setError(null);
    try {
      const res = await api.testMcpConnection();
      setTestResult(res);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Couldn’t check the AI connection.",
      );
    } finally {
      setTesting(false);
    }
  };

  const handleAddGithubToken = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!githubToken.trim()) return;
    setGithubBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await api.createGitCredential({
        label: githubLabel.trim() || undefined,
        token: githubToken.trim(),
      });
      setGithubToken("");
      setGithubLabel("");
      const baseMsg = `Connected ${res.accountLogin ? `@${res.accountLogin}` : "GitHub"} (${res.accessibleRepoCount} ${res.accessibleRepoCount === 1 ? "repo" : "repos"} visible).`;
      setNotice(res.warning ? `${baseMsg} ${res.warning}` : baseMsg);
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Could not verify or save GitHub token.",
      );
    } finally {
      setGithubBusy(false);
    }
  };

  const handleTestGithubCred = async (id: string) => {
    setTestingCredId(id);
    setError(null);
    setNotice(null);
    try {
      const res = await api.testGitCredential(id);
      const baseMsg = `GitHub token verified${res.accountLogin ? ` for @${res.accountLogin}` : ""}: ${res.accessibleRepoCount} ${res.accessibleRepoCount === 1 ? "repo" : "repos"} accessible.`;
      setNotice(res.warning ? `${baseMsg} ${res.warning}` : baseMsg);
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "GitHub token check failed.",
      );
    } finally {
      setTestingCredId(null);
    }
  };

  const handleSetDefaultGithubCred = async (id: string) => {
    setGithubBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await api.setDefaultGitCredential(id);
      setNotice(`Set "${res.credential.label}" as the default GitHub token.`);
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Could not update default GitHub token.",
      );
    } finally {
      setGithubBusy(false);
    }
  };

  const handleDeleteGithubCred = async (id: string, label: string) => {
    if (
      !window.confirm(
        `Remove GitHub token "${label}"? Apps already built stay running, but future rebuilds of private repos using this token will need another token.`,
      )
    ) {
      return;
    }
    setGithubBusy(true);
    setError(null);
    setNotice(null);
    try {
      await api.deleteGitCredential(id);
      setNotice(`Removed GitHub token "${label}".`);
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not remove GitHub token.",
      );
    } finally {
      setGithubBusy(false);
    }
  };

  const handleSaveAlerts = async (e: React.FormEvent) => {
    e.preventDefault();
    setAlertBusy(true);
    setError(null);
    setNotice(null);
    try {
      const payload: Parameters<typeof api.updateNotifications>[0] = {
        channel: alertChannel,
        enabled: alertChannel === "none" ? false : alertEnabled,
        notifyOnApproval,
        notifyOnAppDown,
        notifyOnDeployFailure,
      };
      if (alertChannel === "telegram") {
        if (alertTelegramToken.trim()) {
          payload.telegramBotToken = alertTelegramToken.trim();
        }
        payload.telegramChatId = alertTelegramChatId.trim() || null;
      } else if (alertChannel !== "none") {
        if (alertWebhookUrl.trim()) {
          payload.webhookUrl = alertWebhookUrl.trim();
        }
      }
      const res = await api.updateNotifications(payload);
      applyLoadedAlerts(res.settings);
      setAlertWebhookUrl("");
      setAlertTelegramToken("");
      setNotice(
        res.settings.enabled
          ? `Saved instant alerts (${res.settings.channel}).`
          : "Saved alert settings (currently paused).",
      );
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not save alert settings.",
      );
    } finally {
      setAlertBusy(false);
    }
  };

  const handleTestAlert = async () => {
    setAlertTesting(true);
    setError(null);
    setNotice(null);
    try {
      const res = await api.testNotification();
      setAlertSettings(res.settings);
      if (res.ok) {
        setNotice("Test alert sent! Check your Discord, Slack, Telegram, or webhook receiver.");
      } else {
        setError(res.error || "Test alert failed.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Test alert failed.");
    } finally {
      setAlertTesting(false);
    }
  };

  const handleDownloadSystemBackup = async () => {
    setBackupDownloading(true);
    setError(null);
    setNotice(null);
    try {
      const res = await api.downloadSystemBackup(includeBackupAppData);
      setNotice(
        `Downloaded ${res.filename} (${(res.sizeBytes / 1024).toFixed(1)} KB, secrets excluded).`,
      );
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not download server backup.",
      );
    } finally {
      setBackupDownloading(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword.length < 8) {
      setError("New password must be at least 8 characters long.");
      return;
    }
    if (newPassword !== confirmNewPassword) {
      setError("New password and confirmation do not match.");
      return;
    }
    setAccountBusy(true);
    setError(null);
    setNotice(null);
    try {
      await api.changePassword(currentPassword, newPassword);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmNewPassword("");
      setNotice(
        "Password updated. All older browser sessions have been signed out.",
      );
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not change password.",
      );
    } finally {
      setAccountBusy(false);
    }
  };

  const handleLogoutAll = async () => {
    if (
      !window.confirm(
        "Sign out every browser and device currently logged into this dashboard (including this tab)?",
      )
    ) {
      return;
    }
    setAccountBusy(true);
    setError(null);
    try {
      await api.logoutAll(false);
      onSignedOut?.();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not sign out all devices.",
      );
    } finally {
      setAccountBusy(false);
    }
  };

  const newRawToken = newCreatedToken?.rawToken ?? null;
  const selectedSnippetEndpoint =
    endpointSource === "tailscale" && snippets?.tailscale?.httpsReady
      ? snippets.tailscale
      : endpointSource === "domain" && snippets?.customDomain?.httpsReady
        ? snippets.customDomain
        : null;
  const activeSnippetVariant = selectedSnippetEndpoint?.snippets ?? snippets;
  const rawActiveSnippet = activeSnippetVariant
    ? activeSnippetVariant[activeClient]
    : "";
  const placeholder =
    activeSnippetVariant?.tokenPlaceholder ||
    snippets?.tokenPlaceholder ||
    "vpsmcp_YOUR_TOKEN_HERE";
  const activeSnippet =
    newRawToken && rawActiveSnippet
      ? rawActiveSnippet.split(placeholder).join(newRawToken)
      : rawActiveSnippet;
  const activeMcpUrl = selectedSnippetEndpoint?.url ?? snippets?.mcpUrl ?? "";
  const hasBothRemoteEndpoints = Boolean(
    snippets?.customDomain?.httpsReady && snippets?.tailscale?.httpsReady,
  );
  const customDomainReady = Boolean(
    setup.domain && setup.httpsActive && setup.tlsStatus === "active",
  );
  const tailscaleReady = Boolean(snippets?.tailscale?.httpsReady);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        description="General preferences, AI access, domains, GitHub and updates."
      />

      {error && (
        <div className="rounded-xl border border-bad-line bg-bad-soft px-4 py-3 text-sm text-bad">
          {error}
        </div>
      )}
      {notice && (
        <div className="rounded-xl border border-line bg-surface-2 px-4 py-3 text-sm text-fg-2">
          {notice}
        </div>
      )}

      <div className="space-y-8">
        <nav aria-label="Settings sections" className="-mt-2 flex gap-6 overflow-x-auto border-b border-line">
          {SETTINGS_PANES.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setPane(item.id)}
              aria-current={pane === item.id ? "page" : undefined}
              className={`btn-press -mb-px shrink-0 border-b-2 pb-2.5 text-sm whitespace-nowrap cursor-pointer ${
                pane === item.id
                  ? "border-fg text-fg font-medium"
                  : "border-transparent text-muted hover:text-fg"
              }`}
            >
              {item.label}
              {item.id === "updates" && updateStatus?.updateAvailable && (
                <span className="ml-2 inline-block h-1.5 w-1.5 rounded-full bg-ok align-middle" />
              )}
            </button>
          ))}
        </nav>

        <div className="min-w-0 space-y-6">
          {pane === "general" && (
            <section className="surface-panel rounded-xl p-6 space-y-5">
              <div>
                <h2 className="text-base font-medium text-fg">
                  Overview display
                </h2>
                <p className="mt-1 text-xs text-muted">
                  Choose how server CPU, memory, and disk usage appear on the
                  Overview page.
                </p>
              </div>

              <fieldset className="space-y-2">
                <legend className="block text-xs font-medium text-fg-2">
                  Resource usage style
                </legend>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {(
                    [
                      {
                        id: "bar",
                        title: "Bar",
                        desc: "Compact progress bar showing current usage.",
                      },
                      {
                        id: "chart",
                        title: "Chart",
                        desc: "Live area chart tracking usage over time.",
                      },
                    ] as const
                  ).map((option) => {
                    const selected = resourceDisplay === option.id;
                    return (
                      <label
                        key={option.id}
                        className={`btn-press block rounded-lg border px-4 py-3 text-left cursor-pointer has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-fg-2 has-[:focus-visible]:outline-offset-2 ${
                          selected
                            ? "border-fg bg-surface-2 text-fg"
                            : "border-line bg-well text-muted hover:text-fg hover:border-line-strong"
                        }`}
                      >
                        <input
                          type="radio"
                          name="resource-display"
                          value={option.id}
                          checked={selected}
                          onChange={() => onResourceDisplayChange(option.id)}
                          className="sr-only"
                        />
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-sm font-medium text-fg">
                            {option.title}
                          </span>
                          <span
                            className={`h-2 w-2 rounded-full ${
                              selected ? "bg-fg" : "bg-line-strong"
                            }`}
                          />
                        </div>
                        <p className="mt-1 text-xs text-muted">{option.desc}</p>
                      </label>
                    );
                  })}
                </div>
              </fieldset>
            </section>
          )}
          {pane === "access" && (
            <>
            {snippets && (
              <section className="surface-panel rounded-xl p-6 space-y-4">
                {!snippets.httpsReady ? (
                  <div className="rounded-lg border border-warn-line bg-warn-soft px-4 py-3 text-xs text-warn flex flex-wrap items-center justify-between gap-2">
                    <span>
                      {setup.domain
                        ? `HTTPS certificate for ${setup.domain} is currently ${setup.tlsStatus}${setup.tlsError ? `: ${setup.tlsError}` : ""}. Remote HTTPS MCP will be advertised once TLS succeeds — or enable Tailscale private HTTPS below with no domain needed.`
                        : "No verified HTTPS address yet. Connect a domain or enable Tailscale private HTTPS below (no domain needed)."}
                    </span>
                    {setup.domain && (
                      <button
                        type="button"
                        onClick={async () => {
                          setBusy(true);
                          try {
                            await api.recheckTls();
                            await onRefresh();
                          } finally {
                            setBusy(false);
                          }
                        }}
                        className="btn-press rounded-lg bg-warn px-3 py-1 text-xs font-medium text-on-warn hover:opacity-90 cursor-pointer"
                      >
                        Re-check HTTPS
                      </button>
                    )}
                  </div>
                ) : (
                  setup.domain &&
                  !customDomainReady &&
                  tailscaleReady && (
                    <div className="rounded-lg border border-line bg-well px-4 py-2.5 text-xs text-fg-2 flex flex-wrap items-center justify-between gap-2">
                      <span>
                        Tailscale private HTTPS is active. Your custom domain{" "}
                        <code className="text-warn">{setup.domain}</code> is
                        still{" "}
                        <strong className="font-medium text-warn">
                          {setup.tlsStatus}
                        </strong>
                        .
                      </span>
                      <button
                        type="button"
                        onClick={async () => {
                          setBusy(true);
                          try {
                            await api.recheckTls();
                            await onRefresh();
                          } finally {
                            setBusy(false);
                          }
                        }}
                        className="btn-press rounded-lg border border-line-strong bg-surface px-2.5 py-1 text-[11px] font-medium text-fg hover:bg-surface-2 cursor-pointer"
                      >
                        Re-check HTTPS
                      </button>
                    </div>
                  )
                )}

                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2.5">
                      <h2 className="text-sm font-medium text-fg">
                        Connect your AI tool
                      </h2>
                      {tailscaleReady && (
                        <span className="inline-flex items-center gap-1.5 text-xs text-ok">
                          <span className="h-1.5 w-1.5 rounded-full bg-ok" />
                          {customDomainReady
                            ? "Custom domain + Tailscale HTTPS"
                            : "Tailscale private HTTPS"}
                        </span>
                      )}
                      {newRawToken && (
                        <span className="text-xs font-medium text-ok">
                          New key auto-filled
                        </span>
                      )}
                    </div>

                    {hasBothRemoteEndpoints && (
                      <div className="flex flex-wrap items-center gap-2 pt-0.5">
                        <span className="text-[11px] text-muted">
                          Snippet address:
                        </span>
                        <div className="inline-flex rounded-md border border-line bg-well p-0.5 gap-0.5">
                          <button
                            type="button"
                            onClick={() => setEndpointSource("domain")}
                            className={`btn-press rounded px-2 py-0.5 text-[11px] font-medium cursor-pointer ${
                              (endpointSource === "auto"
                                ? snippets.primarySource !== "tailscale"
                                : endpointSource === "domain")
                                ? "bg-fill text-fg"
                                : "text-muted hover:text-fg"
                            }`}
                          >
                            Custom domain
                          </button>
                          <button
                            type="button"
                            onClick={() => setEndpointSource("tailscale")}
                            className={`btn-press rounded px-2 py-0.5 text-[11px] font-medium cursor-pointer ${
                              (endpointSource === "auto"
                                ? snippets.primarySource === "tailscale"
                                : endpointSource === "tailscale")
                                ? "bg-fill text-fg"
                                : "text-muted hover:text-fg"
                            }`}
                          >
                            Tailscale (private)
                          </button>
                        </div>
                      </div>
                    )}

                    <div className="flex flex-wrap items-center gap-2.5 text-xs text-muted">
                      {snippets.customDomain && snippets.tailscale ? (
                        <div className="flex flex-wrap items-center gap-3">
                          <span className="inline-flex items-center gap-1.5">
                            <span>Custom domain:</span>
                            <code className="text-fg">
                              {snippets.customDomain.url}
                            </code>
                            <button
                              type="button"
                              onClick={() =>
                                copyText(
                                  "mcp-url-domain",
                                  snippets.customDomain!.url,
                                )
                              }
                              className="inline-flex items-center text-muted hover:text-fg cursor-pointer"
                              title="Copy custom domain MCP URL"
                            >
                              {copiedId === "mcp-url-domain" ? (
                                <Check className="h-3 w-3 text-ok" />
                              ) : (
                                <Copy className="h-3 w-3" />
                              )}
                            </button>
                          </span>
                          <span className="inline-flex items-center gap-1.5">
                            <span>Tailscale:</span>
                            <code className="text-fg">
                              {snippets.tailscale.url}
                            </code>
                            <button
                              type="button"
                              onClick={() =>
                                copyText(
                                  "mcp-url-tailscale",
                                  snippets.tailscale!.url,
                                )
                              }
                              className="inline-flex items-center text-muted hover:text-fg cursor-pointer"
                              title="Copy Tailscale MCP URL"
                            >
                              {copiedId === "mcp-url-tailscale" ? (
                                <Check className="h-3 w-3 text-ok" />
                              ) : (
                                <Copy className="h-3 w-3" />
                              )}
                            </button>
                          </span>
                        </div>
                      ) : (
                        <span className="inline-flex items-center gap-1.5">
                          <span>Address:</span>
                          <code className="text-fg">{activeMcpUrl}</code>
                          <button
                            type="button"
                            onClick={() => copyText("mcp-url-primary", activeMcpUrl)}
                            className="inline-flex items-center text-muted hover:text-fg cursor-pointer"
                            title="Copy MCP URL"
                          >
                            {copiedId === "mcp-url-primary" ? (
                              <Check className="h-3 w-3 text-ok" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                          </button>
                        </span>
                      )}
                      <button
                        type="button"
                        disabled={testing}
                        onClick={handleCheckGatewayStatus}
                        className="btn-press inline-flex items-center gap-1 rounded-md border border-line-strong bg-well px-2 py-0.5 text-[11px] font-medium text-fg hover:bg-surface-2 disabled:opacity-50 cursor-pointer"
                      >
                        {testing ? "Checking..." : "Check gateway"}
                      </button>
                    </div>
                  </div>
                  <div
                    role="tablist"
                    aria-label="AI client snippets"
                    className="inline-flex flex-wrap rounded-lg border border-line bg-well p-1 gap-0.5"
                    onKeyDown={(e) => {
                      if (
                        e.key !== "ArrowLeft" &&
                        e.key !== "ArrowRight" &&
                        e.key !== "Home" &&
                        e.key !== "End"
                      ) {
                        return;
                      }
                      e.preventDefault();
                      const order = [
                        "claudeCode",
                        "t3AndAgy",
                        "cursor",
                        "codex",
                        "genericHttp",
                        "curlTest",
                      ] as const;
                      const idx = order.indexOf(activeClient);
                      const next =
                        e.key === "Home"
                          ? order[0]
                          : e.key === "End"
                            ? order[order.length - 1]!
                            : e.key === "ArrowRight"
                              ? order[(idx + 1) % order.length]!
                              : order[(idx - 1 + order.length) % order.length]!;
                      setActiveClient(next);
                      document.getElementById(`mcp-client-tab-${next}`)?.focus();
                    }}
                  >
                    {(
                      [
                        ["claudeCode", "Claude Code"],
                        ["t3AndAgy", "T3 / AGY"],
                        ["cursor", "Cursor"],
                        ["codex", "Codex"],
                        ["genericHttp", "HTTP"],
                        ["curlTest", "Curl"],
                      ] as const
                    ).map(([id, label]) => (
                      <button
                        key={id}
                        id={`mcp-client-tab-${id}`}
                        role="tab"
                        aria-selected={activeClient === id}
                        aria-controls="mcp-client-snippet-panel"
                        tabIndex={activeClient === id ? 0 : -1}
                        type="button"
                        onClick={() => setActiveClient(id)}
                        className={`btn-press rounded-md px-2.5 py-1 text-xs font-medium cursor-pointer ${
                          activeClient === id
                            ? "bg-fill text-fg"
                            : "text-muted hover:text-fg"
                        }`}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>

                {testResult && (
                  <div
                    className={`rounded-lg border px-4 py-3 text-xs ${
                      testResult.ok
                        ? "border-line-strong bg-fill text-fg"
                        : "border-warn-line bg-warn-soft text-warn"
                    }`}
                  >
                    <span className="font-medium">
                      {testResult.ok ? "Gateway healthy: " : "Attention: "}
                    </span>
                    {testResult.message}
                  </div>
                )}

                <div
                  id="mcp-client-snippet-panel"
                  role="tabpanel"
                  aria-labelledby={`mcp-client-tab-${activeClient}`}
                  className="relative"
                >
                  <pre className="surface-well rounded-lg p-4 pr-24 text-xs font-mono text-fg whitespace-pre-wrap break-all leading-relaxed">
                    {activeSnippet}
                  </pre>
                  <button
                    type="button"
                    onClick={() => copyText("snippet", activeSnippet)}
                    className="btn-press absolute top-3 right-3 inline-flex items-center gap-1.5 rounded-md border border-line-strong bg-surface-2 px-2.5 py-1 text-xs font-medium text-fg hover:bg-surface-2 cursor-pointer"
                  >
                    {copiedId === "snippet" ? (
                      <Check className="h-3.5 w-3.5 text-ok" />
                    ) : (
                      <Copy className="h-3.5 w-3.5" />
                    )}
                    {copiedId === "snippet" ? "Copied" : "Copy"}
                  </button>
                </div>
              </section>
            )}
            <section className="surface-panel rounded-xl overflow-hidden">
              <div className="px-6 py-4 border-b border-line flex items-center justify-between">
                <h2 className="text-sm font-medium text-fg">
                  Access keys
                  <span className="ml-2 text-xs font-normal text-muted tabular-nums">
                    ({tokens.length})
                  </span>
                </h2>
              </div>

              {tokens.length === 0 ? (
                <p className="p-6 text-sm text-muted">
                  No access keys yet. Create one above to connect your AI
                  coding assistant.
                </p>
              ) : (
                <div className="divide-y divide-line">
                  {tokens.map((tok) => {
                    const info = SCOPE_LABELS[tok.scope];
                    const isRevoked = Boolean(tok.revokedAt);
                    return (
                      <div
                        key={tok.id}
                        className="row-interactive flex flex-wrap items-center justify-between gap-4 px-6 py-4"
                      >
                        <div className="space-y-1 min-w-0">
                          <div className="flex flex-wrap items-center gap-2.5">
                            <span
                              className={`text-sm font-medium ${
                                isRevoked
                                  ? "line-through text-subtle"
                                  : "text-fg"
                              }`}
                            >
                              {tok.name}
                            </span>
                            <span
                              className={`inline-flex items-center gap-1.5 text-xs font-medium ${info.text}`}
                            >
                              <span className={`h-1.5 w-1.5 rounded-full ${info.dot}`} />
                              {info.title}
                            </span>
                            {tok.allowedSlugs.length > 0 && (
                              <span className="inline-flex items-center gap-1 text-xs font-mono text-info">
                                {tok.allowedSlugs.join(", ")}
                              </span>
                            )}
                            {isRevoked && (
                              <span className="text-xs text-bad">Turned off</span>
                            )}
                          </div>
                          <p className="text-xs font-mono text-subtle tabular-nums">
                            {tok.tokenPrefix}•••••••• &middot;{" "}
                            {tok.lastUsedAt
                              ? `Last used ${new Date(tok.lastUsedAt).toLocaleString()}`
                              : "Never used yet"}
                          </p>
                        </div>
                        {!isRevoked && (
                          <button
                            type="button"
                            onClick={() => handleRevoke(tok.id)}
                            className="btn-press inline-flex items-center gap-1.5 rounded-lg border border-line-strong px-3 py-1.5 text-xs font-medium text-muted hover:text-bad hover:border-bad-line cursor-pointer"
                          >
                            Turn off
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </section>
            <section className="surface-panel rounded-xl p-6 space-y-5">
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-medium text-fg">
                  New access key
                </h2>
              </div>

              <form onSubmit={handleCreateToken} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-medium text-muted mb-1.5">
                      Name
                    </label>
                    <input
                      type="text"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="Claude Code on MacBook"
                      required
                      className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-muted mb-1.5">
                      Permission level
                    </label>
                    <select
                      value={scope}
                      onChange={(e) => setScope(e.target.value as McpTokenScope)}
                      className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
                    >
                      <option value="safe-auto-deploy">
                        Deploy freely — asks before deleting (recommended)
                      </option>
                      <option value="approval-required">
                        Ask first — every change needs your approval
                      </option>
                      <option value="read-only">Read only — can’t change anything</option>
                      <option value="auto-approve">
                        Trusted — apps freely, server commands ask
                      </option>
                      <option value="host-admin">
                        Full admin — unrestricted root access
                      </option>
                    </select>
                  </div>
                </div>

                <p className="text-xs text-muted">{SCOPE_LABELS[scope].desc}</p>
                <div className="surface-well rounded-lg p-4 space-y-3">
                  <label className="inline-flex items-center gap-2 text-xs font-medium text-fg cursor-pointer">
                    <input
                      type="checkbox"
                      checked={restrictApps}
                      onChange={(e) => setRestrictApps(e.target.checked)}
                      className="rounded border-line-strong bg-canvas accent-fg"
                    />
                    Only allow specific apps (optional)
                  </label>

                  {restrictApps && (
                    <div className="space-y-3 pt-1">
                      {apps.length > 0 && (
                        <div className="flex flex-wrap gap-2">
                          {apps.map((app) => {
                            const checked = selectedSlugs.includes(app.slug);
                            return (
                              <button
                                key={app.slug}
                                type="button"
                                onClick={() => toggleAllowedSlug(app.slug)}
                                className={`btn-press rounded-lg border px-2.5 py-1 text-xs font-mono cursor-pointer ${
                                  checked
                                    ? "border-info-line bg-info-soft text-info"
                                    : "border-line-strong bg-surface text-muted hover:text-fg"
                                }`}
                              >
                                {checked ? "✓ " : "+ "}
                                {app.slug}
                              </button>
                            );
                          })}
                        </div>
                      )}
                      <div>
                        <label className="block text-xs text-muted mb-1.5">
                          Or type allowed app short IDs separated by commas
                        </label>
                        <input
                          type="text"
                          value={customSlugsText}
                          onChange={(e) => setCustomSlugsText(e.target.value)}
                          placeholder="my-blog, landing-page"
                          className="field-input w-full rounded-lg px-3 py-1.5 text-xs font-mono"
                        />
                      </div>
                    </div>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={busy}
                  className="btn-press inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-[13px] font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer"
                >
                  Create key
                </button>
              </form>

              {newRawToken && (
                <div className="rounded-xl border border-line bg-surface-2 p-4 space-y-2">
                  <p className="text-xs font-medium text-ok">
                    Copy this key now. For your safety it will never be shown again:
                  </p>
                  <div className="flex items-center gap-2">
                    <code className="surface-well flex-1 overflow-x-auto rounded-lg px-3 py-2 text-xs font-mono text-fg">
                      {newRawToken}
                    </code>
                    <button
                      type="button"
                      onClick={() => copyText("new-token", newRawToken)}
                      className="btn-press inline-flex items-center gap-1.5 rounded-lg bg-primary px-3 py-2 text-xs font-medium text-on-primary hover:bg-primary-hover cursor-pointer"
                    >
                      {copiedId === "new-token" ? (
                        <Check className="h-3.5 w-3.5" />
                      ) : (
                        <Copy className="h-3.5 w-3.5" />
                      )}
                      {copiedId === "new-token" ? "Copied" : "Copy"}
                    </button>
                  </div>
                </div>
              )}
            </section>
            </>
          )}
          {pane === "network" && (
            <>
            <section className="surface-panel rounded-xl p-6 space-y-6">
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-medium text-fg">
                  Domains &amp; automatic HTTPS
                </h2>
              </div>

              <form
                onSubmit={handleUpdateDomain}
                className="grid grid-cols-1 md:grid-cols-3 gap-3.5 items-end"
              >
                <div>
                  <label className="block text-xs font-medium text-muted mb-1.5">
                    Dashboard domain name
                  </label>
                  <input
                    type="text"
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                    placeholder="vps.yourdomain.com"
                    className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-muted mb-1.5">
                    Certificate notice email (optional)
                  </label>
                  <input
                    type="email"
                    value={acmeEmail}
                    onChange={(e) => setAcmeEmail(e.target.value)}
                    placeholder="you@yourdomain.com"
                    className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
                  />
                </div>
                <button
                  type="submit"
                  disabled={busy}
                  className="btn-press rounded-lg bg-primary px-4 py-2 text-[13px] font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer"
                >
                  Save dashboard domain
                </button>
              </form>

              <div className="border-t border-line pt-5 space-y-3.5">
                <div>
                  <h3 className="text-sm font-medium text-fg">
                    Default web address for new apps (optional)
                  </h3>
                  <p className="text-xs text-muted mt-1 leading-relaxed">
                    Set a base domain once so every new app automatically gets{" "}
                    <code className="text-fg">
                      https://app-name.{appsBaseDomain || "yourdomain.com"}
                    </code>{" "}
                    with automatic HTTPS. Add one wildcard DNS{" "}
                    <code className="text-fg">A</code> record:{" "}
                    <code className="text-fg">
                      *.{appsBaseDomain || "yourdomain.com"}
                    </code>{" "}
                    &rarr;{" "}
                    <code className="text-fg">
                      {publicIp || "YOUR_SERVER_IP"}
                    </code>
                    .
                  </p>
                </div>
                <form
                  onSubmit={handleUpdateAppsBaseDomain}
                  className="grid grid-cols-1 md:grid-cols-3 gap-3.5 items-end"
                >
                  <div className="md:col-span-2">
                    <label className="block text-xs font-medium text-muted mb-1.5">
                      Default apps base domain
                    </label>
                    <input
                      type="text"
                      value={appsBaseDomain}
                      onChange={(e) => setAppsBaseDomain(e.target.value)}
                      placeholder="apps.yourdomain.com (leave empty to disable)"
                      className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={busy}
                    className="btn-press rounded-lg bg-primary px-4 py-2 text-[13px] font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer"
                  >
                    Save default domain
                  </button>
                </form>
              </div>
            </section>
            <section className="surface-panel rounded-xl p-6 space-y-5">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <h2 className="text-sm font-medium text-fg">
                      Tailscale private access
                    </h2>
                    {tailscaleLoading && !tailscaleStatus ? (
                      <span className="inline-flex items-center gap-1.5 rounded-full border border-line-strong bg-fill px-2.5 py-0.5 text-[11px] font-medium text-muted">
                        Checking...
                      </span>
                    ) : tailscaleStatus?.serveEnabled ? (
                      <span className="inline-flex items-center gap-1.5 text-xs text-ok">
                        <span className="h-1.5 w-1.5 rounded-full bg-ok" />
                        Private HTTPS active
                      </span>
                    ) : tailscaleStatus?.connected ? (
                      <span className="inline-flex items-center gap-1.5 text-xs text-info">
                        <span className="h-1.5 w-1.5 rounded-full bg-info" />
                        Connected
                      </span>
                    ) : tailscaleStatus?.backendState === "needs_login" ||
                      tailscaleStatus?.backendState === "needs_machine_auth" ? (
                      <span className="inline-flex items-center gap-1.5 text-xs text-warn">
                        <span className="h-1.5 w-1.5 rounded-full bg-warn" />
                        Sign-in needed
                      </span>
                    ) : tailscaleStatus?.installed ? (
                      <span className="inline-flex items-center gap-1.5 rounded-full border border-line-strong bg-fill px-2.5 py-0.5 text-[11px] font-medium text-muted">
                        Stopped
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 rounded-full border border-line-strong bg-fill px-2.5 py-0.5 text-[11px] font-medium text-muted">
                        Not installed
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-muted leading-relaxed">
                    Reach your dashboard and AI connection over your private Tailscale
                    network with automatic{" "}
                    <code className="text-fg">https://</code> — no domain
                    purchase or DNS setup needed.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    disabled={tailscaleLoading || tailscaleBusy}
                    onClick={() =>
                      void Promise.all([loadTailscaleStatus(), onRefresh()])
                    }
                    className="btn-press inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-well px-3 py-2 text-xs font-medium text-fg hover:bg-surface-2 disabled:opacity-50 cursor-pointer"
                  >
                    <RefreshCw
                      className={`h-3.5 w-3.5 ${tailscaleLoading ? "animate-spin" : ""}`}
                    />
                    Refresh
                  </button>
                  {tailscaleBridgeSupported &&
                    tailscaleStatus?.connected &&
                    (tailscaleStatus.serveEnabled ? (
                      <button
                        type="button"
                        disabled={tailscaleBusy}
                        onClick={() => void handleToggleTailscaleServe(false)}
                        className="btn-press rounded-lg border border-line-strong px-3.5 py-2 text-xs font-medium text-muted hover:text-bad hover:border-bad-line disabled:opacity-50 cursor-pointer"
                      >
                        {tailscaleBusy ? "Updating..." : "Disable private HTTPS"}
                      </button>
                    ) : !tailscaleStatus.serveConflict ? (
                      <button
                        type="button"
                        disabled={tailscaleBusy || !tailscaleStatus.dnsName}
                        onClick={() => void handleToggleTailscaleServe(true, false)}
                        className="btn-press rounded-lg bg-primary px-4 py-2 text-[13px] font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer"
                      >
                        {tailscaleBusy ? "Enabling..." : "Enable private HTTPS"}
                      </button>
                    ) : null)}
                  {tailscaleBridgeSupported &&
                    tailscaleStatus?.installed &&
                    !tailscaleStatus.connected && (
                      <button
                        type="button"
                        disabled={tailscaleBusy}
                        onClick={() => void handleTailscaleConnect("login")}
                        className="btn-press rounded-lg bg-primary px-4 py-2 text-[13px] font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer"
                      >
                        {tailscaleBusy ? "Starting..." : "Sign in to Tailscale"}
                      </button>
                    )}
                </div>
              </div>

              {!tailscaleBridgeSupported ? (
                <p className="text-xs text-muted">
                  {tailscaleStatus?.detail ||
                    "Update VPSAgent on your server once to enable Tailscale status detection and private HTTPS."}
                </p>
              ) : tailscaleStatus && !tailscaleStatus.installed ? (
                <div className="surface-well rounded-lg p-4 space-y-3 text-xs">
                  <p className="text-fg-2">
                    Tailscale is not installed on this server yet. Run this command on
                    your server via SSH (or run{" "}
                    <code className="font-mono text-fg">
                      sudo bash ~/vpsagent/bootstrap/install.sh --tailscale
                    </code>
                    ), then click <strong className="text-fg">Refresh</strong>:
                  </p>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 overflow-x-auto rounded-md bg-canvas border border-line px-3 py-2 font-mono text-[11px] text-fg-2">
                      {TAILSCALE_INSTALL_CMD}
                    </code>
                    <button
                      type="button"
                      onClick={() => copyText("ts-install-cmd", TAILSCALE_INSTALL_CMD)}
                      className="btn-press inline-flex items-center gap-1.5 rounded-md border border-line-strong bg-surface px-3 py-2 text-xs font-medium text-fg hover:bg-surface-2 cursor-pointer shrink-0"
                    >
                      {copiedId === "ts-install-cmd" ? (
                        <Check className="h-3.5 w-3.5 text-ok" />
                      ) : (
                        <Copy className="h-3.5 w-3.5" />
                      )}
                      {copiedId === "ts-install-cmd" ? "Copied" : "Copy"}
                    </button>
                  </div>
                </div>
              ) : tailscaleStatus?.installed && !tailscaleStatus.connected ? (
                <div className="space-y-3">
                  {tailscaleLoginUrl && (
                    <div className="rounded-lg border border-line bg-surface-2 p-4 text-xs space-y-2.5">
                      <p className="font-medium text-ok">
                        Open this Tailscale link to sign in and approve your server,
                        then click Refresh above:
                      </p>
                      <a
                        href={tailscaleLoginUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1.5 rounded-lg bg-primary px-3.5 py-2 font-medium text-on-primary hover:bg-primary-hover"
                      >
                        <span>Open Tailscale sign-in</span>
                        <ExternalLink className="h-3.5 w-3.5" />
                      </a>
                    </div>
                  )}
                  {tailscaleStatus.backendState === "needs_machine_auth" && (
                    <div className="rounded-lg border border-warn-line bg-warn-soft px-4 py-3 text-xs text-warn">
                      This server is waiting for device approval in your{" "}
                      <a
                        href="https://login.tailscale.com/admin/machines"
                        target="_blank"
                        rel="noreferrer"
                        className="underline font-medium text-warn"
                      >
                        Tailscale Machines page
                      </a>
                      .
                    </div>
                  )}
                  {tailscaleStatus.detail && (
                    <p className="text-xs text-muted">{tailscaleStatus.detail}</p>
                  )}
                  <div>
                    <button
                      type="button"
                      onClick={() => setShowTailscaleAuthKey((prev) => !prev)}
                      className="inline-flex items-center gap-1.5 text-xs font-medium text-muted hover:text-fg cursor-pointer"
                    >
                      {showTailscaleAuthKey ? (
                        <ChevronUp className="h-3.5 w-3.5" />
                      ) : (
                        <ChevronDown className="h-3.5 w-3.5" />
                      )}
                      Advanced: sign in with a Tailscale auth key
                    </button>
                    {showTailscaleAuthKey && (
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          void handleTailscaleConnect("authkey");
                        }}
                        className="mt-3 flex flex-wrap items-center gap-2.5"
                      >
                        <input
                          type="password"
                          value={tailscaleAuthKey}
                          onChange={(e) => setTailscaleAuthKey(e.target.value)}
                          placeholder="tskey-auth-..."
                          autoComplete="off"
                          required
                          className="field-input flex-1 min-w-[220px] rounded-lg px-3.5 py-2 text-sm font-mono"
                        />
                        <button
                          type="submit"
                          disabled={tailscaleBusy || !tailscaleAuthKey.trim()}
                          className="btn-press rounded-lg bg-primary px-4 py-2 text-xs font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer"
                        >
                          {tailscaleBusy ? "Connecting..." : "Connect with key"}
                        </button>
                      </form>
                    )}
                  </div>
                </div>
              ) : tailscaleStatus?.connected ? (
                <div className="space-y-3.5">
                  <div className="surface-well rounded-lg p-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                    <div className="space-y-1">
                      <span className="text-muted">Tailscale IP</span>
                      <div className="flex items-center gap-2">
                        <code className="font-mono text-sm text-fg">
                          {tailscaleStatus.tailscaleIp || "Unavailable"}
                        </code>
                        {tailscaleStatus.tailscaleIp && (
                          <button
                            type="button"
                            onClick={() =>
                              copyText("ts-ip", tailscaleStatus.tailscaleIp!)
                            }
                            className="text-muted hover:text-fg cursor-pointer"
                            title="Copy Tailscale IP"
                          >
                            {copiedId === "ts-ip" ? (
                              <Check className="h-3.5 w-3.5 text-ok" />
                            ) : (
                              <Copy className="h-3.5 w-3.5" />
                            )}
                          </button>
                        )}
                      </div>
                    </div>

                    <div className="space-y-1">
                      <span className="text-muted">
                        MagicDNS hostname
                        {tailscaleStatus.tailnetName
                          ? ` (${tailscaleStatus.tailnetName})`
                          : ""}
                      </span>
                      <div className="flex items-center gap-2">
                        <code className="font-mono text-sm text-fg break-all">
                          {tailscaleStatus.dnsName || "Not enabled yet"}
                        </code>
                        {tailscaleStatus.dnsName && (
                          <button
                            type="button"
                            onClick={() =>
                              copyText("ts-dns", tailscaleStatus.dnsName!)
                            }
                            className="text-muted hover:text-fg cursor-pointer shrink-0"
                            title="Copy MagicDNS hostname"
                          >
                            {copiedId === "ts-dns" ? (
                              <Check className="h-3.5 w-3.5 text-ok" />
                            ) : (
                              <Copy className="h-3.5 w-3.5" />
                            )}
                          </button>
                        )}
                      </div>
                    </div>

                    {tailscaleStatus.serveEnabled && tailscaleStatus.serveUrl && (
                      <>
                        <div className="space-y-1 pt-2 border-t border-line">
                          <span className="text-muted">
                            Private dashboard URL
                          </span>
                          <div className="flex items-center gap-2">
                            <a
                              href={tailscaleStatus.serveUrl}
                              target="_blank"
                              rel="noreferrer"
                              className="inline-flex items-center gap-1 font-mono link break-all"
                            >
                              <span>{tailscaleStatus.serveUrl}</span>
                              <ExternalLink className="h-3 w-3 shrink-0" />
                            </a>
                            <button
                              type="button"
                              onClick={() =>
                                copyText("ts-dash-url", tailscaleStatus.serveUrl!)
                              }
                              className="text-muted hover:text-fg cursor-pointer shrink-0"
                              title="Copy private dashboard URL"
                            >
                              {copiedId === "ts-dash-url" ? (
                                <Check className="h-3.5 w-3.5 text-ok" />
                              ) : (
                                <Copy className="h-3.5 w-3.5" />
                              )}
                            </button>
                          </div>
                        </div>

                        {tailscaleStatus.mcpUrl && (
                          <div className="space-y-1 pt-2 border-t border-line">
                            <span className="text-muted">
                              Private AI connection (MCP) address
                            </span>
                            <div className="flex items-center gap-2">
                              <code className="font-mono text-fg break-all">
                                {tailscaleStatus.mcpUrl}
                              </code>
                              <button
                                type="button"
                                onClick={() =>
                                  copyText("ts-mcp-url", tailscaleStatus.mcpUrl!)
                                }
                                className="text-muted hover:text-fg cursor-pointer shrink-0"
                                title="Copy private MCP URL"
                              >
                                {copiedId === "ts-mcp-url" ? (
                                  <Check className="h-3.5 w-3.5 text-ok" />
                                ) : (
                                  <Copy className="h-3.5 w-3.5" />
                                )}
                              </button>
                            </div>
                          </div>
                        )}
                      </>
                    )}
                  </div>

                  {(!tailscaleStatus.magicDnsEnabled ||
                    !tailscaleStatus.httpsCertsAvailable) && (
                    <div className="rounded-lg border border-warn-line bg-warn-soft px-4 py-3 text-xs text-warn">
                      Turn on <strong className="font-medium">MagicDNS</strong> and{" "}
                      <strong className="font-medium">HTTPS Certificates</strong> in{" "}
                      <a
                        href="https://login.tailscale.com/admin/dns"
                        target="_blank"
                        rel="noreferrer"
                        className="underline font-medium text-warn"
                      >
                        Tailscale DNS settings
                      </a>
                      , then click{" "}
                      <strong className="font-medium">Enable private HTTPS</strong>.
                    </div>
                  )}

                  {tailscaleConflict && tailscaleStatus && (
                    <div className="rounded-lg border border-warn-line bg-warn-soft px-4 py-3 text-xs text-warn space-y-3">
                      <p>{tailscaleConflict.headline}</p>
                      <ul className="space-y-2">
                        {tailscaleConflict.effects.map((effect) => (
                          <li
                            key={`${effect.kind}:${effect.routes}`}
                            className="rounded-md border border-warn-line bg-well px-3 py-2 space-y-0.5"
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
                      <div className="flex justify-end">
                        <button
                          type="button"
                          disabled={tailscaleBusy || !tailscaleStatus.dnsName}
                          onClick={() => void handleToggleTailscaleServe(true, true)}
                          className="btn-press rounded-lg bg-warn px-3 py-1.5 text-xs font-medium text-on-warn hover:opacity-90 disabled:opacity-50 cursor-pointer"
                        >
                          {tailscaleBusy
                            ? "Updating..."
                            : tailscaleConflict.confirmButtonLabel}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              ) : null}
            </section>
            </>
          )}
          {pane === "github" && (
            <section
              id="github-access"
              ref={githubSectionRef}
              className="surface-panel rounded-xl p-6 space-y-5"
            >
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <h2 className="text-sm font-medium text-fg">
                      Private GitHub repositories
                    </h2>
                    {gitCredentials.length > 0 ? (
                      <span className="inline-flex items-center gap-1.5 text-xs text-ok">
                        <span className="h-1.5 w-1.5 rounded-full bg-ok" />
                        Connected ({gitCredentials.length})
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 rounded-full border border-line-strong bg-fill px-2.5 py-0.5 text-[11px] font-medium text-muted">
                        Not connected
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-muted leading-relaxed">
                    Connect a read-only GitHub token so you and your AI can browse and
                    deploy private GitHub repos. Your token is encrypted at rest and
                    never shown again or sent to AI chats.
                  </p>
                </div>
                <a
                  href="https://github.com/settings/personal-access-tokens/new"
                  target="_blank"
                  rel="noreferrer"
                  className="btn-press inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-well px-3 py-1.5 text-xs font-medium text-fg hover:bg-surface-2 shrink-0"
                >
                  <span>Create token on GitHub</span>
                  <ExternalLink className="h-3.5 w-3.5" />
                </a>
              </div>

              <div className="surface-well rounded-lg px-4 py-3 text-xs text-fg-2 space-y-1">
                <p className="font-medium text-fg">
                  Quick 3-step setup on GitHub (recommended fine-grained token):
                </p>
                <ol className="list-decimal list-inside space-y-0.5 text-muted">
                  <li>
                    Choose <strong className="text-fg">Only select repositories</strong> (or All repositories).
                  </li>
                  <li>
                    Under <strong className="text-fg">Repository permissions</strong>, set{" "}
                    <strong className="text-fg">Contents</strong> to{" "}
                    <strong className="text-fg">Read-only</strong> (Metadata is included automatically).
                  </li>
                  <li>
                    Click <strong className="text-fg">Generate token</strong>, copy it, and paste it below.
                  </li>
                </ol>
              </div>

              <form
                onSubmit={handleAddGithubToken}
                className="grid grid-cols-1 md:grid-cols-12 gap-3.5 items-end"
              >
                <div className="md:col-span-5">
                  <label className="block text-xs font-medium text-muted mb-1.5">
                    GitHub personal access token
                  </label>
                  <input
                    type="password"
                    value={githubToken}
                    onChange={(e) => setGithubToken(e.target.value)}
                    placeholder="github_pat_... or ghp_..."
                    required
                    autoComplete="off"
                    className="field-input w-full rounded-lg px-3.5 py-2 text-sm font-mono"
                  />
                </div>
                <div className="md:col-span-4">
                  <label className="block text-xs font-medium text-muted mb-1.5">
                    Label (optional)
                  </label>
                  <input
                    type="text"
                    value={githubLabel}
                    onChange={(e) => setGithubLabel(e.target.value)}
                    placeholder="Personal GitHub or Work Org"
                    className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
                  />
                </div>
                <div className="md:col-span-3">
                  <button
                    type="submit"
                    disabled={githubBusy || !githubToken.trim()}
                    className="btn-press w-full inline-flex items-center justify-center gap-1.5 rounded-lg bg-primary px-4 py-2 text-[13px] font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer"
                  >
                    {githubBusy ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Lock className="h-3.5 w-3.5" />
                    )}
                    {githubBusy ? "Verifying..." : "Verify & connect"}
                  </button>
                </div>
              </form>

              {gitCredentials.length > 0 && (
                <div className="divide-y divide-line rounded-lg border border-line bg-canvas">
                  {gitCredentials.map((cred) => (
                    <div
                      key={cred.id}
                      className="flex flex-wrap items-center justify-between gap-3 px-4 py-3"
                    >
                      <div className="space-y-1 min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-sm font-medium text-fg">
                            {cred.label}
                          </span>
                          {cred.accountLogin && (
                            <span className="text-xs font-mono text-info">
                              @{cred.accountLogin}
                            </span>
                          )}
                          {cred.isDefault && (
                            <span className="inline-flex items-center gap-1 text-xs text-ok">
                              Default
                            </span>
                          )}
                        </div>
                        <p className="text-xs font-mono text-subtle tabular-nums">
                          {cred.tokenHint} &middot;{" "}
                          {cred.lastUsedAt
                            ? `Last used ${new Date(cred.lastUsedAt).toLocaleString()}`
                            : `Added ${new Date(cred.createdAt).toLocaleDateString()}`}
                        </p>
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          type="button"
                          disabled={githubBusy || testingCredId === cred.id}
                          onClick={() => void handleTestGithubCred(cred.id)}
                          className="btn-press inline-flex items-center gap-1 rounded-lg border border-line-strong bg-surface px-2.5 py-1.5 text-xs font-medium text-fg hover:bg-surface-2 disabled:opacity-50 cursor-pointer"
                        >
                          {testingCredId === cred.id ? (
                            <Loader2 className="h-3 w-3 animate-spin" />
                          ) : (
                            <Check className="h-3 w-3 text-ok" />
                          )}
                          Test
                        </button>
                        {!cred.isDefault && (
                          <button
                            type="button"
                            disabled={githubBusy}
                            onClick={() => void handleSetDefaultGithubCred(cred.id)}
                            className="btn-press rounded-lg border border-line-strong bg-surface px-2.5 py-1.5 text-xs font-medium text-fg-2 hover:text-fg disabled:opacity-50 cursor-pointer"
                          >
                            Set default
                          </button>
                        )}
                        <button
                          type="button"
                          disabled={githubBusy}
                          onClick={() =>
                            void handleDeleteGithubCred(cred.id, cred.label)
                          }
                          className="btn-press inline-flex items-center gap-1 rounded-lg border border-line-strong px-2.5 py-1.5 text-xs font-medium text-muted hover:text-bad hover:border-bad-line disabled:opacity-50 cursor-pointer"
                        >
                          Remove
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>
          )}
          {pane === "alerts" && (() => {
            const hasUnsavedAlertChanges = Boolean(
              alertSettings &&
                (alertEnabled !== alertSettings.enabled ||
                  alertChannel !== alertSettings.channel ||
                  notifyOnApproval !== alertSettings.notifyOnApproval ||
                  notifyOnAppDown !== alertSettings.notifyOnAppDown ||
                  notifyOnDeployFailure !== alertSettings.notifyOnDeployFailure ||
                  (alertChannel === "telegram" &&
                    (alertTelegramChatId.trim() !==
                      (alertSettings.telegramChatId ?? "").trim() ||
                      alertTelegramToken.trim().length > 0)) ||
                  (alertChannel !== "telegram" &&
                    alertChannel !== "none" &&
                    alertWebhookUrl.trim().length > 0)),
            );
            const savedTargetMatchesChannel = Boolean(
              alertSettings?.hasTargetSecret &&
                alertSettings.channel === alertChannel,
            );
            return (
            <form
              onSubmit={(e) => void handleSaveAlerts(e)}
              className="surface-panel rounded-xl p-6 space-y-5"
            >
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <h2 className="text-sm font-medium text-fg">
                    Instant alerts
                  </h2>
                  <p className="text-xs text-muted mt-1">
                    Get notified immediately when an AI pass asks for your approval, an app goes offline, or a build fails.
                  </p>
                </div>
                <label className="inline-flex items-center gap-2 text-xs font-medium text-fg cursor-pointer">
                  <input
                    type="checkbox"
                    checked={alertEnabled && alertChannel !== "none"}
                    disabled={alertChannel === "none"}
                    onChange={(e) => setAlertEnabled(e.target.checked)}
                    className="rounded border-line-strong bg-canvas accent-fg"
                  />
                  Enable alerts
                </label>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-muted mb-1.5">
                    Alert channel
                  </label>
                  <select
                    value={alertChannel}
                    onChange={(e) => {
                      const next = e.target.value as NotificationChannel;
                      setAlertChannel(next);
                      if (next !== "none" && !alertEnabled) {
                        setAlertEnabled(true);
                      }
                    }}
                    className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
                  >
                    <option value="none">Off</option>
                    <option value="discord">Discord webhook</option>
                    <option value="slack">Slack webhook</option>
                    <option value="telegram">Telegram bot</option>
                    <option value="webhook">Custom HTTPS webhook</option>
                  </select>
                </div>

                {savedTargetMatchesChannel && alertSettings?.targetHint && (
                  <div className="surface-well rounded-lg px-3.5 py-2.5 flex items-center justify-between text-xs">
                    <span className="text-muted">Saved target:</span>
                    <code className="font-mono text-fg">
                      {alertSettings.targetHint}
                    </code>
                  </div>
                )}
              </div>

              {alertChannel === "telegram" ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-medium text-muted mb-1.5">
                      Telegram bot token (from @BotFather)
                    </label>
                    <input
                      type="password"
                      value={alertTelegramToken}
                      onChange={(e) => setAlertTelegramToken(e.target.value)}
                      placeholder={
                        alertSettings?.hasTargetSecret &&
                        alertSettings.channel === "telegram"
                          ? "Leave blank to keep saved token"
                          : "123456789:AA..."
                      }
                      className="field-input w-full rounded-lg px-3.5 py-2 text-sm font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-muted mb-1.5">
                      Telegram chat ID
                    </label>
                    <input
                      type="text"
                      value={alertTelegramChatId}
                      onChange={(e) => setAlertTelegramChatId(e.target.value)}
                      placeholder="123456789 or @mychannel"
                      className="field-input w-full rounded-lg px-3.5 py-2 text-sm font-mono"
                    />
                  </div>
                </div>
              ) : alertChannel !== "none" ? (
                <div>
                  <label className="block text-xs font-medium text-muted mb-1.5">
                    {alertChannel === "discord"
                      ? "Discord webhook URL"
                      : alertChannel === "slack"
                        ? "Slack incoming webhook URL"
                        : "Custom HTTPS webhook URL"}
                  </label>
                  <input
                    type="password"
                    value={alertWebhookUrl}
                    onChange={(e) => setAlertWebhookUrl(e.target.value)}
                    placeholder={
                      alertSettings?.hasTargetSecret &&
                      alertSettings.channel === alertChannel
                        ? "Leave blank to keep saved webhook URL"
                        : alertChannel === "discord"
                          ? "https://discord.com/api/webhooks/..."
                          : alertChannel === "slack"
                            ? "https://hooks.slack.com/services/..."
                            : "https://your-service.example.com/webhook"
                    }
                    className="field-input w-full rounded-lg px-3.5 py-2 text-sm font-mono"
                  />
                  <p className="mt-1.5 text-[11px] text-subtle">
                    Encrypted at rest. Payloads automatically scrub secrets before leaving your server.
                  </p>
                </div>
              ) : null}

              {alertChannel !== "none" && (
                <div className="space-y-2 pt-1">
                  <p className="text-xs font-medium text-muted">
                    Send an alert when:
                  </p>
                  <div className="flex flex-wrap gap-5">
                    <label className="inline-flex items-center gap-2 text-xs text-fg-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={notifyOnApproval}
                        onChange={(e) => setNotifyOnApproval(e.target.checked)}
                        className="rounded border-line-strong bg-canvas accent-fg"
                      />
                      AI asks for approval
                    </label>
                    <label className="inline-flex items-center gap-2 text-xs text-fg-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={notifyOnAppDown}
                        onChange={(e) => setNotifyOnAppDown(e.target.checked)}
                        className="rounded border-line-strong bg-canvas accent-fg"
                      />
                      An app goes offline or recovers
                    </label>
                    <label className="inline-flex items-center gap-2 text-xs text-fg-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={notifyOnDeployFailure}
                        onChange={(e) =>
                          setNotifyOnDeployFailure(e.target.checked)
                        }
                        className="rounded border-line-strong bg-canvas accent-fg"
                      />
                      A build or rollback fails
                    </label>
                  </div>
                </div>
              )}

              {(alertSettings?.lastSentAt || alertSettings?.lastError) && (
                <div className="surface-well rounded-lg px-3.5 py-2.5 text-xs space-y-1">
                  {alertSettings.lastSentAt && (
                    <p className="text-fg-2">
                      Last alert sent:{" "}
                      {new Date(alertSettings.lastSentAt).toLocaleString()}
                    </p>
                  )}
                  {alertSettings.lastError && (
                    <p className="text-bad">
                      Last delivery error: {alertSettings.lastError}
                    </p>
                  )}
                </div>
              )}

              <div className="flex flex-wrap items-center justify-end gap-2.5 pt-1">
                {savedTargetMatchesChannel && alertChannel !== "none" && (
                  <>
                    {hasUnsavedAlertChanges && (
                      <span className="text-xs text-muted mr-auto">
                        Save changes first to test this destination.
                      </span>
                    )}
                    <button
                      type="button"
                      disabled={
                        alertTesting || alertBusy || hasUnsavedAlertChanges
                      }
                      onClick={() => void handleTestAlert()}
                      className={buttonSecondary}
                    >
                      {alertTesting ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : null}
                      {alertTesting ? "Sending..." : "Send test alert"}
                    </button>
                  </>
                )}
                <button
                  type="submit"
                  disabled={alertBusy}
                  className={buttonPrimary}
                >
                  {alertBusy ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : null}
                  {alertBusy ? "Saving..." : "Save alert settings"}
                </button>
              </div>
            </form>
            );
          })()}
          {pane === "backups" && (
            <section className="surface-panel rounded-xl p-6 space-y-5">
              <div>
                <h2 className="text-sm font-medium text-fg">Server backup</h2>
                <p className="text-xs text-muted mt-1">
                  Download a safe archive of your VPSAgent database, reverse-proxy routes, app blueprints, and optionally all app data + Postgres dumps.
                </p>
              </div>

              <div className="rounded-lg border border-warn-line bg-warn-soft px-4 py-3 text-xs text-warn space-y-1">
                <p className="font-medium">Secrets are excluded on purpose</p>
                <p>
                  For your protection, downloadable backups never include{" "}
                  <code className="font-mono">.env</code> files or encryption keys. If you plan to migrate to a brand-new VPS, keep a separate offline copy of{" "}
                  <code className="font-mono">/var/lib/vpsagent/.env</code> so your saved variables and tokens can be decrypted.
                </p>
              </div>

              <label className="inline-flex items-center gap-2 text-sm text-fg-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeBackupAppData}
                  onChange={(e) => setIncludeBackupAppData(e.target.checked)}
                  className="rounded border-line-strong bg-canvas accent-fg"
                />
                Include app <code className="font-mono text-xs">/app/data</code>{" "}
                files and live Postgres database dumps
              </label>

              <div className="flex justify-end">
                <button
                  type="button"
                  disabled={backupDownloading}
                  onClick={() => void handleDownloadSystemBackup()}
                  className={buttonPrimary}
                >
                  {backupDownloading ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Download className="h-3.5 w-3.5" />
                  )}
                  {backupDownloading
                    ? "Building archive..."
                    : "Download server backup (.tar.gz)"}
                </button>
              </div>
            </section>
          )}
          {pane === "account" && (
            <div className="space-y-6">
              <form
                onSubmit={(e) => void handleChangePassword(e)}
                className="surface-panel rounded-xl p-6 space-y-4"
              >
                <div>
                  <h2 className="text-sm font-medium text-fg">
                    Change login password
                  </h2>
                  <p className="text-xs text-muted mt-1">
                    Updating your password keeps this browser signed in and automatically signs out all older sessions.
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div>
                    <label className="block text-xs font-medium text-muted mb-1.5">
                      Current password
                    </label>
                    <input
                      type="password"
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      required
                      className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-muted mb-1.5">
                      New password (min 8 chars)
                    </label>
                    <input
                      type="password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      minLength={8}
                      required
                      className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-muted mb-1.5">
                      Confirm new password
                    </label>
                    <input
                      type="password"
                      value={confirmNewPassword}
                      onChange={(e) => setConfirmNewPassword(e.target.value)}
                      minLength={8}
                      required
                      className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
                    />
                  </div>
                </div>

                <div className="flex justify-end">
                  <button
                    type="submit"
                    disabled={accountBusy}
                    className={buttonPrimary}
                  >
                    {accountBusy ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : null}
                    Update password
                  </button>
                </div>
              </form>

              <section className="surface-panel rounded-xl p-6 flex flex-wrap items-center justify-between gap-4">
                <div>
                  <h2 className="text-sm font-medium text-fg">
                    Active dashboard sessions
                  </h2>
                  <p className="text-xs text-muted mt-1">
                    Immediately sign out every browser and device using this dashboard (including this window).
                  </p>
                </div>
                <button
                  type="button"
                  disabled={accountBusy}
                  onClick={() => void handleLogoutAll()}
                  className={buttonSecondary}
                >
                  Sign out all devices
                </button>
              </section>

              <section className="surface-panel rounded-xl p-6 space-y-3">
                <h2 className="text-sm font-medium text-fg">
                  Forgot your password?
                </h2>
                <p className="text-xs text-muted">
                  If you ever get locked out, connect to your VPS over SSH and run this recovery command as root/sudo:
                </p>
                <div className="flex items-center justify-between gap-3 rounded-lg border border-line bg-canvas px-3.5 py-2.5 text-xs">
                  <code className="font-mono text-fg break-all">
                    {RESET_PASSWORD_CMD}
                  </code>
                  <button
                    type="button"
                    onClick={() =>
                      void copyText("reset-cmd", RESET_PASSWORD_CMD)
                    }
                    className={buttonSecondary}
                  >
                    {copiedId === "reset-cmd" ? (
                      <Check className="h-3.5 w-3.5 text-ok" />
                    ) : (
                      <Copy className="h-3.5 w-3.5" />
                    )}
                    Copy
                  </button>
                </div>
              </section>
            </div>
          )}
          {pane === "updates" && (
            <section
              id="vpsagent-updates"
              ref={updatesSectionRef}
              className="surface-panel rounded-xl p-6 space-y-5"
            >
              {(() => {
                const isUpdating = updateStatus?.state === "updating";
                const isReleaseUpdate = updateStatus?.updateSource === "release";
                const updateSteps = isReleaseUpdate
                  ? RELEASE_UPDATE_STEPS
                  : GIT_UPDATE_STEPS;
                const activeStepIdx = getUpdateStepIndex(
                  updateStatus?.phase ?? null,
                  reconnectingUpdate,
                  isReleaseUpdate,
                );
                const safeReleaseUrl = isSafeHttpsUrl(updateStatus?.latestReleaseUrl)
                  ? updateStatus.latestReleaseUrl
                  : null;
                const installedVersionLabel = updateStatus?.currentVersion
                  ? `v${updateStatus.currentVersion.replace(/^v/i, "")}`
                  : updateStatus?.currentReleaseTag || "Unknown";
                const latestReleaseLabel = updateStatus?.latestVersion
                  ? `v${updateStatus.latestVersion.replace(/^v/i, "")}`
                  : updateStatus?.latestReleaseTag || null;
                const updateButtonLabel = isUpdating
                  ? "Updating..."
                  : startingUpdate
                    ? "Starting..."
                    : updateStatus?.updateAvailable &&
                        isReleaseUpdate &&
                        updateStatus.latestReleaseTag
                      ? `Update to ${updateStatus.latestReleaseTag}`
                      : updateStatus?.updateAvailable
                        ? "Install update"
                        : updateStatus?.checkedAt && !updateStatus.updateAvailable
                          ? "Rebuild VPSAgent"
                          : "Update VPSAgent";
                const isSecondaryRebuild = Boolean(
                  updateStatus?.canUpdate &&
                    updateStatus.checkedAt &&
                    !updateStatus.updateAvailable &&
                    !isUpdating,
                );

                return (
                  <>
                    <div className="flex flex-wrap items-start justify-between gap-4">
                      <div className="space-y-1">
                        <div className="flex flex-wrap items-center gap-2.5">
                          <h2 className="text-sm font-medium text-fg">
                            VPSAgent updates
                          </h2>
                          {isUpdating && (
                            <span className="inline-flex items-center gap-1.5 text-xs text-warn">
                              <span className="h-1.5 w-1.5 rounded-full bg-warn animate-pulse" />
                              {reconnectingUpdate ? "Restarting..." : "Updating..."}
                            </span>
                          )}
                          {!isUpdating && updateStatus?.updateAvailable && (
                            <span className="inline-flex items-center gap-1.5 text-xs text-ok">
                              <span className="h-1.5 w-1.5 rounded-full bg-ok" />
                              {isReleaseUpdate && updateStatus.latestReleaseTag
                                ? `${updateStatus.latestReleaseTag} ready`
                                : `${updateStatus.commitsBehind} new ${
                                    updateStatus.commitsBehind === 1
                                      ? "update"
                                      : "updates"
                                  }`}
                            </span>
                          )}
                          {!isUpdating &&
                            updateStatus?.state !== "failed" &&
                            updateStatus?.checkedAt &&
                            !updateStatus.updateAvailable &&
                            updateStatus.canUpdate && (
                              <span className="inline-flex items-center gap-1.5 rounded-full border border-line-strong bg-fill px-2.5 py-0.5 text-[11px] font-medium text-fg-2">
                                Up to date
                              </span>
                            )}
                          {updateStatus?.checksumStatus === "verified" && (
                            <span className="inline-flex items-center gap-1 text-xs text-ok">
                              SHA-256 verified
                            </span>
                          )}
                          {updateStatus?.checksumStatus !== "verified" &&
                            updateStatus?.checksumAvailable && (
                              <span className="inline-flex items-center gap-1 text-xs text-info">
                                SHA-256 check included
                              </span>
                            )}
                          {updateStatus?.updateSource === "git" &&
                            (updateStatus.releaseStatus === "no_releases" ||
                              updateStatus.releaseStatus === "unavailable") && (
                              <span className="inline-flex items-center rounded-full border border-line-strong bg-fill px-2.5 py-0.5 text-[11px] font-medium text-muted">
                                Branch fallback
                              </span>
                            )}
                        </div>
                        <p className="text-xs text-muted">
                          Checks GitHub Releases (or your linked branch if no release
                          is published yet) and safely updates VPSAgent without
                          touching your apps, secrets, or database.
                        </p>
                      </div>

                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          type="button"
                          disabled={
                            updateLoading ||
                            checkingUpdate ||
                            startingUpdate ||
                            isUpdating
                          }
                          onClick={handleCheckUpdates}
                          className="btn-press inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-well px-3 py-2 text-xs font-medium text-fg hover:bg-surface-2 disabled:opacity-50 cursor-pointer"
                        >
                          <RefreshCw
                            className={`h-3.5 w-3.5 ${checkingUpdate ? "animate-spin" : ""}`}
                          />
                          {checkingUpdate ? "Checking..." : "Check for updates"}
                        </button>
                        <button
                          type="button"
                          disabled={
                            updateLoading ||
                            startingUpdate ||
                            checkingUpdate ||
                            !updateStatus?.canUpdate ||
                            isUpdating
                          }
                          onClick={handleApplyUpdate}
                          className={
                            isSecondaryRebuild
                              ? "btn-press inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-surface px-3.5 py-2 text-xs font-medium text-fg hover:bg-surface-2 disabled:opacity-50 cursor-pointer"
                              : "btn-press inline-flex items-center gap-1.5 rounded-lg bg-primary px-4 py-2 text-[13px] font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer"
                          }
                        >
                          {updateButtonLabel}
                        </button>
                      </div>
                    </div>

                    <div className="surface-well rounded-lg px-4 py-3 flex flex-wrap items-center justify-between gap-3 text-xs">
                      <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 text-muted">
                        <span>
                          Installed:{" "}
                          <code className="font-mono text-fg">
                            {installedVersionLabel}
                          </code>
                          {updateStatus?.currentCommit && (
                            <code className="ml-1.5 font-mono text-subtle">
                              ({updateStatus.currentCommit.slice(0, 7)})
                            </code>
                          )}
                          {updateStatus?.installedFrom === "release" && (
                            <span className="ml-1.5 text-[11px] text-ok">
                              release
                            </span>
                          )}
                        </span>

                        <span>
                          Latest available:{" "}
                          {latestReleaseLabel ? (
                            <>
                              <code
                                className={`font-mono ${
                                  updateStatus?.updateAvailable && isReleaseUpdate
                                    ? "text-ok font-medium"
                                    : "text-fg"
                                }`}
                              >
                                {latestReleaseLabel}
                              </code>
                              {updateStatus?.latestReleasePrerelease && (
                                <span className="ml-1.5 text-[11px] text-warn">
                                  Pre-release
                                </span>
                              )}
                              {safeReleaseUrl && (
                                <a
                                  href={safeReleaseUrl}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="ml-2 inline-flex items-center gap-1 text-[11px] link"
                                >
                                  <span>View release</span>
                                  <ExternalLink className="h-3 w-3" />
                                </a>
                              )}
                            </>
                          ) : updateStatus?.releaseStatus === "no_releases" ? (
                            <span className="text-fg-2">
                              No GitHub release yet{" "}
                              {updateStatus.branch
                                ? `(tracking ${updateStatus.branch})`
                                : ""}
                            </span>
                          ) : updateStatus?.releaseStatus === "unavailable" ? (
                            <span className="text-warn">
                              Release check unavailable{" "}
                              {updateStatus.branch
                                ? `(tracking ${updateStatus.branch})`
                                : ""}
                            </span>
                          ) : updateStatus?.updateSource === "git" &&
                            updateStatus.updateAvailable &&
                            updateStatus.latestCommit ? (
                            <code className="font-mono text-fg">
                              {updateStatus.commitsBehind} commit
                              {updateStatus.commitsBehind === 1 ? "" : "s"} ahead (
                              {updateStatus.latestCommit.slice(0, 7)})
                            </code>
                          ) : (
                            <span className="text-subtle">
                              Click &ldquo;Check for updates&rdquo;
                            </span>
                          )}
                        </span>

                        {updateStatus?.branch && (
                          <span>
                            Branch:{" "}
                            <code className="font-mono text-fg">
                              {updateStatus.branch}
                            </code>
                          </span>
                        )}
                      </div>
                      {updateStatus?.checkedAt && (
                        <span className="text-[11px] text-subtle tabular-nums">
                          Last checked{" "}
                          {new Date(updateStatus.checkedAt).toLocaleString()}
                        </span>
                      )}
                    </div>

                    {!isUpdating &&
                      updateStatus?.updateAvailable &&
                      isReleaseUpdate && (
                        <div className="rounded-lg border border-line bg-surface-2 px-4 py-3 text-xs text-fg-2 space-y-2">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div>
                              <span className="font-medium text-fg">
                                {updateStatus.latestReleaseName ||
                                  updateStatus.latestReleaseTag ||
                                  "New release available"}
                              </span>
                              {updateStatus.latestReleasePublishedAt && (
                                <span className="ml-2 text-[11px] text-muted">
                                  Published{" "}
                                  {new Date(
                                    updateStatus.latestReleasePublishedAt,
                                  ).toLocaleDateString()}
                                </span>
                              )}
                            </div>
                            {safeReleaseUrl && (
                              <a
                                href={safeReleaseUrl}
                                target="_blank"
                                rel="noreferrer"
                                className="inline-flex items-center gap-1 text-[11px] font-medium link"
                              >
                                <span>Release notes on GitHub</span>
                                <ExternalLink className="h-3 w-3" />
                              </a>
                            )}
                          </div>
                          {updateStatus.latestReleaseNotes && (
                            <p className="whitespace-pre-line text-[11px] text-fg-2 leading-relaxed max-h-28 overflow-y-auto">
                              {updateStatus.latestReleaseNotes}
                            </p>
                          )}
                          <p className="text-[11px] text-muted">
                            {updateStatus.checksumAvailable
                              ? "Includes a SHA-256 checksum that VPSAgent verifies automatically before rebuilding."
                              : "Downloads directly from GitHub Releases without touching your apps, secrets, or database."}
                          </p>
                        </div>
                      )}

                    {!isUpdating &&
                      updateStatus?.updateAvailable &&
                      !isReleaseUpdate &&
                      updateStatus.latestCommitSubject && (
                        <div className="rounded-lg border border-line bg-surface-2 px-4 py-3 text-xs text-fg-2">
                          <span className="font-medium">Latest change: </span>
                          {updateStatus.latestCommitSubject}
                          {updateStatus.latestCommit && (
                            <code className="ml-2 font-mono text-fg">
                              ({updateStatus.latestCommit.slice(0, 7)})
                            </code>
                          )}
                        </div>
                      )}

                    {!isUpdating && updateStatus?.releaseNote && (
                      <p className="text-xs text-muted">
                        {updateStatus.releaseNote}
                      </p>
                    )}

                    {isUpdating && (
                      <div className="rounded-lg border border-warn-line bg-warn-soft px-4 py-3.5 text-xs text-warn space-y-3">
                        <div>
                          <span className="font-medium">
                            {reconnectingUpdate
                              ? "Restarting VPSAgent: "
                              : "Update in progress: "}
                          </span>
                          {reconnectingUpdate
                            ? "Reconnecting to your server automatically. This page will reload as soon as it is back."
                            : updateStatus?.message ||
                              "Downloading and rebuilding VPSAgent..."}
                        </div>
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                          {updateSteps.map((step, idx) => {
                            const done = idx < activeStepIdx;
                            const current = idx === activeStepIdx;
                            return (
                              <div
                                key={step.key}
                                className={`rounded-md border px-2.5 py-1.5 text-[11px] flex items-center gap-1.5 ${
                                  done
                                    ? "border-line-strong bg-fill text-fg"
                                    : current
                                      ? "border-warn-line bg-warn-soft text-warn font-medium"
                                      : "border-line bg-well text-muted"
                                }`}
                              >
                                {done ? (
                                  <Check className="h-3 w-3 text-ok shrink-0" />
                                ) : current ? (
                                  <Loader2 className="h-3 w-3 text-warn animate-spin shrink-0" />
                                ) : (
                                  <span className="h-1.5 w-1.5 rounded-full bg-fill shrink-0" />
                                )}
                                <span className="truncate">{step.label}</span>
                              </div>
                            );
                          })}
                        </div>
                        <p className="text-[11px] text-warn">
                          Your apps, secrets, database, and login stay untouched while
                          VPSAgent restarts.
                        </p>
                      </div>
                    )}

                    {updateStatus?.state === "failed" && updateStatus.error && (
                      <div className="rounded-lg border border-line-strong px-4 py-3 text-xs text-muted hover:text-bad">
                        <span className="font-medium">Last update failed: </span>
                        {updateStatus.error}
                      </div>
                    )}

                    {!updateLoading &&
                      updateStatus &&
                      !updateStatus.canUpdate &&
                      updateStatus.unavailableReason && (
                        <p className="text-xs text-muted">
                          {updateStatus.unavailableReason}
                        </p>
                      )}

                    {!updateLoading && !updateStatus && updateLoadError && (
                      <p className="text-xs text-warn">
                        Could not check update availability: {updateLoadError}
                      </p>
                    )}

                    {updateStatus && updateStatus.logs.length > 0 && (
                      <div className="space-y-2">
                        <button
                          type="button"
                          onClick={() => setShowUpdateLogs((prev) => !prev)}
                          className="inline-flex items-center gap-1.5 text-xs font-medium text-muted hover:text-fg cursor-pointer"
                        >
                          {showUpdateLogs ? (
                            <ChevronUp className="h-3.5 w-3.5" />
                          ) : (
                            <ChevronDown className="h-3.5 w-3.5" />
                          )}
                          {showUpdateLogs ? "Hide update log" : "View update log"}
                        </button>
                        {showUpdateLogs && (
                          <pre className="surface-well max-h-56 overflow-auto rounded-lg p-3 text-[11px] font-mono text-fg-2 leading-relaxed">
                            {updateStatus.logs.join("\n")}
                          </pre>
                        )}
                      </div>
                    )}
                  </>
                );
              })()}
            </section>
          )}
        </div>
      </div>
    </div>
  );
}
