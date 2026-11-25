import { useCallback, useEffect, useState } from "react";
import {
  Database,
  ExternalLink,
  GitBranch,
  Globe,
  Hammer,
  KeyRound,
  Loader2,
  Play,
  Plus,
  Rocket,
  RotateCw,
  Search,
  ShieldCheck,
  Sparkles,
  Square,
  Terminal,
  Trash2,
} from "lucide-react";
import {
  api,
  type AppEnvEntry,
  type AppRecord,
  type CompanionService,
  type DeploymentRecord,
  type GitInspectResult,
  type InspectResult,
} from "../api";
import { formatSafetyCheckHealth, type HealthBadge } from "../health-display";

function healthToneClass(tone: HealthBadge["tone"]): string {
  if (tone === "healthy") return "text-emerald-300";
  if (tone === "unhealthy") return "text-rose-300";
  if (tone === "warning") return "text-amber-300";
  return "text-[#E5E7EB]";
}

function isDeploymentActive(status: DeploymentRecord["status"]): boolean {
  return (
    status === "queued" ||
    status === "cloning" ||
    status === "building" ||
    status === "starting" ||
    status === "verifying"
  );
}

function deploymentToneClass(status: DeploymentRecord["status"]): string {
  if (status === "succeeded") return "text-emerald-300";
  if (status === "failed") return "text-rose-300";
  return "text-amber-300";
}

function appStatusDot(status: AppRecord["status"]): string {
  if (status === "running") return "bg-emerald-400";
  if (status === "error") return "bg-rose-400";
  return "bg-amber-400";
}

function appStatusText(status: AppRecord["status"]): string {
  if (status === "running") return "text-emerald-300";
  if (status === "error") return "text-rose-300";
  return "text-amber-300";
}

type DrawerSection = "deployments" | "logs" | "domain" | "env" | "security";

interface AppsTabProps {
  apps: AppRecord[];
  appsBaseDomain: string | null;
  deepLink?: {
    slug: string;
    section: DrawerSection;
    deploymentId?: string;
  } | null;
  onConsumeDeepLink?: () => void;
  onRefresh: () => Promise<void>;
  onInspectSync?: (inspect: InspectResult) => void;
}

export function AppsTab({
  apps,
  appsBaseDomain,
  deepLink,
  onConsumeDeepLink,
  onRefresh,
  onInspectSync,
}: AppsTabProps) {
  const [showCreate, setShowCreate] = useState(false);
  const [busySlug, setBusySlug] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [sourceType, setSourceType] = useState<"git" | "image">("git");
  const [image, setImage] = useState("nginxinc/nginx-unprivileged:alpine");
  const [gitRepoUrl, setGitRepoUrl] = useState("");
  const [gitBranch, setGitBranch] = useState("");
  const [dockerfilePath, setDockerfilePath] = useState("auto");
  const [internalPort, setInternalPort] = useState("");
  const [domain, setDomain] = useState("");
  const [noDomain, setNoDomain] = useState(false);
  const [withPostgres, setWithPostgres] = useState(false);
  const [withRedis, setWithRedis] = useState(false);
  const [envText, setEnvText] = useState("");
  const [inspectingGit, setInspectingGit] = useState(false);
  const [gitPreview, setGitPreview] = useState<GitInspectResult | null>(null);
  const [creating, setCreating] = useState(false);

  const [trackedDeployment, setTrackedDeployment] =
    useState<DeploymentRecord | null>(null);

  const [selectedSlug, setSelectedSlug] = useState<string | null>(null);
  const [section, setSection] = useState<DrawerSection>("deployments");
  const [deployments, setDeployments] = useState<DeploymentRecord[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const [envVars, setEnvVars] = useState<AppEnvEntry[]>([]);
  const [missingEnvKeys, setMissingEnvKeys] = useState<string[]>([]);
  const [inspectData, setInspectData] = useState<InspectResult | null>(null);
  const [newEnvKey, setNewEnvKey] = useState("");
  const [newEnvVal, setNewEnvVal] = useState("");
  const [editDomain, setEditDomain] = useState("");
  const [drawerLoading, setDrawerLoading] = useState(false);

  const openDrawerBySlug = useCallback(
    async (targetSlug: string, sec: DrawerSection, currentDomain?: string | null) => {
      setSelectedSlug(targetSlug);
      setSection(sec);
      setEditDomain(currentDomain ?? "");
      setDrawerLoading(true);
      setError(null);
      try {
        if (sec === "deployments") {
          const res = await api.listDeployments(targetSlug, 10);
          setDeployments(res.deployments);
        } else if (sec === "logs") {
          const res = await api.getAppLogs(targetSlug, 120);
          setLogs(res.lines);
        } else if (sec === "env") {
          const res = await api.getAppEnv(targetSlug);
          setEnvVars(res.envVars);
          setMissingEnvKeys(res.missingEnvKeys ?? []);
        } else if (sec === "security") {
          const res = await api.inspectApp(targetSlug);
          setInspectData(res.inspect);
          onInspectSync?.(res.inspect);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Could not load details.");
      } finally {
        setDrawerLoading(false);
      }
    },
    [onInspectSync],
  );

  useEffect(() => {
    if (!deepLink) return;
    const match = apps.find((a) => a.slug === deepLink.slug);
    if (deepLink.deploymentId) {
      void api
        .getDeployment(deepLink.deploymentId)
        .then((res) => setTrackedDeployment(res.deployment))
        .catch(() => {});
    }
    if (match) {
      void openDrawerBySlug(match.slug, deepLink.section, match.domain);
    }
    onConsumeDeepLink?.();
  }, [apps, deepLink, onConsumeDeepLink, openDrawerBySlug]);

  useEffect(() => {
    if (!trackedDeployment || !isDeploymentActive(trackedDeployment.status)) {
      return;
    }
    const id = trackedDeployment.id;
    const timer = window.setInterval(() => {
      void api
        .getDeployment(id)
        .then(async (res) => {
          setTrackedDeployment(res.deployment);
          if (selectedSlug === res.deployment.slug && section === "deployments") {
            const list = await api.listDeployments(res.deployment.slug, 10);
            setDeployments(list.deployments);
          }
          if (!isDeploymentActive(res.deployment.status)) {
            await onRefresh();
            if (res.deployment.status === "succeeded") {
              setNotice(
                res.deployment.domain
                  ? `${res.deployment.slug} is live at https://${res.deployment.domain}`
                  : `${res.deployment.slug} finished deploying and is running safely.`,
              );
              if (res.missingEnvKeys.length > 0) {
                setMissingEnvKeys(res.missingEnvKeys);
                void openDrawerBySlug(
                  res.deployment.slug,
                  "env",
                  res.deployment.domain,
                );
              }
            } else {
              setError(
                res.deployment.error ||
                  `Deployment failed for ${res.deployment.slug}.`,
              );
            }
          }
        })
        .catch(() => {});
    }, 1500);
    return () => window.clearInterval(timer);
  }, [onRefresh, openDrawerBySlug, section, selectedSlug, trackedDeployment]);

  const handleInspectGit = async () => {
    if (!gitRepoUrl.trim()) {
      setError("Paste a public HTTPS GitHub link first.");
      return;
    }
    setInspectingGit(true);
    setError(null);
    setNotice(null);
    try {
      const res = await api.inspectGitRepo(
        gitRepoUrl.trim(),
        gitBranch.trim() || null,
        dockerfilePath.trim() || "auto",
      );
      const info = res.inspect;
      setGitPreview(info);
      if (!name.trim()) setName(info.suggestedName);
      if (!slug.trim()) setSlug(info.suggestedSlug);
      if (!gitBranch.trim() && info.resolvedBranch) {
        setGitBranch(info.resolvedBranch);
      }
      setDockerfilePath(info.hasDockerfile ? info.dockerfilePath : "auto");
      setInternalPort(String(info.suggestedPort));
      if (!domain.trim() && info.suggestedDomain && !noDomain) {
        setDomain(info.suggestedDomain);
      }
      setWithPostgres(info.suggestedCompanions.includes("postgres"));
      setWithRedis(info.suggestedCompanions.includes("redis"));
      setNotice(info.buildPlanSummary);
    } catch (err) {
      setGitPreview(null);
      setError(
        err instanceof Error ? err.message : "Could not inspect GitHub repo.",
      );
    } finally {
      setInspectingGit(false);
    }
  };

  const handleAction = async (
    targetSlug: string,
    action: "start" | "stop" | "restart" | "rebuild",
  ) => {
    setBusySlug(targetSlug);
    setError(null);
    setNotice(null);
    try {
      const res = await api.appAction(targetSlug, action, action === "rebuild");
      if (action === "rebuild" && res.deployment) {
        setTrackedDeployment(res.deployment);
        setNotice(`Rebuild started in the background for ${targetSlug}.`);
        await openDrawerBySlug(targetSlug, "deployments");
      } else {
        setNotice(`Completed "${action}" on ${targetSlug}.`);
      }
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to ${action} app.`);
    } finally {
      setBusySlug(null);
    }
  };

  const handleDelete = async (targetSlug: string) => {
    if (!window.confirm(`Delete app "${targetSlug}" and remove its files?`)) {
      return;
    }
    setBusySlug(targetSlug);
    setError(null);
    try {
      await api.deleteApp(targetSlug);
      if (selectedSlug === targetSlug) setSelectedSlug(null);
      setNotice(`Removed app "${targetSlug}".`);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete app.");
    } finally {
      setBusySlug(null);
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setCreating(true);
    try {
      const companions: CompanionService[] = [];
      if (withPostgres) companions.push({ type: "postgres" });
      if (withRedis) companions.push({ type: "redis" });

      const parsedEnv: Record<string, string> = {};
      for (const line of envText.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const idx = trimmed.indexOf("=");
        if (idx > 0) {
          parsedEnv[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim();
        }
      }

      const parsedPort = internalPort.trim()
        ? Number.parseInt(internalPort, 10)
        : undefined;

      const res = await api.deployApp(
        {
          slug: slug.trim().toLowerCase(),
          name: name.trim(),
          sourceType,
          image: sourceType === "image" ? image.trim() : null,
          gitRepoUrl: sourceType === "git" ? gitRepoUrl.trim() : null,
          gitBranch: sourceType === "git" ? gitBranch.trim() || null : null,
          dockerfilePath:
            sourceType === "git"
              ? dockerfilePath.trim() || "auto"
              : "Dockerfile",
          ...(noDomain
            ? { noDomain: true, domain: null }
            : domain.trim()
              ? { domain: domain.trim() }
              : {}),
          ...(parsedPort && Number.isFinite(parsedPort)
            ? { internalPort: parsedPort }
            : {}),
          cpuLimit: "0.5",
          memoryLimitMb: 512,
          companions,
          envVars: parsedEnv,
        },
        true,
      );

      setShowCreate(false);
      setGitPreview(null);
      setSlug("");
      setName("");
      setGitRepoUrl("");
      setGitBranch("");
      setDockerfilePath("auto");
      setInternalPort("");
      setDomain("");
      setNoDomain(false);
      setWithPostgres(false);
      setWithRedis(false);
      setEnvText("");

      if (res.deployment) {
        setTrackedDeployment(res.deployment);
        setNotice(
          `Deployment started for ${res.deployment.slug}. Watching build progress live.`,
        );
      } else {
        setNotice("App launched safely inside its Locked Apartment.");
      }
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not launch app.");
    } finally {
      setCreating(false);
    }
  };

  const handleSaveEnv = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedSlug || !newEnvKey.trim()) return;
    setDrawerLoading(true);
    setError(null);
    try {
      const res = await api.updateAppEnv(selectedSlug, [
        { key: newEnvKey.trim(), value: newEnvVal },
      ]);
      setEnvVars(res.envVars);
      setMissingEnvKeys(res.missingEnvKeys ?? []);
      setNewEnvKey("");
      setNewEnvVal("");
      setNotice(`Saved hidden setting ${newEnvKey.trim()}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save setting.");
    } finally {
      setDrawerLoading(false);
    }
  };

  const handleDeleteEnv = async (key: string) => {
    if (!selectedSlug) return;
    setDrawerLoading(true);
    try {
      const res = await api.deleteAppEnv(selectedSlug, key);
      setEnvVars(res.envVars);
      setMissingEnvKeys(res.missingEnvKeys ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete setting.");
    } finally {
      setDrawerLoading(false);
    }
  };

  const handleSaveDomain = async (remove: boolean) => {
    if (!selectedSlug) return;
    setDrawerLoading(true);
    setError(null);
    try {
      await api.setAppDomain(
        selectedSlug,
        remove ? null : editDomain.trim() || null,
      );
      if (remove) setEditDomain("");
      setNotice(
        remove
          ? `Disconnected domain from ${selectedSlug}.`
          : `Connected ${editDomain.trim()} with automatic HTTPS.`,
      );
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update domain.");
    } finally {
      setDrawerLoading(false);
    }
  };

  return (
    <div className="space-y-6 panel-enter">
      {/* Page Header */}
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-[-0.025em] text-white">
            Apps
          </h1>
          <p className="mt-1 text-sm text-[#9CA3AF]">
            Deploy public GitHub repos (auto-detected or Dockerfile) or Docker
            images inside isolated Locked Apartments.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowCreate((v) => !v)}
          className="btn-press inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-4 py-2 text-[13px] font-semibold text-[#042F1E] hover:bg-emerald-400 cursor-pointer"
        >
          <Plus className="h-4 w-4" />
          {showCreate ? "Close form" : "Launch new app"}
        </button>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/35 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      )}
      {notice && (
        <div className="rounded-xl border border-emerald-500/35 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
          {notice}
        </div>
      )}

      {/* Live Background Deployment Tracker */}
      {trackedDeployment && (
        <div className="surface-panel panel-enter rounded-xl border-l-4 border-l-emerald-400 p-5 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2.5 text-xs">
              {isDeploymentActive(trackedDeployment.status) ? (
                <Loader2 className="h-4 w-4 animate-spin text-amber-300" />
              ) : (
                <Rocket className="h-4 w-4 text-emerald-400" />
              )}
              <span className="text-sm font-semibold text-white">
                Deployment for{" "}
                <code className="text-emerald-300">
                  {trackedDeployment.slug}
                </code>
              </span>
              <span
                className={`font-semibold capitalize ${deploymentToneClass(trackedDeployment.status)}`}
              >
                {trackedDeployment.status}
              </span>
              {trackedDeployment.detectedRuntime && (
                <span className="font-mono text-[#9CA3AF]">
                  &middot; {trackedDeployment.detectedRuntime}
                  {trackedDeployment.usedAutoDockerfile ? " (auto)" : ""}
                </span>
              )}
              {trackedDeployment.commitSha && (
                <span className="inline-flex items-center gap-1 font-mono text-[#9CA3AF]">
                  <GitBranch className="h-3 w-3" />
                  {trackedDeployment.commitSha.slice(0, 7)}
                </span>
              )}
            </div>
            {!isDeploymentActive(trackedDeployment.status) && (
              <button
                type="button"
                onClick={() => setTrackedDeployment(null)}
                className="btn-press text-xs text-[#9CA3AF] hover:text-white cursor-pointer"
              >
                Dismiss
              </button>
            )}
          </div>
          {trackedDeployment.phaseDetail && (
            <p className="text-xs text-[#D1D5DB]">
              {trackedDeployment.phaseDetail}
            </p>
          )}
          {trackedDeployment.error && (
            <p className="text-xs text-rose-300">{trackedDeployment.error}</p>
          )}
          {trackedDeployment.buildLogs.length > 0 && (
            <pre className="surface-well max-h-48 overflow-auto rounded-lg p-3 text-xs font-mono text-[#D1D5DB] whitespace-pre-wrap">
              {trackedDeployment.buildLogs.join("\n")}
            </pre>
          )}
        </div>
      )}

      {/* Launch New App Form */}
      {showCreate && (
        <form
          onSubmit={handleCreate}
          className="surface-panel panel-enter rounded-xl p-6 space-y-5"
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-sm font-semibold text-white">
              Launch a new Locked-Apartment app
            </h2>
            <div
              role="tablist"
              aria-label="App source type"
              className="inline-flex rounded-lg border border-white/[0.08] bg-[#0C0E12] p-1 gap-0.5"
            >
              <button
                role="tab"
                aria-selected={sourceType === "git"}
                type="button"
                onClick={() => setSourceType("git")}
                className={`btn-press rounded-md px-3 py-1.5 text-xs font-medium cursor-pointer ${
                  sourceType === "git"
                    ? "bg-white/[0.1] text-white"
                    : "text-[#9CA3AF] hover:text-white"
                }`}
              >
                GitHub repository
              </button>
              <button
                role="tab"
                aria-selected={sourceType === "image"}
                type="button"
                onClick={() => setSourceType("image")}
                className={`btn-press rounded-md px-3 py-1.5 text-xs font-medium cursor-pointer ${
                  sourceType === "image"
                    ? "bg-white/[0.1] text-white"
                    : "text-[#9CA3AF] hover:text-white"
                }`}
              >
                Docker image
              </button>
            </div>
          </div>

          {sourceType === "git" ? (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-2.5 items-end">
                <div className="flex-1 min-w-[260px]">
                  <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
                    Public HTTPS GitHub repo URL
                  </label>
                  <input
                    type="url"
                    value={gitRepoUrl}
                    onChange={(e) => setGitRepoUrl(e.target.value)}
                    placeholder="https://github.com/owner/repo"
                    required
                    className="field-input w-full rounded-lg px-3.5 py-2 text-sm font-mono"
                  />
                </div>
                <button
                  type="button"
                  disabled={inspectingGit || !gitRepoUrl.trim()}
                  onClick={handleInspectGit}
                  className="btn-press inline-flex items-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-500/12 px-3.5 py-2 text-xs font-semibold text-sky-200 hover:bg-sky-500/20 disabled:opacity-50 cursor-pointer"
                >
                  {inspectingGit ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Search className="h-3.5 w-3.5" />
                  )}
                  {inspectingGit ? "Inspecting..." : "Inspect & auto-fill"}
                </button>
              </div>

              {gitPreview && (
                <div className="rounded-lg border border-sky-500/30 bg-sky-500/[0.08] p-3.5 space-y-1.5 text-xs">
                  <div className="flex flex-wrap items-center gap-2 text-sky-200 font-medium">
                    <Sparkles className="h-3.5 w-3.5" />
                    <span>{gitPreview.buildPlanSummary}</span>
                  </div>
                  {gitPreview.envExampleKeys.length > 0 && (
                    <p className="text-[#D1D5DB]">
                      Detected settings from <code>.env.example</code>:{" "}
                      <span className="font-mono text-amber-200">
                        {gitPreview.envExampleKeys.map((k) => k.key).join(", ")}
                      </span>{" "}
                      (fill them below or safely later in Hidden Settings).
                    </p>
                  )}
                  {gitPreview.notes.map((n, i) => (
                    <p key={i} className="text-[#9CA3AF]">
                      {n}
                    </p>
                  ))}
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
                    Branch (optional, defaults to repo default)
                  </label>
                  <input
                    type="text"
                    value={gitBranch}
                    onChange={(e) => setGitBranch(e.target.value)}
                    placeholder="main"
                    className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
                    Dockerfile path (leave &ldquo;auto&rdquo; to auto-detect)
                  </label>
                  <input
                    type="text"
                    value={dockerfilePath}
                    onChange={(e) => setDockerfilePath(e.target.value)}
                    placeholder="auto"
                    className="field-input w-full rounded-lg px-3.5 py-2 text-sm font-mono"
                  />
                </div>
              </div>
            </div>
          ) : (
            <div>
              <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
                Docker image
              </label>
              <input
                type="text"
                value={image}
                onChange={(e) => setImage(e.target.value)}
                placeholder="nginxinc/nginx-unprivileged:alpine"
                required
                className="field-input w-full rounded-lg px-3.5 py-2 text-sm font-mono"
              />
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
                Display name
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="My Blog"
                required
                className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
                Short ID (lowercase letters &amp; hyphens)
              </label>
              <input
                type="text"
                value={slug}
                onChange={(e) => setSlug(e.target.value)}
                placeholder="my-blog"
                required
                className="field-input w-full rounded-lg px-3.5 py-2 text-sm font-mono"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
                App internal port{" "}
                {sourceType === "git" && (
                  <span className="text-[#6B7280]">
                    (optional, auto-detected)
                  </span>
                )}
              </label>
              <input
                type="number"
                value={internalPort}
                onChange={(e) => setInternalPort(e.target.value)}
                placeholder={sourceType === "git" ? "Auto-detect" : "8080"}
                min={1}
                max={65535}
                required={sourceType === "image"}
                className="field-input w-full rounded-lg px-3.5 py-2 text-sm tabular-nums"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
                Public domain{" "}
                {appsBaseDomain && !noDomain && (
                  <span className="text-emerald-400">
                    (auto: {slug || "your-app"}.{appsBaseDomain})
                  </span>
                )}
              </label>
              <input
                type="text"
                value={domain}
                disabled={noDomain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder={
                  appsBaseDomain
                    ? `${slug || "my-app"}.${appsBaseDomain}`
                    : "app.yourdomain.com"
                }
                className="field-input w-full rounded-lg px-3.5 py-2 text-sm disabled:opacity-45"
              />
              {appsBaseDomain && (
                <label className="mt-2 inline-flex items-center gap-2 text-xs text-[#9CA3AF] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={noDomain}
                    onChange={(e) => setNoDomain(e.target.checked)}
                    className="rounded border-white/20 bg-[#090A0C] accent-emerald-500"
                  />
                  Keep private (skip automatic subdomain)
                </label>
              )}
            </div>
          </div>

          <div className="flex flex-wrap gap-6 pt-1">
            <label className="inline-flex items-center gap-2 text-sm text-[#D1D5DB] cursor-pointer">
              <input
                type="checkbox"
                checked={withPostgres}
                onChange={(e) => setWithPostgres(e.target.checked)}
                className="rounded border-white/20 bg-[#090A0C] accent-emerald-500"
              />
              Attach private Postgres database
            </label>
            <label className="inline-flex items-center gap-2 text-sm text-[#D1D5DB] cursor-pointer">
              <input
                type="checkbox"
                checked={withRedis}
                onChange={(e) => setWithRedis(e.target.checked)}
                className="rounded border-white/20 bg-[#090A0C] accent-emerald-500"
              />
              Attach private Redis cache
            </label>
          </div>

          <div>
            <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
              Hidden settings / secrets (optional, one KEY=VALUE per line)
            </label>
            <textarea
              rows={3}
              value={envText}
              onChange={(e) => setEnvText(e.target.value)}
              placeholder={"NODE_ENV=production\nAPI_SECRET=my-secret-value"}
              className="field-input w-full rounded-lg px-3.5 py-2 text-sm font-mono"
            />
          </div>

          <div className="flex justify-end gap-2.5 pt-1">
            <button
              type="button"
              onClick={() => setShowCreate(false)}
              className="btn-press rounded-lg border border-white/[0.1] bg-[#111317] px-4 py-2 text-[13px] font-medium text-[#9CA3AF] hover:text-white cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={creating}
              className="btn-press rounded-lg bg-emerald-500 px-4 py-2 text-[13px] font-semibold text-[#042F1E] hover:bg-emerald-400 disabled:opacity-50 cursor-pointer"
            >
              {creating ? "Starting..." : "Launch app"}
            </button>
          </div>
        </form>
      )}

      {/* Apps List */}
      {apps.length === 0 ? (
        <div className="surface-panel rounded-xl p-10 text-center space-y-3">
          <p className="text-sm font-medium text-[#F4F5F7]">
            No apps running yet
          </p>
          <p className="text-xs text-[#9CA3AF] max-w-md mx-auto">
            Launch a public GitHub repo or Docker image directly, or create a
            visitor pass in AI Keys &amp; Settings so your AI agent can deploy
            for you.
          </p>
          <button
            type="button"
            onClick={() => setShowCreate(true)}
            className="btn-press inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-4 py-2 text-xs font-semibold text-[#042F1E] hover:bg-emerald-400 cursor-pointer"
          >
            <Plus className="h-3.5 w-3.5" />
            Launch your first app
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {apps.map((app) => {
            const isBusy = busySlug === app.slug;
            const isOpen = selectedSlug === app.slug;
            return (
              <article
                key={app.slug}
                className="surface-panel rounded-xl overflow-hidden"
              >
                {/* App Primary Row */}
                <div className="p-5 flex flex-wrap items-start justify-between gap-4">
                  <div className="space-y-1.5 min-w-0">
                    <div className="flex flex-wrap items-center gap-3">
                      <h2 className="text-base font-semibold tracking-[-0.015em] text-white">
                        {app.name}
                      </h2>
                      <span
                        className={`inline-flex items-center gap-1.5 text-xs font-medium capitalize ${appStatusText(app.status)}`}
                      >
                        <span
                          className={`h-1.5 w-1.5 rounded-full ${appStatusDot(app.status)}`}
                        />
                        {app.status}
                      </span>
                      {app.domain && (
                        <a
                          href={`https://${app.domain}`}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 text-xs text-emerald-400 hover:text-emerald-300"
                        >
                          <span>{app.domain}</span>
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      )}
                    </div>

                    {/* Clean Typographic Metadata Line (no pill soup) */}
                    <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-[#9CA3AF] tabular-nums">
                      <span className="font-mono text-[#D1D5DB]">
                        {app.slug}
                      </span>
                      <span className="text-[#4B5563]">&middot;</span>
                      <span>Port {app.internalPort}</span>
                      <span className="text-[#4B5563]">&middot;</span>
                      <span>
                        {app.cpuLimit} CPU / {app.memoryLimitMb} MB
                      </span>
                      {app.detectedRuntime && (
                        <>
                          <span className="text-[#4B5563]">&middot;</span>
                          <span className="font-mono">
                            {app.detectedRuntime}
                          </span>
                        </>
                      )}
                      {app.lastCommitSha && (
                        <>
                          <span className="text-[#4B5563]">&middot;</span>
                          <span className="inline-flex items-center gap-1 font-mono text-[#9CA3AF]">
                            <GitBranch className="h-3 w-3 text-[#6B7280]" />
                            {app.lastCommitSha.slice(0, 7)}
                          </span>
                        </>
                      )}
                      {app.companions.length > 0 && (
                        <>
                          <span className="text-[#4B5563]">&middot;</span>
                          <span className="inline-flex items-center gap-1 text-sky-300">
                            <Database className="h-3 w-3" />
                            {app.companions.map((c) => c.type).join(" + ")}
                          </span>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Grouped Lifecycle Control Bar */}
                  <div className="inline-flex items-center rounded-lg border border-white/[0.08] bg-[#0C0E12] divide-x divide-white/[0.08] overflow-hidden shrink-0">
                    {app.status === "running" ? (
                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => handleAction(app.slug, "stop")}
                        className="btn-press inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[#D1D5DB] hover:bg-white/[0.06] hover:text-white disabled:opacity-45 cursor-pointer"
                      >
                        <Square className="h-3 w-3" />
                        Stop
                      </button>
                    ) : (
                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => handleAction(app.slug, "start")}
                        className="btn-press inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-emerald-300 hover:bg-emerald-500/15 disabled:opacity-45 cursor-pointer"
                      >
                        <Play className="h-3 w-3" />
                        Start
                      </button>
                    )}
                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => handleAction(app.slug, "restart")}
                      className="btn-press inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[#D1D5DB] hover:bg-white/[0.06] hover:text-white disabled:opacity-45 cursor-pointer"
                    >
                      <RotateCw className="h-3 w-3" />
                      Restart
                    </button>
                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => handleAction(app.slug, "rebuild")}
                      className="btn-press inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[#D1D5DB] hover:bg-white/[0.06] hover:text-white disabled:opacity-45 cursor-pointer"
                    >
                      <Hammer className="h-3 w-3" />
                      Rebuild
                    </button>
                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => handleDelete(app.slug)}
                      className="btn-press inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-rose-300 hover:bg-rose-500/15 disabled:opacity-45 cursor-pointer"
                    >
                      <Trash2 className="h-3 w-3" />
                      Delete
                    </button>
                  </div>
                </div>

                {/* Inspector Tab Strip */}
                <div className="border-t border-white/[0.06] bg-[#0C0E12]/70 px-4 py-1.5 flex flex-wrap gap-1">
                  {(
                    [
                      ["deployments", "Deployments", Rocket],
                      ["logs", "Logs", Terminal],
                      ["domain", "Domain", Globe],
                      ["env", "Hidden settings (.env)", KeyRound],
                      ["security", "Safety check", ShieldCheck],
                    ] as const
                  ).map(([key, label, Icon]) => {
                    const active = isOpen && section === key;
                    return (
                      <button
                        key={key}
                        type="button"
                        onClick={() =>
                          active
                            ? setSelectedSlug(null)
                            : void openDrawerBySlug(app.slug, key, app.domain)
                        }
                        className={`btn-press inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium cursor-pointer ${
                          active
                            ? "bg-white/[0.09] text-white"
                            : "text-[#9CA3AF] hover:text-[#F4F5F7] hover:bg-white/[0.04]"
                        }`}
                      >
                        <Icon
                          className={`h-3.5 w-3.5 ${active ? "text-emerald-400" : "text-[#6B7280]"}`}
                        />
                        {label}
                      </button>
                    );
                  })}
                </div>

                {/* Expanded Inspector Drawer */}
                {isOpen && (
                  <div className="panel-enter border-t border-white/[0.08] bg-[#0C0E12] p-5">
                    {drawerLoading ? (
                      <div className="space-y-2.5" aria-busy="true">
                        <div className="h-4 w-48 rounded skeleton-bar" />
                        <div className="h-16 w-full rounded-lg skeleton-bar" />
                      </div>
                    ) : section === "deployments" ? (
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="text-xs text-[#9CA3AF]">
                            Recent builds &amp; deployments (secrets are
                            automatically scrubbed)
                          </span>
                          <button
                            type="button"
                            onClick={() =>
                              void openDrawerBySlug(
                                app.slug,
                                "deployments",
                                app.domain,
                              )
                            }
                            className="btn-press text-xs font-medium text-emerald-400 hover:text-emerald-300 cursor-pointer"
                          >
                            Refresh
                          </button>
                        </div>
                        {deployments.length === 0 ? (
                          <p className="text-xs text-[#6B7280]">
                            No tracked deployments yet.
                          </p>
                        ) : (
                          <div className="divide-y divide-white/[0.06] border-t border-white/[0.06]">
                            {deployments.map((dep) => (
                              <div key={dep.id} className="py-3.5 space-y-2">
                                <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <span
                                      className={`font-semibold capitalize ${deploymentToneClass(dep.status)}`}
                                    >
                                      {dep.status}
                                    </span>
                                    <span className="font-mono text-[#D1D5DB]">
                                      {dep.action}
                                    </span>
                                    {dep.detectedRuntime && (
                                      <span className="text-[#9CA3AF]">
                                        {dep.detectedRuntime}
                                        {dep.usedAutoDockerfile ? " (auto)" : ""}
                                      </span>
                                    )}
                                    {dep.commitSha && (
                                      <span className="font-mono text-[#6B7280]">
                                        @{dep.commitSha.slice(0, 7)}
                                      </span>
                                    )}
                                  </div>
                                  <span className="text-[#6B7280] tabular-nums">
                                    {new Date(dep.createdAt).toLocaleString()}
                                  </span>
                                </div>
                                {dep.phaseDetail && (
                                  <p className="text-xs text-[#9CA3AF]">
                                    {dep.phaseDetail}
                                  </p>
                                )}
                                {dep.error && (
                                  <p className="text-xs text-rose-300">
                                    {dep.error}
                                  </p>
                                )}
                                {dep.buildLogs.length > 0 && (
                                  <pre className="max-h-40 overflow-auto rounded-lg border border-white/[0.08] bg-[#090A0C] p-3 text-[11px] font-mono text-[#D1D5DB] whitespace-pre-wrap">
                                    {dep.buildLogs.join("\n")}
                                  </pre>
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ) : section === "logs" ? (
                      <div className="space-y-2.5">
                        <div className="flex items-center justify-between">
                          <span className="text-xs text-[#9CA3AF]">
                            Recent container logs (passwords &amp; tokens
                            automatically scrubbed)
                          </span>
                          <button
                            type="button"
                            onClick={() =>
                              void openDrawerBySlug(app.slug, "logs", app.domain)
                            }
                            className="btn-press text-xs font-medium text-emerald-400 hover:text-emerald-300 cursor-pointer"
                          >
                            Refresh logs
                          </button>
                        </div>
                        <pre className="max-h-64 overflow-auto rounded-lg border border-white/[0.08] bg-[#090A0C] p-3.5 text-xs font-mono text-[#D1D5DB] whitespace-pre-wrap leading-relaxed">
                          {logs.length > 0 ? logs.join("\n") : "No logs yet."}
                        </pre>
                      </div>
                    ) : section === "domain" ? (
                      <div className="flex flex-wrap items-end gap-3">
                        <div className="flex-1 min-w-[220px]">
                          <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
                            Public web address (automatic HTTPS)
                          </label>
                          <input
                            type="text"
                            value={editDomain}
                            onChange={(e) => setEditDomain(e.target.value)}
                            placeholder="app.yourdomain.com"
                            className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
                          />
                        </div>
                        <button
                          type="button"
                          onClick={() => handleSaveDomain(false)}
                          className="btn-press rounded-lg bg-emerald-500 px-4 py-2 text-xs font-semibold text-[#042F1E] hover:bg-emerald-400 cursor-pointer"
                        >
                          Connect domain
                        </button>
                        {app.domain && (
                          <button
                            type="button"
                            onClick={() => handleSaveDomain(true)}
                            className="btn-press rounded-lg border border-white/[0.1] bg-[#111317] px-3.5 py-2 text-xs font-medium text-[#9CA3AF] hover:text-white cursor-pointer"
                          >
                            Disconnect
                          </button>
                        )}
                      </div>
                    ) : section === "env" ? (
                      <div className="space-y-4">
                        {missingEnvKeys.length > 0 && (
                          <div className="rounded-lg border border-amber-500/35 bg-amber-500/[0.08] p-3.5 space-y-2">
                            <p className="text-xs font-medium text-amber-200">
                              Suggested settings from this repo&rsquo;s{" "}
                              <code>.env.example</code> (click one to fill it
                              safely here):
                            </p>
                            <div className="flex flex-wrap gap-1.5">
                              {missingEnvKeys.map((key) => (
                                <button
                                  key={key}
                                  type="button"
                                  onClick={() => setNewEnvKey(key)}
                                  className="btn-press rounded-md border border-amber-500/40 bg-[#090A0C] px-2.5 py-1 text-xs font-mono text-amber-200 hover:bg-amber-500/20 cursor-pointer"
                                >
                                  + {key}
                                </button>
                              ))}
                            </div>
                          </div>
                        )}
                        <form
                          onSubmit={handleSaveEnv}
                          className="flex flex-wrap gap-2"
                        >
                          <input
                            type="text"
                            value={newEnvKey}
                            onChange={(e) => setNewEnvKey(e.target.value)}
                            placeholder="SETTING_NAME"
                            required
                            className="field-input rounded-lg px-3 py-2 text-xs font-mono"
                          />
                          <input
                            type="password"
                            value={newEnvVal}
                            onChange={(e) => setNewEnvVal(e.target.value)}
                            placeholder="Value (encrypted at rest)"
                            required
                            className="field-input flex-1 min-w-[200px] rounded-lg px-3 py-2 text-xs font-mono"
                          />
                          <button
                            type="submit"
                            className="btn-press rounded-lg bg-emerald-500 px-4 py-2 text-xs font-semibold text-[#042F1E] hover:bg-emerald-400 cursor-pointer"
                          >
                            Save setting
                          </button>
                        </form>
                        <div className="divide-y divide-white/[0.06] rounded-lg border border-white/[0.08] bg-[#090A0C]">
                          {envVars.length === 0 ? (
                            <p className="p-3.5 text-xs text-[#6B7280]">
                              No saved settings yet.
                            </p>
                          ) : (
                            envVars.map((entry) => (
                              <div
                                key={entry.key}
                                className="flex items-center justify-between px-3.5 py-2.5 text-xs"
                              >
                                <div className="min-w-0 truncate">
                                  <span className="font-mono text-[#F4F5F7]">
                                    {entry.key}
                                  </span>
                                  <span className="ml-3 font-mono text-[#6B7280]">
                                    {entry.maskedValue}
                                  </span>
                                </div>
                                <button
                                  type="button"
                                  onClick={() => handleDeleteEnv(entry.key)}
                                  className="btn-press text-rose-400 hover:text-rose-300 cursor-pointer shrink-0 ml-3"
                                >
                                  Remove
                                </button>
                              </div>
                            ))
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-3 text-xs">
                        {inspectData ? (
                          <div className="space-y-3">
                            <div className="flex flex-wrap items-center gap-4">
                              <span
                                className={`inline-flex items-center gap-1.5 font-semibold ${
                                  inspectData.lockedApartmentCompliant
                                    ? "text-emerald-300"
                                    : "text-rose-300"
                                }`}
                              >
                                <span
                                  className={`h-2 w-2 rounded-full ${
                                    inspectData.lockedApartmentCompliant
                                      ? "bg-emerald-400"
                                      : "bg-rose-400"
                                  }`}
                                />
                                {inspectData.lockedApartmentCompliant
                                  ? "Locked Apartment verified"
                                  : "Safety warning: check config"}
                              </span>
                              <span className="text-[#9CA3AF] tabular-nums">
                                Containers: {inspectData.containers.length}{" "}
                                &middot; Overall status:{" "}
                                <span
                                  className={
                                    inspectData.status === "running"
                                      ? "text-emerald-300 font-semibold"
                                      : inspectData.status === "error"
                                        ? "text-rose-300 font-semibold"
                                        : "text-[#F4F5F7] font-semibold"
                                  }
                                >
                                  {inspectData.status}
                                </span>
                              </span>
                            </div>
                            {(() => {
                              const health =
                                formatSafetyCheckHealth(inspectData);
                              return (
                                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
                                  <div className="rounded-lg border border-white/[0.06] bg-[#090A0C] px-3.5 py-2.5">
                                    <p className="text-[11px] text-[#6B7280]">
                                      Docker liveness
                                    </p>
                                    <p
                                      className={`mt-0.5 font-mono font-medium ${healthToneClass(health.dockerLiveness.tone)}`}
                                    >
                                      {health.dockerLiveness.label}
                                    </p>
                                  </div>
                                  <div className="rounded-lg border border-white/[0.06] bg-[#090A0C] px-3.5 py-2.5">
                                    <p className="text-[11px] text-[#6B7280]">
                                      Monitored HTTP health
                                    </p>
                                    <p
                                      className={`mt-0.5 font-mono font-medium ${healthToneClass(health.monitoredHttp.tone)}`}
                                    >
                                      {health.monitoredHttp.label}
                                    </p>
                                  </div>
                                  <div className="rounded-lg border border-white/[0.06] bg-[#090A0C] px-3.5 py-2.5">
                                    <p className="text-[11px] text-[#6B7280]">
                                      Live HTTP probe
                                    </p>
                                    <p
                                      className={`mt-0.5 font-mono font-medium ${healthToneClass(health.liveHttpProbe.tone)}`}
                                    >
                                      {health.liveHttpProbe.label}
                                    </p>
                                  </div>
                                </div>
                              );
                            })()}
                          </div>
                        ) : (
                          <p className="text-[#9CA3AF]">
                            No container inspection data available.
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}
