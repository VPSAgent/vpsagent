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
  return "text-slate-200";
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

function deploymentBadgeClass(status: DeploymentRecord["status"]): string {
  if (status === "succeeded") return "bg-emerald-500/15 text-emerald-300";
  if (status === "failed") return "bg-rose-500/15 text-rose-300";
  return "bg-amber-500/15 text-amber-300";
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

  // Create form state (GitHub first!)
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

  // Active background deployment tracker banner
  const [trackedDeployment, setTrackedDeployment] =
    useState<DeploymentRecord | null>(null);

  // Expanded app inspector drawer
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

  // Handle deep links like /#apps/<slug>/env (from AI secret handoff!) or approved deployments
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

  // Poll any active background deployment every 1.5s until it finishes
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
          `Deployment started for ${res.deployment.slug} — watching build progress live.`,
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
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold text-white">Apps</h2>
          <p className="text-sm text-slate-400">
            Deploy public GitHub repos (even without a Dockerfile) or Docker
            images inside isolated Locked Apartments.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowCreate((v) => !v)}
          className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400 transition cursor-pointer"
        >
          <Plus className="h-4 w-4" />
          {showCreate ? "Close Form" : "Launch New App"}
        </button>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">
          {error}
        </div>
      )}
      {notice && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300">
          {notice}
        </div>
      )}

      {/* Live Background Deployment Tracker */}
      {trackedDeployment && (
        <div className="rounded-2xl border border-slate-700 bg-slate-900/90 p-5 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2.5">
              {isDeploymentActive(trackedDeployment.status) ? (
                <Loader2 className="h-4 w-4 animate-spin text-amber-300" />
              ) : (
                <Rocket className="h-4 w-4 text-emerald-400" />
              )}
              <span className="text-sm font-semibold text-white">
                Deployment for{" "}
                <code className="text-emerald-300">{trackedDeployment.slug}</code>
              </span>
              <span
                className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${deploymentBadgeClass(trackedDeployment.status)}`}
              >
                {trackedDeployment.status}
              </span>
              {trackedDeployment.detectedRuntime && (
                <span className="rounded-full bg-slate-800 px-2.5 py-0.5 text-xs text-slate-300">
                  {trackedDeployment.detectedRuntime}
                  {trackedDeployment.usedAutoDockerfile ? " (auto)" : ""}
                </span>
              )}
              {trackedDeployment.commitSha && (
                <span className="inline-flex items-center gap-1 text-xs font-mono text-slate-400">
                  <GitBranch className="h-3 w-3" />
                  {trackedDeployment.commitSha.slice(0, 7)}
                </span>
              )}
            </div>
            {!isDeploymentActive(trackedDeployment.status) && (
              <button
                type="button"
                onClick={() => setTrackedDeployment(null)}
                className="text-xs text-slate-400 hover:text-white cursor-pointer"
              >
                Dismiss
              </button>
            )}
          </div>
          {trackedDeployment.phaseDetail && (
            <p className="text-xs text-slate-300">
              {trackedDeployment.phaseDetail}
            </p>
          )}
          {trackedDeployment.error && (
            <p className="text-xs text-rose-300">{trackedDeployment.error}</p>
          )}
          {trackedDeployment.buildLogs.length > 0 && (
            <pre className="max-h-48 overflow-auto rounded-xl border border-slate-800 bg-black/60 p-3 text-xs font-mono text-slate-300 whitespace-pre-wrap">
              {trackedDeployment.buildLogs.join("\n")}
            </pre>
          )}
        </div>
      )}

      {showCreate && (
        <form
          onSubmit={handleCreate}
          className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6 space-y-4"
        >
          <h3 className="text-base font-semibold text-white">
            Launch a New Locked-Apartment App
          </h3>

          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => setSourceType("git")}
              className={`rounded-lg px-3.5 py-2 text-xs font-semibold border transition cursor-pointer ${
                sourceType === "git"
                  ? "border-emerald-500 bg-emerald-500/15 text-emerald-300"
                  : "border-slate-700 bg-slate-950 text-slate-400"
              }`}
            >
              Deploy from GitHub (Auto-Detect or Dockerfile)
            </button>
            <button
              type="button"
              onClick={() => setSourceType("image")}
              className={`rounded-lg px-3.5 py-2 text-xs font-semibold border transition cursor-pointer ${
                sourceType === "image"
                  ? "border-emerald-500 bg-emerald-500/15 text-emerald-300"
                  : "border-slate-700 bg-slate-950 text-slate-400"
              }`}
            >
              Ready-Made Package (Docker Image)
            </button>
          </div>

          {sourceType === "git" ? (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2 items-end">
                <div className="flex-1 min-w-[260px]">
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Public HTTPS GitHub Repo URL
                  </label>
                  <input
                    type="url"
                    value={gitRepoUrl}
                    onChange={(e) => setGitRepoUrl(e.target.value)}
                    placeholder="https://github.com/owner/repo"
                    required
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono text-white"
                  />
                </div>
                <button
                  type="button"
                  disabled={inspectingGit || !gitRepoUrl.trim()}
                  onClick={handleInspectGit}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-500/15 px-3.5 py-2 text-xs font-semibold text-sky-200 hover:bg-sky-500/25 disabled:opacity-50 cursor-pointer"
                >
                  {inspectingGit ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Search className="h-3.5 w-3.5" />
                  )}
                  {inspectingGit ? "Inspecting..." : "Inspect & Auto-Fill"}
                </button>
              </div>

              {gitPreview && (
                <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 p-3.5 space-y-1.5 text-xs">
                  <div className="flex flex-wrap items-center gap-2 text-sky-200 font-medium">
                    <Sparkles className="h-3.5 w-3.5" />
                    <span>{gitPreview.buildPlanSummary}</span>
                  </div>
                  {gitPreview.envExampleKeys.length > 0 && (
                    <p className="text-slate-300">
                      Detected settings from <code>.env.example</code>:{" "}
                      <span className="font-mono text-amber-200">
                        {gitPreview.envExampleKeys.map((k) => k.key).join(", ")}
                      </span>{" "}
                      (you can fill them below or safely later in Hidden Settings).
                    </p>
                  )}
                  {gitPreview.notes.map((n, i) => (
                    <p key={i} className="text-slate-400">
                      {n}
                    </p>
                  ))}
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Branch (Optional — defaults to repo default)
                  </label>
                  <input
                    type="text"
                    value={gitBranch}
                    onChange={(e) => setGitBranch(e.target.value)}
                    placeholder="main"
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Dockerfile Path (leave &ldquo;auto&rdquo; to auto-detect)
                  </label>
                  <input
                    type="text"
                    value={dockerfilePath}
                    onChange={(e) => setDockerfilePath(e.target.value)}
                    placeholder="auto"
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono text-white"
                  />
                </div>
              </div>
            </div>
          ) : (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Docker Image
              </label>
              <input
                type="text"
                value={image}
                onChange={(e) => setImage(e.target.value)}
                placeholder="nginxinc/nginx-unprivileged:alpine"
                required
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono text-white"
              />
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Display Name
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="My Blog"
                required
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Short ID (lowercase letters &amp; hyphens)
              </label>
              <input
                type="text"
                value={slug}
                onChange={(e) => setSlug(e.target.value)}
                placeholder="my-blog"
                required
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono text-white"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                App Internal Port{" "}
                {sourceType === "git" && (
                  <span className="text-slate-500">
                    (Optional — auto-detected)
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
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Public Domain{" "}
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
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white disabled:opacity-50"
              />
              {appsBaseDomain && (
                <label className="mt-1.5 inline-flex items-center gap-2 text-xs text-slate-400 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={noDomain}
                    onChange={(e) => setNoDomain(e.target.checked)}
                    className="rounded border-slate-600 bg-slate-950"
                  />
                  Keep private (don&rsquo;t assign an automatic subdomain)
                </label>
              )}
            </div>
          </div>

          <div className="flex flex-wrap gap-6 pt-1">
            <label className="inline-flex items-center gap-2 text-sm text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={withPostgres}
                onChange={(e) => setWithPostgres(e.target.checked)}
                className="rounded border-slate-600 bg-slate-950"
              />
              Attach Private Postgres Database
            </label>
            <label className="inline-flex items-center gap-2 text-sm text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={withRedis}
                onChange={(e) => setWithRedis(e.target.checked)}
                className="rounded border-slate-600 bg-slate-950"
              />
              Attach Private Redis Cache
            </label>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Hidden Settings / Secrets (Optional, one KEY=VALUE per line)
            </label>
            <textarea
              rows={3}
              value={envText}
              onChange={(e) => setEnvText(e.target.value)}
              placeholder={"NODE_ENV=production\nAPI_SECRET=my-secret-value"}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono text-white"
            />
          </div>

          <div className="flex justify-end gap-3">
            <button
              type="button"
              onClick={() => setShowCreate(false)}
              className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800 cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={creating}
              className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50 cursor-pointer"
            >
              {creating ? "Starting..." : "Launch App"}
            </button>
          </div>
        </form>
      )}

      {apps.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-slate-800 bg-slate-900/40 p-10 text-center">
          <p className="text-slate-300 font-medium">No apps running yet</p>
          <p className="text-sm text-slate-500 mt-1">
            Click &ldquo;Launch New App&rdquo; above or give your AI a visitor
            pass in Tab 4.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {apps.map((app) => {
            const isBusy = busySlug === app.slug;
            const isOpen = selectedSlug === app.slug;
            return (
              <div
                key={app.slug}
                className="rounded-2xl border border-slate-800 bg-slate-900/70 overflow-hidden"
              >
                <div className="p-5 flex flex-wrap items-center justify-between gap-4">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2.5">
                      <h3 className="text-base font-semibold text-white">
                        {app.name}
                      </h3>
                      <span
                        className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                          app.status === "running"
                            ? "bg-emerald-500/15 text-emerald-300"
                            : app.status === "error"
                              ? "bg-rose-500/15 text-rose-300"
                              : "bg-amber-500/15 text-amber-300"
                        }`}
                      >
                        {app.status}
                      </span>
                      {app.detectedRuntime && (
                        <span className="rounded-full bg-slate-800 px-2.5 py-0.5 text-xs text-slate-300">
                          {app.detectedRuntime}
                        </span>
                      )}
                      {app.lastCommitSha && (
                        <span className="inline-flex items-center gap-1 rounded-full bg-slate-800/80 px-2 py-0.5 text-xs font-mono text-slate-400">
                          <GitBranch className="h-3 w-3" />
                          {app.lastCommitSha.slice(0, 7)}
                        </span>
                      )}
                      {app.companions.map((c) => (
                        <span
                          key={c.type}
                          className="inline-flex items-center gap-1 rounded-full bg-sky-500/15 px-2.5 py-0.5 text-xs font-medium text-sky-300"
                        >
                          <Database className="h-3 w-3" />
                          {c.type}
                        </span>
                      ))}
                    </div>
                    <p className="text-xs text-slate-400">
                      ID: <code className="text-slate-300">{app.slug}</code>{" "}
                      &middot; Port {app.internalPort} &middot; {app.cpuLimit}{" "}
                      CPU / {app.memoryLimitMb} MB RAM
                    </p>
                    {app.domain && (
                      <a
                        href={`https://${app.domain}`}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 text-xs text-emerald-400 hover:text-emerald-300"
                      >
                        https://{app.domain}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    )}
                  </div>

                  {/* Action Buttons */}
                  <div className="flex flex-wrap items-center gap-2">
                    {app.status === "running" ? (
                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => handleAction(app.slug, "stop")}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 cursor-pointer"
                      >
                        <Square className="h-3.5 w-3.5" /> Stop
                      </button>
                    ) : (
                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => handleAction(app.slug, "start")}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-300 hover:bg-emerald-500/20 cursor-pointer"
                      >
                        <Play className="h-3.5 w-3.5" /> Start
                      </button>
                    )}
                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => handleAction(app.slug, "restart")}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 cursor-pointer"
                    >
                      <RotateCw className="h-3.5 w-3.5" /> Restart
                    </button>
                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => handleAction(app.slug, "rebuild")}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 cursor-pointer"
                    >
                      <Hammer className="h-3.5 w-3.5" /> Rebuild
                    </button>
                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => handleDelete(app.slug)}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/30 px-3 py-1.5 text-xs font-medium text-rose-300 hover:bg-rose-500/10 cursor-pointer"
                    >
                      <Trash2 className="h-3.5 w-3.5" /> Delete
                    </button>
                  </div>
                </div>

                {/* Drawer triggers */}
                <div className="border-t border-slate-800/80 bg-slate-950/40 px-5 py-2.5 flex flex-wrap gap-2">
                  {(
                    [
                      ["deployments", "Deployments", Rocket],
                      ["logs", "Logs", Terminal],
                      ["domain", "Domain", Globe],
                      ["env", "Hidden Settings (.env)", KeyRound],
                      ["security", "Safety Check", ShieldCheck],
                    ] as const
                  ).map(([key, label, Icon]) => (
                    <button
                      key={key}
                      type="button"
                      onClick={() =>
                        isOpen && section === key
                          ? setSelectedSlug(null)
                          : void openDrawerBySlug(app.slug, key, app.domain)
                      }
                      className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition cursor-pointer ${
                        isOpen && section === key
                          ? "bg-slate-800 text-white"
                          : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
                      }`}
                    >
                      <Icon className="h-3.5 w-3.5" />
                      {label}
                    </button>
                  ))}
                </div>

                {isOpen && (
                  <div className="border-t border-slate-800 bg-slate-950/80 p-5">
                    {drawerLoading ? (
                      <p className="text-sm text-slate-400">Loading...</p>
                    ) : section === "deployments" ? (
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-medium text-slate-400">
                            Recent builds &amp; deployments (build logs are
                            automatically scrubbed of secrets)
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
                            className="text-xs text-emerald-400 hover:text-emerald-300 cursor-pointer"
                          >
                            Refresh
                          </button>
                        </div>
                        {deployments.length === 0 ? (
                          <p className="text-xs text-slate-400">
                            No tracked deployments yet.
                          </p>
                        ) : (
                          <div className="space-y-3">
                            {deployments.map((dep) => (
                              <div
                                key={dep.id}
                                className="rounded-xl border border-slate-800 bg-slate-900/70 p-3.5 space-y-2"
                              >
                                <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <span
                                      className={`rounded-full px-2 py-0.5 font-semibold ${deploymentBadgeClass(dep.status)}`}
                                    >
                                      {dep.status}
                                    </span>
                                    <span className="font-mono text-slate-300">
                                      {dep.action}
                                    </span>
                                    {dep.detectedRuntime && (
                                      <span className="text-slate-400">
                                        {dep.detectedRuntime}
                                        {dep.usedAutoDockerfile ? " (auto)" : ""}
                                      </span>
                                    )}
                                    {dep.commitSha && (
                                      <span className="font-mono text-slate-400">
                                        @{dep.commitSha.slice(0, 7)}
                                      </span>
                                    )}
                                  </div>
                                  <span className="text-slate-500">
                                    {new Date(dep.createdAt).toLocaleString()}
                                  </span>
                                </div>
                                {dep.phaseDetail && (
                                  <p className="text-xs text-slate-300">
                                    {dep.phaseDetail}
                                  </p>
                                )}
                                {dep.error && (
                                  <p className="text-xs text-rose-300">
                                    {dep.error}
                                  </p>
                                )}
                                {dep.buildLogs.length > 0 && (
                                  <pre className="max-h-40 overflow-auto rounded-lg border border-slate-800 bg-black/60 p-2.5 text-[11px] font-mono text-slate-300 whitespace-pre-wrap">
                                    {dep.buildLogs.join("\n")}
                                  </pre>
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ) : section === "logs" ? (
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-medium text-slate-400">
                            Recent logs (passwords &amp; tokens automatically
                            scrubbed)
                          </span>
                          <button
                            type="button"
                            onClick={() =>
                              void openDrawerBySlug(app.slug, "logs", app.domain)
                            }
                            className="text-xs text-emerald-400 hover:text-emerald-300 cursor-pointer"
                          >
                            Refresh Logs
                          </button>
                        </div>
                        <pre className="max-h-64 overflow-auto rounded-xl border border-slate-800 bg-black/60 p-3.5 text-xs font-mono text-slate-300 whitespace-pre-wrap">
                          {logs.length > 0 ? logs.join("\n") : "No logs yet."}
                        </pre>
                      </div>
                    ) : section === "domain" ? (
                      <div className="flex flex-wrap items-end gap-3">
                        <div className="flex-1 min-w-[220px]">
                          <label className="block text-xs font-medium text-slate-300 mb-1">
                            Public Web Address (Automatic HTTPS)
                          </label>
                          <input
                            type="text"
                            value={editDomain}
                            onChange={(e) => setEditDomain(e.target.value)}
                            placeholder="app.yourdomain.com"
                            className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
                          />
                        </div>
                        <button
                          type="button"
                          onClick={() => handleSaveDomain(false)}
                          className="rounded-lg bg-emerald-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-emerald-400 cursor-pointer"
                        >
                          Connect Domain
                        </button>
                        {app.domain && (
                          <button
                            type="button"
                            onClick={() => handleSaveDomain(true)}
                            className="rounded-lg border border-slate-700 px-3.5 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800 cursor-pointer"
                          >
                            Disconnect
                          </button>
                        )}
                      </div>
                    ) : section === "env" ? (
                      <div className="space-y-4">
                        {missingEnvKeys.length > 0 && (
                          <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3.5 space-y-2">
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
                                  className="rounded-md border border-amber-500/40 bg-slate-950 px-2.5 py-1 text-xs font-mono text-amber-200 hover:bg-amber-500/20 cursor-pointer"
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
                            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-mono text-white"
                          />
                          <input
                            type="password"
                            value={newEnvVal}
                            onChange={(e) => setNewEnvVal(e.target.value)}
                            placeholder="Value (encrypted at rest)"
                            required
                            className="flex-1 min-w-[200px] rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-mono text-white"
                          />
                          <button
                            type="submit"
                            className="rounded-lg bg-emerald-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-emerald-400 cursor-pointer"
                          >
                            Save Setting
                          </button>
                        </form>
                        <div className="divide-y divide-slate-800/80 rounded-xl border border-slate-800">
                          {envVars.length === 0 ? (
                            <p className="p-3 text-xs text-slate-400">
                              No saved settings yet.
                            </p>
                          ) : (
                            envVars.map((entry) => (
                              <div
                                key={entry.key}
                                className="flex items-center justify-between px-3.5 py-2 text-xs"
                              >
                                <div>
                                  <span className="font-mono text-slate-200">
                                    {entry.key}
                                  </span>
                                  <span className="ml-3 font-mono text-slate-500">
                                    {entry.maskedValue}
                                  </span>
                                </div>
                                <button
                                  type="button"
                                  onClick={() => handleDeleteEnv(entry.key)}
                                  className="text-rose-400 hover:text-rose-300 cursor-pointer"
                                >
                                  Remove
                                </button>
                              </div>
                            ))
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-2 text-xs">
                        {inspectData ? (
                          <div className="space-y-2">
                            <div className="flex flex-wrap items-center gap-3">
                              <span
                                className={`rounded-full px-3 py-1 font-semibold ${
                                  inspectData.lockedApartmentCompliant
                                    ? "bg-emerald-500/15 text-emerald-300"
                                    : "bg-rose-500/15 text-rose-300"
                                }`}
                              >
                                {inspectData.lockedApartmentCompliant
                                  ? "Locked Apartment Verified"
                                  : "Safety Warning — Check Config"}
                              </span>
                              <span className="text-slate-400">
                                Containers: {inspectData.containers.length}{" "}
                                &middot; Overall Status:{" "}
                                <span
                                  className={
                                    inspectData.status === "running"
                                      ? "text-emerald-300 font-semibold"
                                      : inspectData.status === "error"
                                        ? "text-rose-300 font-semibold"
                                        : "text-slate-200 font-semibold"
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
                                <div className="flex flex-wrap items-center gap-4 text-slate-400">
                                  <span>
                                    Docker Liveness:{" "}
                                    <span
                                      className={`font-mono ${healthToneClass(health.dockerLiveness.tone)}`}
                                    >
                                      {health.dockerLiveness.label}
                                    </span>
                                  </span>
                                  <span>
                                    Monitored HTTP Health:{" "}
                                    <span
                                      className={`font-mono ${healthToneClass(health.monitoredHttp.tone)}`}
                                    >
                                      {health.monitoredHttp.label}
                                    </span>
                                  </span>
                                  <span>
                                    Live HTTP Probe:{" "}
                                    <span
                                      className={`font-mono ${healthToneClass(health.liveHttpProbe.tone)}`}
                                    >
                                      {health.liveHttpProbe.label}
                                    </span>
                                  </span>
                                </div>
                              );
                            })()}
                          </div>
                        ) : (
                          <p className="text-slate-400">
                            No container inspection data available.
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
