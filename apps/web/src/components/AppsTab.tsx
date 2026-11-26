import { useCallback, useEffect, useRef, useState } from "react";
import {
  Loader2,
  RefreshCw,
} from "lucide-react";
import {
  api,
  type AppEnvEntry,
  type AppRecord,
  type CompanionService,
  type DeploymentRecord,
  type GitCredentialRecord,
  type GitInspectResult,
  type GithubRepoSummary,
  type InspectResult,
} from "../api";
import { formatSafetyCheckHealth, type HealthBadge } from "../health-display";
import { AppCard, AppStatus } from "./AppCard";
import { PageHeader, buttonPrimary, buttonSecondary } from "./PageHeader";

function healthToneClass(tone: HealthBadge["tone"]): string {
  if (tone === "healthy") return "text-ok";
  if (tone === "unhealthy") return "text-bad";
  if (tone === "warning") return "text-warn";
  return "text-fg";
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
  if (status === "succeeded") return "text-ok";
  if (status === "failed") return "text-bad";
  return "text-warn";
}

const RESERVED_SLUGS = new Set([
  "core",
  "vpsagent",
  "vps-os",
  "caddy",
  "api",
  "dashboard",
  "agent",
  "system",
  "root",
  "admin",
]);

function normalizeSlugCandidate(raw: string): string {
  let cleaned = raw
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48)
    .replace(/-+$/g, "");
  if (cleaned.length < 2) {
    cleaned = `${cleaned || "my"}-app`;
  }
  return cleaned;
}

function pickUnusedSlug(
  rawRepoName: string,
  owner: string | null,
  existingApps: AppRecord[],
): string {
  const taken = new Set(existingApps.map((a) => a.slug.toLowerCase()));
  const isAvailable = (cand: string) =>
    cand.length >= 2 && !RESERVED_SLUGS.has(cand) && !taken.has(cand);

  const base = normalizeSlugCandidate(rawRepoName);
  if (isAvailable(base)) return base;

  if (owner) {
    const withOwner = normalizeSlugCandidate(`${owner}-${rawRepoName}`);
    if (isAvailable(withOwner)) return withOwner;
  }

  for (let i = 2; i <= 99; i++) {
    const suffix = `-${i}`;
    const candidate = `${base.slice(0, 48 - suffix.length).replace(/-+$/g, "")}${suffix}`;
    if (isAvailable(candidate)) return candidate;
  }
  return base;
}

type DrawerSection = "deployments" | "logs" | "domain" | "env" | "security";

interface AppsTabProps {
  apps: AppRecord[];
  appsBaseDomain: string | null;
  gitCredentials?: GitCredentialRecord[];
  deepLink?: {
    slug: string;
    section: DrawerSection;
    deploymentId?: string;
  } | null;
  onConsumeDeepLink?: () => void;
  onOpenGithubSettings?: () => void;
  onRefresh: () => Promise<void>;
  onInspectSync?: (inspect: InspectResult) => void;
}

export function AppsTab({
  apps,
  appsBaseDomain,
  gitCredentials = [],
  deepLink,
  onConsumeDeepLink,
  onOpenGithubSettings,
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
  const [gitCredentialId, setGitCredentialId] = useState("");
  const [githubRepos, setGithubRepos] = useState<GithubRepoSummary[]>([]);
  const [reposHasMore, setReposHasMore] = useState(false);
  const [reposLoading, setReposLoading] = useState(false);
  const [repoFilter, setRepoFilter] = useState("");
  const [reposError, setReposError] = useState<string | null>(null);
  const manualFieldsRef = useRef<Set<string>>(new Set());
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

  const loadGithubRepos = useCallback(
    async (queryText?: string) => {
      if (gitCredentials.length === 0) {
        setGithubRepos([]);
        setReposHasMore(false);
        return;
      }
      setReposLoading(true);
      setReposError(null);
      try {
        const res = await api.listGithubRepos({
          ...(queryText?.trim() ? { query: queryText.trim() } : {}),
          limit: 50,
        });
        setGithubRepos(res.repos);
        setReposHasMore(Boolean(res.hasMore));
        if (res.errors.length > 0 && res.repos.length === 0) {
          setReposError(res.errors[0]!.error);
        }
      } catch (err) {
        setReposError(
          err instanceof Error
            ? err.message
            : "Could not load your GitHub repositories.",
        );
      } finally {
        setReposLoading(false);
      }
    },
    [gitCredentials.length],
  );

  useEffect(() => {
    if (!showCreate || sourceType !== "git" || gitCredentials.length === 0) {
      return;
    }
    const timer = window.setTimeout(() => {
      void loadGithubRepos(repoFilter);
    }, repoFilter.trim() ? 250 : 0);
    return () => window.clearTimeout(timer);
  }, [gitCredentials.length, loadGithubRepos, repoFilter, showCreate, sourceType]);

  const resetInferredBuildFields = () => {
    const manual = manualFieldsRef.current;
    if (!manual.has("dockerfile")) setDockerfilePath("auto");
    if (!manual.has("port")) setInternalPort("");
    if (!manual.has("postgres")) setWithPostgres(false);
    if (!manual.has("redis")) setWithRedis(false);
    if (!manual.has("domain")) setDomain("");
  };

  const handleSelectGithubRepo = (repo: GithubRepoSummary) => {
    setGitRepoUrl(repo.htmlUrl);
    setGitPreview(null);
    resetInferredBuildFields();
    const manual = manualFieldsRef.current;
    if (!manual.has("branch")) {
      setGitBranch(repo.defaultBranch ?? "");
    }
    if (!manual.has("slug")) {
      setSlug(pickUnusedSlug(repo.name, repo.owner, apps));
    }
    if (!manual.has("name")) {
      const displayName = repo.name
        .replace(/[-_.]+/g, " ")
        .replace(/\b\w/g, (ch) => ch.toUpperCase())
        .slice(0, 100);
      if (displayName) {
        setName(displayName);
      }
    }
  };

  const handleInspectGit = async () => {
    if (!gitRepoUrl.trim()) {
      setError("Paste an HTTPS GitHub link first.");
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
        gitCredentialId || null,
      );
      const info = res.inspect;
      setGitPreview(info);
      const manual = manualFieldsRef.current;
      if (!manual.has("name")) setName(info.suggestedName);
      if (!manual.has("slug")) {
        setSlug(pickUnusedSlug(info.suggestedSlug, null, apps));
      }
      if (!manual.has("branch") && info.resolvedBranch) {
        setGitBranch(info.resolvedBranch);
      }
      if (!manual.has("dockerfile")) {
        setDockerfilePath(info.hasDockerfile ? info.dockerfilePath : "auto");
      }
      if (!manual.has("port")) {
        setInternalPort(String(info.suggestedPort));
      }
      if (!manual.has("postgres")) {
        setWithPostgres(info.suggestedCompanions.includes("postgres"));
      }
      if (!manual.has("redis")) {
        setWithRedis(info.suggestedCompanions.includes("redis"));
      }
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
          ...(sourceType === "git" && gitCredentialId
            ? { gitCredentialId }
            : {}),
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
          createOnly: true,
        },
        true,
      );

      setShowCreate(false);
      setGitPreview(null);
      manualFieldsRef.current.clear();
      setSlug("");
      setName("");
      setGitRepoUrl("");
      setGitBranch("");
      setGitCredentialId("");
      setRepoFilter("");
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
        setNotice("App deployed.");
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

  const selectedApp = apps.find((a) => a.slug === selectedSlug) ?? null;

  return (
    <div className="space-y-6">
      {!selectedApp && (
        <PageHeader
          title="Apps"
          description="Each app runs in its own isolated container."
          actions={
            <button
              type="button"
              onClick={() => {
                setShowCreate((v) => {
                  if (v) {
                    setGitCredentialId("");
                    setRepoFilter("");
                    manualFieldsRef.current.clear();
                  }
                  return !v;
                });
              }}
              className={showCreate ? buttonSecondary : buttonPrimary}
            >
              {showCreate ? "Cancel" : "New app"}
            </button>
          }
        />
      )}

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
      {trackedDeployment && (
        <div className="surface-panel rounded-xl p-5 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2.5 text-xs">
              {isDeploymentActive(trackedDeployment.status) ? (
                <Loader2 className="h-4 w-4 animate-spin text-warn" />
              ) : null}
              <span className="text-sm font-medium text-fg">
                Deployment for{" "}
                <code className="text-fg">
                  {trackedDeployment.slug}
                </code>
              </span>
              <span
                className={`font-medium capitalize ${deploymentToneClass(trackedDeployment.status)}`}
              >
                {trackedDeployment.status}
              </span>
              {trackedDeployment.detectedRuntime && (
                <span className="font-mono text-muted">
                  &middot; {trackedDeployment.detectedRuntime}
                  {trackedDeployment.usedAutoDockerfile ? " (auto)" : ""}
                </span>
              )}
              {trackedDeployment.commitSha && (
                <span className="inline-flex items-center gap-1 font-mono text-muted">
                  {trackedDeployment.commitSha.slice(0, 7)}
                </span>
              )}
            </div>
            {!isDeploymentActive(trackedDeployment.status) && (
              <button
                type="button"
                onClick={() => setTrackedDeployment(null)}
                className="btn-press text-xs text-muted hover:text-fg cursor-pointer"
              >
                Dismiss
              </button>
            )}
          </div>
          {trackedDeployment.phaseDetail && (
            <p className="text-xs text-fg-2">
              {trackedDeployment.phaseDetail}
            </p>
          )}
          {trackedDeployment.error && (
            <p className="text-xs text-bad">{trackedDeployment.error}</p>
          )}
          {trackedDeployment.buildLogs.length > 0 && (
            <pre className="surface-well max-h-48 overflow-auto rounded-lg p-3 text-xs font-mono text-fg-2 whitespace-pre-wrap">
              {trackedDeployment.buildLogs.join("\n")}
            </pre>
          )}
        </div>
      )}
      {showCreate && !selectedApp && (
        <form
          onSubmit={handleCreate}
          className="surface-panel rounded-xl p-6 space-y-5"
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-sm font-medium text-fg">
              Deploy a new app
            </h2>
            <div
              role="tablist"
              aria-label="App source type"
              className="inline-flex rounded-lg border border-line bg-well p-1 gap-0.5"
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
                const order = ["git", "image"] as const;
                const idx = order.indexOf(sourceType);
                const next =
                  e.key === "Home"
                    ? order[0]
                    : e.key === "End"
                      ? order[order.length - 1]!
                      : e.key === "ArrowRight"
                        ? order[(idx + 1) % order.length]!
                        : order[(idx - 1 + order.length) % order.length]!;
                setSourceType(next);
                document.getElementById(`app-source-tab-${next}`)?.focus();
              }}
            >
              <button
                id="app-source-tab-git"
                role="tab"
                aria-selected={sourceType === "git"}
                aria-controls="app-source-panel-git"
                tabIndex={sourceType === "git" ? 0 : -1}
                type="button"
                onClick={() => setSourceType("git")}
                className={`btn-press rounded-md px-3 py-1.5 text-xs font-medium cursor-pointer ${
                  sourceType === "git"
                    ? "bg-fill text-fg"
                    : "text-muted hover:text-fg"
                }`}
              >
                GitHub repository
              </button>
              <button
                id="app-source-tab-image"
                role="tab"
                aria-selected={sourceType === "image"}
                aria-controls="app-source-panel-image"
                tabIndex={sourceType === "image" ? 0 : -1}
                type="button"
                onClick={() => setSourceType("image")}
                className={`btn-press rounded-md px-3 py-1.5 text-xs font-medium cursor-pointer ${
                  sourceType === "image"
                    ? "bg-fill text-fg"
                    : "text-muted hover:text-fg"
                }`}
              >
                Docker image
              </button>
            </div>
          </div>

          {sourceType === "git" ? (
            <div
              id="app-source-panel-git"
              role="tabpanel"
              aria-labelledby="app-source-tab-git"
              className="space-y-4"
            >
              {gitCredentials.length > 0 ? (
                <div className="surface-well rounded-lg p-3.5 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-fg">
                      Your GitHub repositories
                    </span>
                    <div className="flex items-center gap-2">
                      <input
                        type="text"
                        value={repoFilter}
                        onChange={(e) => setRepoFilter(e.target.value)}
                        placeholder="Filter repos..."
                        className="field-input rounded-md px-2.5 py-1 text-xs w-44"
                      />
                      <button
                        type="button"
                        disabled={reposLoading}
                        onClick={() => void loadGithubRepos(repoFilter)}
                        className="btn-press inline-flex items-center gap-1 rounded-md border border-line-strong bg-surface px-2.5 py-1 text-xs text-fg-2 hover:text-fg disabled:opacity-50 cursor-pointer"
                      >
                        <RefreshCw
                          className={`h-3 w-3 ${reposLoading ? "animate-spin" : ""}`}
                        />
                        Refresh
                      </button>
                    </div>
                  </div>

                  {reposError && (
                    <p className="text-xs text-bad">{reposError}</p>
                  )}

                  {reposLoading && githubRepos.length === 0 ? (
                    <p className="text-xs text-muted">
                      Loading your accessible repositories...
                    </p>
                  ) : githubRepos.length === 0 ? (
                    <p className="text-xs text-muted">
                      {repoFilter.trim()
                        ? reposHasMore
                          ? "No matches in the 500 most recently updated repositories — paste any GitHub URL below to deploy it directly."
                          : "No repositories match that search."
                        : "No repositories returned for your saved token yet — check Contents: Read-only permission or paste a repo URL below."}
                    </p>
                  ) : (
                    <>
                      <div className="max-h-44 overflow-y-auto divide-y divide-line rounded-md border border-line bg-canvas">
                        {githubRepos.map((repo) => {
                          const selected =
                            gitRepoUrl.trim().replace(/\/+$/, "") ===
                            repo.htmlUrl;
                          return (
                            <button
                              key={`${repo.credentialId}:${repo.fullName}`}
                              type="button"
                              onClick={() => handleSelectGithubRepo(repo)}
                              className={`w-full text-left px-3 py-2 flex items-center justify-between gap-3 text-xs cursor-pointer transition-colors ${
                                selected
                                  ? "bg-ok-soft text-fg"
                                  : "hover:bg-fill text-fg-2"
                              }`}
                            >
                              <div className="min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono font-medium truncate">
                                    {repo.fullName}
                                  </span>
                                  {repo.private ? (
                                    <span className="inline-flex items-center gap-1 rounded bg-warn-soft px-1.5 py-0.5 text-[10px] font-medium text-warn shrink-0">
                                      Private
                                    </span>
                                  ) : (
                                    <span className="rounded bg-fill px-1.5 py-0.5 text-[10px] text-muted shrink-0">
                                      Public
                                    </span>
                                  )}
                                </div>
                                {repo.description && (
                                  <p className="text-[11px] text-subtle truncate mt-0.5">
                                    {repo.description}
                                  </p>
                                )}
                              </div>
                              <div className="text-right shrink-0 text-[11px] text-subtle font-mono">
                                {repo.defaultBranch ?? "main"}
                                {gitCredentials.length > 1 && (
                                  <span className="block text-[10px] text-muted font-sans">
                                    {repo.credentialLabel}
                                  </span>
                                )}
                              </div>
                            </button>
                          );
                        })}
                      </div>
                      {reposHasMore && (
                        <p className="text-[11px] text-muted">
                          {repoFilter.trim()
                            ? `Showing up to ${githubRepos.length} recent matches — refine your search or paste any GitHub URL below if you don't see your repo.`
                            : `Showing the ${githubRepos.length} most recently updated repositories — search above or paste any GitHub URL below.`}
                        </p>
                      )}
                    </>
                  )}
                </div>
              ) : null}

              <div className="flex flex-wrap gap-2.5 items-end">
                <div className="flex-1 min-w-[260px]">
                  <label className="block text-xs font-medium text-muted mb-1.5">
                    HTTPS GitHub repo URL (public or private)
                  </label>
                  <input
                    type="url"
                    value={gitRepoUrl}
                    onChange={(e) => {
                      setGitRepoUrl(e.target.value);
                      setGitPreview(null);
                      resetInferredBuildFields();
                    }}
                    placeholder="https://github.com/owner/repo"
                    required
                    className="field-input w-full rounded-lg px-3.5 py-2 text-sm font-mono"
                  />
                </div>
                <button
                  type="button"
                  disabled={inspectingGit || !gitRepoUrl.trim()}
                  onClick={handleInspectGit}
                  className="btn-press inline-flex items-center gap-1.5 rounded-lg border border-line-strong px-3.5 py-2 text-xs font-medium text-fg-2 hover:bg-fill disabled:opacity-50 cursor-pointer"
                >
                  {inspectingGit ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : null}
                  {inspectingGit ? "Inspecting..." : "Inspect & auto-fill"}
                </button>
              </div>

              {gitCredentials.length === 0 && (
                <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-line bg-well px-3.5 py-2 text-xs text-muted">
                  <span>Deploying a private GitHub repo?</span>
                  {onOpenGithubSettings && (
                    <button
                      type="button"
                      onClick={onOpenGithubSettings}
                      className="btn-press inline-flex items-center gap-1 link font-medium cursor-pointer"
                    >
                      Connect GitHub in Settings
                    </button>
                  )}
                </div>
              )}

              {gitCredentials.length > 1 && (
                <div>
                  <label className="block text-xs font-medium text-muted mb-1.5">
                    GitHub access token
                  </label>
                  <select
                    value={gitCredentialId}
                    onChange={(e) => setGitCredentialId(e.target.value)}
                    className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
                  >
                    <option value="">Auto (public or default token)</option>
                    {gitCredentials.map((cred) => (
                      <option key={cred.id} value={cred.id}>
                        {cred.label}
                        {cred.accountLogin ? ` (@${cred.accountLogin})` : ""}
                        {cred.isDefault ? " — Default" : ""}
                      </option>
                    ))}
                  </select>
                </div>
              )}

              {gitPreview && (
                <div className="rounded-lg border border-info-line bg-info-soft p-3.5 space-y-1.5 text-xs">
                  <div className="flex flex-wrap items-center gap-2 text-info font-medium">
                    <span>{gitPreview.buildPlanSummary}</span>
                  </div>
                  {gitPreview.envExampleKeys.length > 0 && (
                    <p className="text-fg-2">
                      Detected settings from <code>.env.example</code>:{" "}
                      <span className="font-mono text-warn">
                        {gitPreview.envExampleKeys.map((k) => k.key).join(", ")}
                      </span>{" "}
                      (fill them below or safely later in Hidden Settings).
                    </p>
                  )}
                  {gitPreview.notes.map((n, i) => (
                    <p key={i} className="text-muted">
                      {n}
                    </p>
                  ))}
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-muted mb-1.5">
                    Branch (optional, defaults to repo default)
                  </label>
                  <input
                    type="text"
                    value={gitBranch}
                    onChange={(e) => {
                      manualFieldsRef.current.add("branch");
                      setGitBranch(e.target.value);
                    }}
                    placeholder="main"
                    className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-muted mb-1.5">
                    Dockerfile path (leave &ldquo;auto&rdquo; to auto-detect)
                  </label>
                  <input
                    type="text"
                    value={dockerfilePath}
                    onChange={(e) => {
                      manualFieldsRef.current.add("dockerfile");
                      setDockerfilePath(e.target.value);
                    }}
                    placeholder="auto"
                    className="field-input w-full rounded-lg px-3.5 py-2 text-sm font-mono"
                  />
                </div>
              </div>
            </div>
          ) : (
            <div
              id="app-source-panel-image"
              role="tabpanel"
              aria-labelledby="app-source-tab-image"
            >
              <label className="block text-xs font-medium text-muted mb-1.5">
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
              <label className="block text-xs font-medium text-muted mb-1.5">
                Display name
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => {
                  manualFieldsRef.current.add("name");
                  setName(e.target.value);
                }}
                placeholder="My Blog"
                required
                className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-muted mb-1.5">
                Short ID (lowercase letters &amp; hyphens)
              </label>
              <input
                type="text"
                value={slug}
                onChange={(e) => {
                  manualFieldsRef.current.add("slug");
                  setSlug(e.target.value);
                }}
                placeholder="my-blog"
                required
                className="field-input w-full rounded-lg px-3.5 py-2 text-sm font-mono"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-muted mb-1.5">
                App internal port{" "}
                {sourceType === "git" && (
                  <span className="text-subtle">
                    (optional, auto-detected)
                  </span>
                )}
              </label>
              <input
                type="number"
                value={internalPort}
                onChange={(e) => {
                  manualFieldsRef.current.add("port");
                  setInternalPort(e.target.value);
                }}
                placeholder={sourceType === "git" ? "Auto-detect" : "8080"}
                min={1}
                max={65535}
                required={sourceType === "image"}
                className="field-input w-full rounded-lg px-3.5 py-2 text-sm tabular-nums"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-muted mb-1.5">
                Public domain{" "}
                {appsBaseDomain && !noDomain && (
                  <span className="text-ok">
                    (auto: {slug || "your-app"}.{appsBaseDomain})
                  </span>
                )}
              </label>
              <input
                type="text"
                value={domain}
                disabled={noDomain}
                onChange={(e) => {
                  manualFieldsRef.current.add("domain");
                  setDomain(e.target.value);
                }}
                placeholder={
                  appsBaseDomain
                    ? `${slug || "my-app"}.${appsBaseDomain}`
                    : "app.yourdomain.com"
                }
                className="field-input w-full rounded-lg px-3.5 py-2 text-sm disabled:opacity-45"
              />
              {appsBaseDomain && (
                <label className="mt-2 inline-flex items-center gap-2 text-xs text-muted cursor-pointer">
                  <input
                    type="checkbox"
                    checked={noDomain}
                    onChange={(e) => setNoDomain(e.target.checked)}
                    className="rounded border-line-strong bg-canvas accent-fg"
                  />
                  Keep private (skip automatic subdomain)
                </label>
              )}
            </div>
          </div>

          <div className="flex flex-wrap gap-6 pt-1">
            <label className="inline-flex items-center gap-2 text-sm text-fg-2 cursor-pointer">
              <input
                type="checkbox"
                checked={withPostgres}
                onChange={(e) => {
                  manualFieldsRef.current.add("postgres");
                  setWithPostgres(e.target.checked);
                }}
                className="rounded border-line-strong bg-canvas accent-fg"
              />
              Attach private Postgres database
            </label>
            <label className="inline-flex items-center gap-2 text-sm text-fg-2 cursor-pointer">
              <input
                type="checkbox"
                checked={withRedis}
                onChange={(e) => {
                  manualFieldsRef.current.add("redis");
                  setWithRedis(e.target.checked);
                }}
                className="rounded border-line-strong bg-canvas accent-fg"
              />
              Attach private Redis cache
            </label>
          </div>

          <div>
            <label className="block text-xs font-medium text-muted mb-1.5">
              Environment variables (optional, one KEY=VALUE per line)
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
              onClick={() => {
                setShowCreate(false);
                setGitCredentialId("");
                setRepoFilter("");
                manualFieldsRef.current.clear();
              }}
              className="btn-press rounded-lg border border-line-strong bg-surface px-4 py-2 text-[13px] font-medium text-muted hover:text-fg cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={creating}
              className="btn-press rounded-lg bg-primary px-4 py-2 text-[13px] font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer"
            >
              {creating ? "Starting..." : "Launch app"}
            </button>
          </div>
        </form>
      )}

      {apps.length === 0 ? (
        <div className="surface-panel rounded-lg px-6 py-10 space-y-3">
          <p className="text-sm font-medium">No apps yet.</p>
          <p className="text-xs text-muted max-w-md">
            Deploy a GitHub repo or Docker image yourself, or create an access
            key in Settings so your AI agent can deploy for you.
          </p>
          <button
            type="button"
            onClick={() => setShowCreate(true)}
            className="btn-press rounded-md bg-primary px-3.5 py-1.5 text-xs font-medium text-on-primary hover:bg-primary-hover cursor-pointer"
          >
            Deploy your first app
          </button>
        </div>
      ) : !selectedApp ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
          {apps.map((app) => (
            <AppCard
              key={app.slug}
              app={app}
              onOpen={() => void openDrawerBySlug(app.slug, "deployments", app.domain)}
            />
          ))}
        </div>
      ) : (
        <div>
          {[selectedApp].map((app) => {
            const isBusy = busySlug === app.slug;
            const isOpen = true;
            return (
              <div key={app.slug} className="space-y-6">
                <button
                  type="button"
                  onClick={() => setSelectedSlug(null)}
                  className="btn-press text-xs text-muted hover:text-fg cursor-pointer"
                >
                  ← All apps
                </button>

                <div className="flex flex-wrap items-end justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-3">
                      <h1 className="text-2xl font-semibold tracking-[-0.02em]">{app.name}</h1>
                      <AppStatus status={app.status} />
                    </div>
                    <p className="mt-1.5 text-sm text-muted">
                      {app.domain ? (
                        <a
                          href={`https://${app.domain}`}
                          target="_blank"
                          rel="noreferrer"
                          className="hover:text-fg hover:underline underline-offset-2"
                        >
                          {app.domain}
                        </a>
                      ) : (
                        "No public address"
                      )}
                    </p>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    {app.status === "running" ? (
                      <button type="button" disabled={isBusy} onClick={() => handleAction(app.slug, "stop")} className={buttonSecondary}>
                        Stop
                      </button>
                    ) : (
                      <button type="button" disabled={isBusy} onClick={() => handleAction(app.slug, "start")} className={buttonSecondary}>
                        Start
                      </button>
                    )}
                    <button type="button" disabled={isBusy} onClick={() => handleAction(app.slug, "restart")} className={buttonSecondary}>
                      Restart
                    </button>
                    <button type="button" disabled={isBusy} onClick={() => handleAction(app.slug, "rebuild")} className={buttonPrimary}>
                      Rebuild
                    </button>
                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => handleDelete(app.slug)}
                      className="btn-press rounded-md px-3 py-2 text-[13px] text-muted hover:text-fg hover:bg-bad-soft disabled:opacity-50 cursor-pointer"
                    >
                      Delete
                    </button>
                  </div>
                </div>

                <dl className="grid grid-cols-2 lg:grid-cols-4 gap-px overflow-hidden rounded-lg border border-line bg-line">
                  {(
                    [
                      ["Short ID", <span className="font-mono">{app.slug}</span>],
                      [
                        "Source",
                        app.sourceType === "git"
                          ? `${app.gitRepoUrl?.replace(/^https?:\/\/(www\.)?github\.com\//, "") ?? "GitHub"}${app.gitBranch ? ` · ${app.gitBranch}` : ""}`
                          : app.image ?? "Docker image",
                      ],
                      [
                        "Runtime",
                        [app.detectedRuntime, `port ${app.internalPort}`].filter(Boolean).join(" · "),
                      ],
                      [
                        "Limits",
                        `${app.cpuLimit} CPU · ${app.memoryLimitMb} MB${
                          app.companions.length > 0
                            ? ` · + ${app.companions.map((c) => c.type).join(", ")}`
                            : ""
                        }`,
                      ],
                    ] as Array<[string, React.ReactNode]>
                  ).map(([label, value]) => (
                    <div key={label} className="bg-surface px-4 py-3 min-w-0">
                      <dt className="text-xs text-muted">{label}</dt>
                      <dd className="mt-1 truncate text-sm">{value}</dd>
                    </div>
                  ))}
                </dl>

                <nav aria-label={`${app.name} sections`} className="flex flex-wrap gap-x-6 border-b border-line">
                  {(
                    [
                      ["deployments", "Deploys"],
                      ["logs", "Logs"],
                      ["domain", "Address"],
                      ["env", "Variables"],
                      ["security", "Health"],
                    ] as const
                  ).map(([key, label]) => {
                    const active = section === key;
                    return (
                      <button
                        key={key}
                        type="button"
                        aria-current={active ? "page" : undefined}
                        onClick={() => {
                          if (!active) void openDrawerBySlug(app.slug, key, app.domain);
                        }}
                        className={`btn-press -mb-px border-b-2 pb-2.5 text-sm cursor-pointer ${
                          active ? "border-fg text-fg font-medium" : "border-transparent text-muted hover:text-fg"
                        }`}
                      >
                        {label}
                      </button>
                    );
                  })}
                </nav>

                {isOpen && (
                  <div>
                    {drawerLoading ? (
                      <div className="space-y-2.5" aria-busy="true">
                        <div className="h-4 w-48 rounded skeleton-bar" />
                        <div className="h-16 w-full rounded-lg skeleton-bar" />
                      </div>
                    ) : section === "deployments" ? (
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="text-xs text-muted">
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
                            className="btn-press text-xs font-medium link cursor-pointer"
                          >
                            Refresh
                          </button>
                        </div>
                        {deployments.length === 0 ? (
                          <p className="text-xs text-subtle">
                            No tracked deployments yet.
                          </p>
                        ) : (
                          <div className="divide-y divide-line border-t border-line">
                            {deployments.map((dep) => (
                              <div key={dep.id} className="py-3.5 space-y-2">
                                <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <span
                                      className={`font-medium capitalize ${deploymentToneClass(dep.status)}`}
                                    >
                                      {dep.status}
                                    </span>
                                    <span className="font-mono text-fg-2">
                                      {dep.action}
                                    </span>
                                    {dep.detectedRuntime && (
                                      <span className="text-muted">
                                        {dep.detectedRuntime}
                                        {dep.usedAutoDockerfile ? " (auto)" : ""}
                                      </span>
                                    )}
                                    {dep.commitSha && (
                                      <span className="font-mono text-subtle">
                                        @{dep.commitSha.slice(0, 7)}
                                      </span>
                                    )}
                                  </div>
                                  <span className="text-subtle tabular-nums">
                                    {new Date(dep.createdAt).toLocaleString()}
                                  </span>
                                </div>
                                {dep.phaseDetail && (
                                  <p className="text-xs text-muted">
                                    {dep.phaseDetail}
                                  </p>
                                )}
                                {dep.error && (
                                  <p className="text-xs text-bad">
                                    {dep.error}
                                  </p>
                                )}
                                {dep.buildLogs.length > 0 && (
                                  <pre className="max-h-40 overflow-auto rounded-lg border border-line bg-canvas p-3 text-[11px] font-mono text-fg-2 whitespace-pre-wrap">
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
                          <span className="text-xs text-muted">
                            Recent container logs (passwords &amp; tokens
                            automatically scrubbed)
                          </span>
                          <button
                            type="button"
                            onClick={() =>
                              void openDrawerBySlug(app.slug, "logs", app.domain)
                            }
                            className="btn-press text-xs font-medium link cursor-pointer"
                          >
                            Refresh logs
                          </button>
                        </div>
                        <pre className="max-h-64 overflow-auto rounded-lg border border-line bg-canvas p-3.5 text-xs font-mono text-fg-2 whitespace-pre-wrap leading-relaxed">
                          {logs.length > 0 ? logs.join("\n") : "No logs yet."}
                        </pre>
                      </div>
                    ) : section === "domain" ? (
                      <div className="flex flex-wrap items-end gap-3">
                        <div className="flex-1 min-w-[220px]">
                          <label className="block text-xs font-medium text-muted mb-1.5">
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
                          className="btn-press rounded-lg bg-primary px-4 py-2 text-xs font-medium text-on-primary hover:bg-primary-hover cursor-pointer"
                        >
                          Connect domain
                        </button>
                        {app.domain && (
                          <button
                            type="button"
                            onClick={() => handleSaveDomain(true)}
                            className="btn-press rounded-lg border border-line-strong bg-surface px-3.5 py-2 text-xs font-medium text-muted hover:text-fg cursor-pointer"
                          >
                            Disconnect
                          </button>
                        )}
                      </div>
                    ) : section === "env" ? (
                      <div className="space-y-4">
                        {missingEnvKeys.length > 0 && (
                          <div className="rounded-lg border border-warn-line bg-warn-soft p-3.5 space-y-2">
                            <p className="text-xs font-medium text-warn">
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
                                  className="btn-press rounded-md border border-warn-line bg-canvas px-2.5 py-1 text-xs font-mono text-warn hover:bg-warn-soft cursor-pointer"
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
                            className="btn-press rounded-lg bg-primary px-4 py-2 text-xs font-medium text-on-primary hover:bg-primary-hover cursor-pointer"
                          >
                            Save setting
                          </button>
                        </form>
                        <div className="divide-y divide-line rounded-lg border border-line bg-canvas">
                          {envVars.length === 0 ? (
                            <p className="p-3.5 text-xs text-subtle">
                              No saved settings yet.
                            </p>
                          ) : (
                            envVars.map((entry) => (
                              <div
                                key={entry.key}
                                className="flex items-center justify-between px-3.5 py-2.5 text-xs"
                              >
                                <div className="min-w-0 [overflow-wrap:anywhere]">
                                  <span className="font-mono text-fg">
                                    {entry.key}
                                  </span>
                                  <span className="ml-3 font-mono text-subtle">
                                    {entry.maskedValue}
                                  </span>
                                </div>
                                <button
                                  type="button"
                                  onClick={() => handleDeleteEnv(entry.key)}
                                  className="btn-press text-bad hover:text-bad cursor-pointer shrink-0 ml-3"
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
                                className={`inline-flex items-center gap-1.5 font-medium ${
                                  inspectData.lockedApartmentCompliant
                                    ? "text-ok"
                                    : "text-bad"
                                }`}
                              >
                                <span
                                  className={`h-2 w-2 rounded-full ${
                                    inspectData.lockedApartmentCompliant
                                      ? "bg-ok"
                                      : "bg-bad"
                                  }`}
                                />
                                {inspectData.lockedApartmentCompliant
                                  ? "Isolation verified"
                                  : "Safety warning: check config"}
                              </span>
                              <span className="text-muted tabular-nums">
                                Containers: {inspectData.containers.length}{" "}
                                &middot; Overall status:{" "}
                                <span
                                  className={
                                    inspectData.status === "running"
                                      ? "text-ok font-medium"
                                      : inspectData.status === "error"
                                        ? "text-bad font-medium"
                                        : "text-fg font-medium"
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
                                  <div className="rounded-lg border border-line bg-canvas px-3.5 py-2.5">
                                    <p className="text-[11px] text-subtle">
                                      Docker liveness
                                    </p>
                                    <p
                                      className={`mt-0.5 font-mono font-medium ${healthToneClass(health.dockerLiveness.tone)}`}
                                    >
                                      {health.dockerLiveness.label}
                                    </p>
                                  </div>
                                  <div className="rounded-lg border border-line bg-canvas px-3.5 py-2.5">
                                    <p className="text-[11px] text-subtle">
                                      Monitored HTTP health
                                    </p>
                                    <p
                                      className={`mt-0.5 font-mono font-medium ${healthToneClass(health.monitoredHttp.tone)}`}
                                    >
                                      {health.monitoredHttp.label}
                                    </p>
                                  </div>
                                  <div className="rounded-lg border border-line bg-canvas px-3.5 py-2.5">
                                    <p className="text-[11px] text-subtle">
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
                          <p className="text-muted">
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
