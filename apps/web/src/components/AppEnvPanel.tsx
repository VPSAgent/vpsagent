import { useEffect, useMemo, useRef, useState } from "react";
import { Eye, EyeOff, FileUp, Layers, Plus, ShieldCheck, X } from "lucide-react";
import type { AppEnvEntry, AppEnvRequest, AppRecord } from "../api";
import {
  appendMissingKeysToEnvDraft,
  isBuildTimePublicEnvKey,
  isLikelySecretEnvKey,
  parseEnvBlock,
} from "../env-utils";

interface AppEnvPanelProps {
  app: AppRecord;
  envVars: AppEnvEntry[];
  missingEnvKeys: string[];
  envRequest: AppEnvRequest | null;
  busy: boolean;
  envNeedsRebuild: boolean;
  changedBuildTimeKeys: string[];
  onSaveVars: (
    vars: Array<{ key: string; value: string; isSecret?: boolean }>,
    options?: { rebuild?: boolean },
  ) => Promise<boolean>;
  onDeleteVar: (key: string) => Promise<void>;
  onDismissRequest: () => Promise<void>;
  onRebuild: () => Promise<void>;
  onClearRebuildBanner: () => void;
}

export function AppEnvPanel({
  app,
  envVars,
  missingEnvKeys,
  envRequest,
  busy,
  envNeedsRebuild,
  changedBuildTimeKeys,
  onSaveVars,
  onDeleteVar,
  onDismissRequest,
  onRebuild,
  onClearRebuildBanner,
}: AppEnvPanelProps) {
  const [entryMode, setEntryMode] = useState<"bulk" | "single">("bulk");

  // Bulk .env paste state
  const [bulkText, setBulkText] = useState("");
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Single key/value state
  const [singleKey, setSingleKey] = useState("");
  const [singleVal, setSingleVal] = useState("");
  const [showSingleVal, setShowSingleVal] = useState(false);

  // Agent-requested checklist state
  const [checklistValues, setChecklistValues] = useState<
    Record<string, string>
  >({});
  const [revealedKeys, setRevealedKeys] = useState<Record<string, boolean>>({});
  const [showChecklistPaste, setShowChecklistPaste] = useState(false);
  const [checklistPasteText, setChecklistPasteText] = useState("");
  const [checklistPasteNote, setChecklistPasteNote] = useState<string | null>(
    null,
  );

  // Reset checklist drafts when app or request changes
  useEffect(() => {
    setChecklistValues({});
    setRevealedKeys({});
    setShowChecklistPaste(false);
    setChecklistPasteText("");
    setChecklistPasteNote(null);
  }, [app.slug, envRequest?.updatedAt]);

  const existingKeySet = useMemo(
    () => new Set(envVars.map((e) => e.key)),
    [envVars],
  );

  const requestedKeySet = useMemo(
    () => new Set((envRequest?.keys ?? []).map((k) => k.key)),
    [envRequest],
  );

  const visibleMissingKeys = useMemo(
    () => missingEnvKeys.filter((k) => !requestedKeySet.has(k)),
    [missingEnvKeys, requestedKeySet],
  );

  const bulkParsed = useMemo(() => parseEnvBlock(bulkText), [bulkText]);
  const bulkBuildTimeKeys = useMemo(
    () => bulkParsed.vars.filter((v) => v.isBuildTime).map((v) => v.key),
    [bulkParsed],
  );
  const bulkSecretCount = useMemo(
    () => bulkParsed.vars.filter((v) => v.isSecret).length,
    [bulkParsed],
  );

  const filledChecklistEntries = useMemo(() => {
    if (!envRequest) return [];
    return envRequest.keys
      .map((item) => ({
        key: item.key,
        value: checklistValues[item.key] ?? "",
        isSecret: item.isSecret,
      }))
      .filter((item) => item.value.length > 0);
  }, [envRequest, checklistValues]);

  const checklistHasBuildTime = useMemo(() => {
    if (!envRequest) return false;
    return (
      envRequest.rebuildAfterSave ||
      filledChecklistEntries.some((item) => isBuildTimePublicEnvKey(item.key))
    );
  }, [envRequest, filledChecklistEntries]);

  const handleFileImport = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === "string") {
        setBulkText(reader.result);
        setEntryMode("bulk");
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  const handleBulkSave = async (rebuild: boolean) => {
    if (bulkParsed.vars.length === 0 || bulkParsed.errors.length > 0) return;
    const saved = await onSaveVars(
      bulkParsed.vars.map((v) => ({
        key: v.key,
        value: v.value,
        isSecret: v.isSecret,
      })),
      { rebuild },
    );
    if (saved) {
      setBulkText("");
    }
  };

  const handleSingleSave = async (e: React.FormEvent, rebuild = false) => {
    e.preventDefault();
    const key = singleKey.trim();
    if (!key) return;
    const saved = await onSaveVars(
      [
        {
          key,
          value: singleVal,
          isSecret: isLikelySecretEnvKey(key),
        },
      ],
      { rebuild },
    );
    if (saved) {
      setSingleKey("");
      setSingleVal("");
      setShowSingleVal(false);
    }
  };

  const handleChecklistAutoFill = () => {
    if (!envRequest) return;
    const parsed = parseEnvBlock(checklistPasteText);
    if (parsed.vars.length === 0) {
      setChecklistPasteNote("No KEY=value pairs found in pasted text.");
      return;
    }
    const next = { ...checklistValues };
    let matched = 0;
    const unmatched: string[] = [];
    for (const entry of parsed.vars) {
      if (requestedKeySet.has(entry.key)) {
        next[entry.key] = entry.value;
        matched += 1;
      } else {
        unmatched.push(entry.key);
      }
    }
    setChecklistValues(next);
    setChecklistPasteText("");
    setShowChecklistPaste(false);
    setChecklistPasteNote(
      unmatched.length > 0
        ? `Filled ${matched} requested field${matched === 1 ? "" : "s"}. (${unmatched.length} extra key${unmatched.length === 1 ? "" : "s"} not in this checklist — use Bulk paste below if you also want to save them.)`
        : `Filled ${matched} requested field${matched === 1 ? "" : "s"}. Review and click Save below.`,
    );
  };

  const handleChecklistSave = async (rebuild: boolean) => {
    if (filledChecklistEntries.length === 0) return;
    const saved = await onSaveVars(filledChecklistEntries, { rebuild });
    if (saved) {
      setChecklistValues({});
      setChecklistPasteNote(null);
    }
  };

  const handleFillMissingInBulk = () => {
    setBulkText((prev) => appendMissingKeysToEnvDraft(prev, visibleMissingKeys));
    setEntryMode("bulk");
  };

  const isGitApp = app.sourceType === "git";
  const singleIsBuildTime =
    singleKey.trim().length > 0 && isBuildTimePublicEnvKey(singleKey.trim());

  return (
    <div className="space-y-4">
      {envNeedsRebuild && isGitApp && (
        <div className="rounded-lg border border-warn-line bg-warn-soft px-4 py-3 text-xs text-warn flex flex-wrap items-center justify-between gap-3">
          <span>
            Build-time variable
            {changedBuildTimeKeys.length === 1 ? "" : "s"} updated
            {changedBuildTimeKeys.length > 0
              ? ` (${changedBuildTimeKeys.slice(0, 4).join(", ")}${changedBuildTimeKeys.length > 4 ? ", …" : ""})`
              : ""}
            . Rebuild this app so the new values are baked into the frontend
            bundle.
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={busy}
              onClick={() => {
                onClearRebuildBanner();
                void onRebuild();
              }}
              className="btn-press rounded-md bg-warn px-3 py-1.5 text-xs font-medium text-on-warn hover:opacity-90 cursor-pointer disabled:opacity-50"
            >
              Rebuild now
            </button>
            <button
              type="button"
              onClick={onClearRebuildBanner}
              className="text-warn/80 hover:text-warn cursor-pointer p-1"
              aria-label="Dismiss rebuild reminder"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      )}

      {envRequest && envRequest.keys.length > 0 && (
        <div className="rounded-xl border border-accent-line bg-accent-soft/40 p-4 space-y-3.5">
          <div className="flex items-start justify-between gap-3">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-accent shrink-0" />
                <h3 className="text-xs font-semibold text-fg">
                  Variables requested by {envRequest.requestedBy} (
                  {envRequest.keys.length})
                </h3>
              </div>
              {envRequest.note && (
                <p className="text-xs text-muted">{envRequest.note}</p>
              )}
              <p className="text-[11px] text-subtle">
                Values entered here are encrypted directly on your server and
                never sent back to chat.
              </p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => setShowChecklistPaste((v) => !v)}
                className="btn-press rounded-md border border-line bg-canvas px-2.5 py-1 text-[11px] font-medium text-fg hover:bg-surface-2 cursor-pointer"
              >
                {showChecklistPaste ? "Hide paste" : "Paste .env to auto-fill"}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => void onDismissRequest()}
                className="btn-press rounded-md px-2 py-1 text-[11px] text-subtle hover:text-fg cursor-pointer"
              >
                Dismiss
              </button>
            </div>
          </div>

          {showChecklistPaste && (
            <div className="rounded-lg border border-line bg-canvas p-3 space-y-2">
              <textarea
                rows={4}
                value={checklistPasteText}
                onChange={(e) => setChecklistPasteText(e.target.value)}
                placeholder={"Paste KEY=value lines here to auto-fill matching rows above..."}
                className="field-input w-full rounded-lg px-3 py-2 text-xs font-mono"
              />
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={handleChecklistAutoFill}
                  disabled={!checklistPasteText.trim()}
                  className="btn-press rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-on-primary hover:bg-primary-hover cursor-pointer disabled:opacity-50"
                >
                  Fill matching fields
                </button>
              </div>
            </div>
          )}

          {checklistPasteNote && (
            <p className="text-[11px] text-muted">{checklistPasteNote}</p>
          )}

          <div className="space-y-2.5">
            {envRequest.keys.map((item) => {
              const isBuildTime = isBuildTimePublicEnvKey(item.key);
              const isRevealed = Boolean(revealedKeys[item.key]);
              const alreadySet = existingKeySet.has(item.key);
              return (
                <div
                  key={item.key}
                  className="rounded-lg border border-line bg-canvas p-3 space-y-1.5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <label
                        htmlFor={`req-env-${item.key}`}
                        className="text-xs font-mono font-medium text-fg"
                      >
                        {item.key}
                      </label>
                      {isBuildTime && (
                        <span className="rounded bg-warn-soft px-1.5 py-0.5 text-[10px] font-medium text-warn">
                          Build-time
                        </span>
                      )}
                      {item.isSecret && (
                        <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] text-subtle">
                          Secret
                        </span>
                      )}
                      {!item.required && (
                        <span className="text-[10px] text-subtle">
                          (optional)
                        </span>
                      )}
                      {alreadySet && (
                        <span className="text-[10px] text-ok">
                          Already saved — enter a new value to overwrite
                        </span>
                      )}
                    </div>
                  </div>
                  {item.description && (
                    <p className="text-[11px] text-subtle">{item.description}</p>
                  )}
                  <div className="relative flex items-center">
                    <input
                      id={`req-env-${item.key}`}
                      type={
                        item.isSecret && !isRevealed ? "password" : "text"
                      }
                      value={checklistValues[item.key] ?? ""}
                      onChange={(e) =>
                        setChecklistValues((prev) => ({
                          ...prev,
                          [item.key]: e.target.value,
                        }))
                      }
                      placeholder={
                        alreadySet
                          ? "Leave blank to keep existing value"
                          : item.isSecret
                            ? "Paste secret value (encrypted at rest)"
                            : "Enter value"
                      }
                      autoComplete="off"
                      className="field-input w-full rounded-lg px-3 py-1.5 pr-9 text-xs font-mono"
                    />
                    {item.isSecret && (
                      <button
                        type="button"
                        onClick={() =>
                          setRevealedKeys((prev) => ({
                            ...prev,
                            [item.key]: !prev[item.key],
                          }))
                        }
                        className="absolute right-2.5 text-subtle hover:text-fg cursor-pointer"
                        aria-label={isRevealed ? "Hide value" : "Show value"}
                      >
                        {isRevealed ? (
                          <EyeOff className="h-3.5 w-3.5" />
                        ) : (
                          <Eye className="h-3.5 w-3.5" />
                        )}
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
            <span className="text-[11px] text-subtle">
              {filledChecklistEntries.length} of {envRequest.keys.length} filled
            </span>
            <div className="flex flex-wrap items-center gap-2">
              {isGitApp && checklistHasBuildTime ? (
                <>
                  <button
                    type="button"
                    disabled={busy || filledChecklistEntries.length === 0}
                    onClick={() => void handleChecklistSave(false)}
                    className="btn-press rounded-lg border border-line bg-canvas px-3 py-1.5 text-xs font-medium text-fg hover:bg-surface-2 cursor-pointer disabled:opacity-50"
                  >
                    Save only
                  </button>
                  <button
                    type="button"
                    disabled={busy || filledChecklistEntries.length === 0}
                    onClick={() => void handleChecklistSave(true)}
                    className="btn-press rounded-lg bg-primary px-3.5 py-1.5 text-xs font-medium text-on-primary hover:bg-primary-hover cursor-pointer disabled:opacity-50"
                  >
                    Save {filledChecklistEntries.length || ""} &amp; Rebuild
                  </button>
                </>
              ) : (
                <button
                  type="button"
                  disabled={busy || filledChecklistEntries.length === 0}
                  onClick={() => void handleChecklistSave(false)}
                  className="btn-press rounded-lg bg-primary px-3.5 py-1.5 text-xs font-medium text-on-primary hover:bg-primary-hover cursor-pointer disabled:opacity-50"
                >
                  Save {filledChecklistEntries.length || ""} setting
                  {filledChecklistEntries.length === 1 ? "" : "s"}
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {visibleMissingKeys.length > 0 && (
        <div className="rounded-lg border border-warn-line bg-warn-soft p-3.5 space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs font-medium text-warn">
              Suggested settings from this repo&rsquo;s{" "}
              <code>.env.example</code>:
            </p>
            <button
              type="button"
              onClick={handleFillMissingInBulk}
              className="btn-press rounded-md border border-warn-line bg-canvas px-2.5 py-1 text-[11px] font-medium text-warn hover:bg-warn-soft cursor-pointer"
            >
              Add all {visibleMissingKeys.length} to bulk editor
            </button>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {visibleMissingKeys.map((key) => (
              <button
                key={key}
                type="button"
                onClick={() => {
                  setSingleKey(key);
                  setEntryMode("single");
                }}
                className="btn-press rounded-md border border-warn-line bg-canvas px-2.5 py-1 text-xs font-mono text-warn hover:bg-warn-soft cursor-pointer"
              >
                + {key}
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="rounded-xl border border-line bg-canvas p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="inline-flex rounded-lg border border-line bg-surface-1 p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setEntryMode("bulk")}
              className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1 font-medium cursor-pointer transition-colors ${
                entryMode === "bulk"
                  ? "bg-canvas text-fg shadow-xs"
                  : "text-subtle hover:text-fg"
              }`}
            >
              <Layers className="h-3.5 w-3.5" />
              Bulk paste (.env)
            </button>
            <button
              type="button"
              onClick={() => setEntryMode("single")}
              className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1 font-medium cursor-pointer transition-colors ${
                entryMode === "single"
                  ? "bg-canvas text-fg shadow-xs"
                  : "text-subtle hover:text-fg"
              }`}
            >
              <Plus className="h-3.5 w-3.5" />
              Add one
            </button>
          </div>

          {entryMode === "bulk" && (
            <div>
              <input
                ref={fileInputRef}
                type="file"
                accept=".env,.env.local,.env.production,text/plain,.txt"
                onChange={handleFileImport}
                className="hidden"
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="btn-press inline-flex items-center gap-1.5 rounded-md border border-line bg-surface-1 px-2.5 py-1 text-xs text-muted hover:text-fg cursor-pointer"
              >
                <FileUp className="h-3.5 w-3.5" />
                Import .env file
              </button>
            </div>
          )}
        </div>

        {entryMode === "bulk" ? (
          <div className="space-y-3">
            <textarea
              rows={6}
              value={bulkText}
              onChange={(e) => setBulkText(e.target.value)}
              placeholder={[
                "# Paste multiple settings in standard .env format:",
                "NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co",
                "NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...",
                "SUPABASE_SERVICE_ROLE_KEY=eyJ...",
                "POLAR_ACCESS_TOKEN=polar_oat_...",
              ].join("\n")}
              spellCheck={false}
              className="field-input w-full rounded-lg px-3 py-2.5 text-xs font-mono leading-relaxed"
            />

            {bulkParsed.errors.length > 0 && (
              <div className="rounded-lg border border-bad-line bg-bad-soft px-3 py-2 text-xs text-bad space-y-0.5">
                {bulkParsed.errors.slice(0, 4).map((err) => (
                  <p key={err.line}>{err.message}</p>
                ))}
                {bulkParsed.errors.length > 4 && (
                  <p>
                    …and {bulkParsed.errors.length - 4} more formatting issue
                    {bulkParsed.errors.length - 4 === 1 ? "" : "s"}.
                  </p>
                )}
              </div>
            )}

            {bulkParsed.vars.length > 0 && (
              <div className="space-y-2">
                <p className="text-[11px] text-muted">
                  Ready to save{" "}
                  <strong className="text-fg">
                    {bulkParsed.vars.length} setting
                    {bulkParsed.vars.length === 1 ? "" : "s"}
                  </strong>
                  {bulkSecretCount > 0 ? ` · ${bulkSecretCount} secret${bulkSecretCount === 1 ? "" : "s"}` : ""}
                  {bulkBuildTimeKeys.length > 0
                    ? ` · ${bulkBuildTimeKeys.length} build-time public (baked on rebuild)`
                    : ""}
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {bulkParsed.vars.slice(0, 12).map((entry) => (
                    <span
                      key={entry.key}
                      className="inline-flex items-center gap-1 rounded border border-line bg-surface-1 px-2 py-0.5 text-[11px] font-mono text-fg"
                    >
                      {entry.key}
                      {entry.isBuildTime && (
                        <span className="text-[9px] font-sans font-medium text-warn">
                          build
                        </span>
                      )}
                    </span>
                  ))}
                  {bulkParsed.vars.length > 12 && (
                    <span className="text-[11px] text-subtle px-1 py-0.5">
                      +{bulkParsed.vars.length - 12} more
                    </span>
                  )}
                </div>
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-[11px] text-subtle">
                All values are encrypted at rest. Public{" "}
                <code>NEXT_PUBLIC_*</code> and <code>VITE_*</code> vars are
                automatically passed into Docker builds.
              </p>
              <div className="flex flex-wrap items-center gap-2">
                {isGitApp && bulkBuildTimeKeys.length > 0 ? (
                  <>
                    <button
                      type="button"
                      disabled={
                        busy ||
                        bulkParsed.vars.length === 0 ||
                        bulkParsed.errors.length > 0
                      }
                      onClick={() => void handleBulkSave(false)}
                      className="btn-press rounded-lg border border-line bg-canvas px-3 py-2 text-xs font-medium text-fg hover:bg-surface-2 cursor-pointer disabled:opacity-50"
                    >
                      Save only
                    </button>
                    <button
                      type="button"
                      disabled={
                        busy ||
                        bulkParsed.vars.length === 0 ||
                        bulkParsed.errors.length > 0
                      }
                      onClick={() => void handleBulkSave(true)}
                      className="btn-press rounded-lg bg-primary px-4 py-2 text-xs font-medium text-on-primary hover:bg-primary-hover cursor-pointer disabled:opacity-50"
                    >
                      Save {bulkParsed.vars.length} &amp; Rebuild
                    </button>
                  </>
                ) : (
                  <button
                    type="button"
                    disabled={
                      busy ||
                      bulkParsed.vars.length === 0 ||
                      bulkParsed.errors.length > 0
                    }
                    onClick={() => void handleBulkSave(false)}
                    className="btn-press rounded-lg bg-primary px-4 py-2 text-xs font-medium text-on-primary hover:bg-primary-hover cursor-pointer disabled:opacity-50"
                  >
                    Save {bulkParsed.vars.length || ""} setting
                    {bulkParsed.vars.length === 1 ? "" : "s"}
                  </button>
                )}
              </div>
            </div>
          </div>
        ) : (
          <form
            onSubmit={(e) => void handleSingleSave(e, false)}
            className="flex flex-wrap gap-2"
          >
            <input
              type="text"
              value={singleKey}
              onChange={(e) => setSingleKey(e.target.value)}
              placeholder="SETTING_NAME"
              required
              className="field-input rounded-lg px-3 py-2 text-xs font-mono"
            />
            <div className="relative flex-1 min-w-[200px]">
              <input
                type={
                  showSingleVal || singleIsBuildTime ? "text" : "password"
                }
                value={singleVal}
                onChange={(e) => setSingleVal(e.target.value)}
                placeholder="Value (encrypted at rest)"
                required
                className="field-input w-full rounded-lg px-3 py-2 pr-9 text-xs font-mono"
              />
              {!singleIsBuildTime && (
                <button
                  type="button"
                  onClick={() => setShowSingleVal((v) => !v)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-subtle hover:text-fg cursor-pointer"
                  aria-label={showSingleVal ? "Hide value" : "Show value"}
                >
                  {showSingleVal ? (
                    <EyeOff className="h-3.5 w-3.5" />
                  ) : (
                    <Eye className="h-3.5 w-3.5" />
                  )}
                </button>
              )}
            </div>
            <button
              type="submit"
              disabled={busy}
              className="btn-press rounded-lg bg-primary px-4 py-2 text-xs font-medium text-on-primary hover:bg-primary-hover cursor-pointer disabled:opacity-50"
            >
              Save setting
            </button>
            {isGitApp && singleIsBuildTime && (
              <button
                type="button"
                disabled={busy || !singleKey.trim() || !singleVal}
                onClick={(e) => void handleSingleSave(e, true)}
                className="btn-press rounded-lg border border-line bg-surface-1 px-3 py-2 text-xs font-medium text-fg hover:bg-surface-2 cursor-pointer disabled:opacity-50"
              >
                Save &amp; Rebuild
              </button>
            )}
          </form>
        )}
      </div>

      <div className="divide-y divide-line rounded-lg border border-line bg-canvas">
        {envVars.length === 0 ? (
          <p className="p-3.5 text-xs text-subtle">No saved settings yet.</p>
        ) : (
          envVars.map((entry) => {
            const isBuildTime = isBuildTimePublicEnvKey(entry.key);
            return (
              <div
                key={entry.key}
                className="flex items-center justify-between gap-3 px-3.5 py-2.5 text-xs"
              >
                <div className="min-w-0 [overflow-wrap:anywhere] flex flex-wrap items-center gap-2">
                  <span className="font-mono text-fg">{entry.key}</span>
                  {isBuildTime && (
                    <span className="rounded bg-warn-soft px-1.5 py-0.5 text-[10px] font-medium text-warn">
                      Build-time
                    </span>
                  )}
                  <span className="font-mono text-subtle">
                    {entry.maskedValue}
                  </span>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <button
                    type="button"
                    onClick={() => {
                      setSingleKey(entry.key);
                      setSingleVal("");
                      setEntryMode("single");
                    }}
                    className="btn-press text-muted hover:text-fg cursor-pointer"
                  >
                    Update
                  </button>
                  <button
                    type="button"
                    onClick={() => void onDeleteVar(entry.key)}
                    className="btn-press text-bad hover:text-bad cursor-pointer"
                  >
                    Remove
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
