import type { ReactNode } from "react";

/** Consistent page title block: title, one-line description, optional actions. */
export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-[-0.02em]">{title}</h1>
        {description && <p className="mt-1.5 text-sm text-muted">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

/** Small section heading used inside pages. */
export function SectionHeading({
  title,
  action,
}: {
  title: string;
  action?: ReactNode;
}) {
  return (
    <div className="mb-3 flex items-baseline justify-between gap-3">
      <h2 className="text-[15px] font-semibold">{title}</h2>
      {action}
    </div>
  );
}

export const buttonPrimary =
  "btn-press inline-flex items-center gap-1.5 rounded-md bg-primary px-3.5 py-2 text-[13px] font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer";

export const buttonSecondary =
  "btn-press inline-flex items-center gap-1.5 rounded-md border border-line-strong px-3.5 py-2 text-[13px] text-fg hover:bg-surface-2 disabled:opacity-50 cursor-pointer";
