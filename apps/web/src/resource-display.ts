export type ResourceDisplayMode = "bar" | "chart";

export interface ResourceSample {
  timestamp: string;
  cpu: number;
  memory: number;
  disk: number;
}

export const RESOURCE_DISPLAY_STORAGE_KEY = "vpsagent.resourceDisplay";
export const MAX_RESOURCE_SAMPLES = 24;

export function loadResourceDisplayMode(): ResourceDisplayMode {
  try {
    if (typeof window === "undefined") return "bar";
    const stored = window.localStorage.getItem(RESOURCE_DISPLAY_STORAGE_KEY);
    return stored === "chart" ? "chart" : "bar";
  } catch {
    return "bar";
  }
}

export function saveResourceDisplayMode(mode: ResourceDisplayMode): void {
  try {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(RESOURCE_DISPLAY_STORAGE_KEY, mode);
  } catch {
    // Ignore storage errors (e.g. private browsing restrictions).
  }
}

export function clampPercent(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(100, Math.max(0, Math.round(value)));
}

export function appendResourceSample(
  history: ResourceSample[],
  sample: ResourceSample,
  maxSamples = MAX_RESOURCE_SAMPLES,
): ResourceSample[] {
  const normalized: ResourceSample = {
    timestamp: sample.timestamp,
    cpu: clampPercent(sample.cpu),
    memory: clampPercent(sample.memory),
    disk: clampPercent(sample.disk),
  };

  const last = history[history.length - 1];
  if (last && last.timestamp === normalized.timestamp) {
    return [...history.slice(0, -1), normalized];
  }

  const next = [...history, normalized];
  return next.length > maxSamples ? next.slice(next.length - maxSamples) : next;
}

export interface ChartPoint {
  x: number;
  y: number;
  value: number;
}

export interface ChartGeometry {
  linePath: string;
  areaPath: string;
  points: ChartPoint[];
}

export function buildChartGeometry(
  values: number[],
  width: number,
  height: number,
  padding = 6,
): ChartGeometry {
  const innerWidth = Math.max(1, width - padding * 2);
  const innerHeight = Math.max(1, height - padding * 2);
  const bottomY = padding + innerHeight;

  const safeValues = values.length > 0 ? values.map(clampPercent) : [0];
  const valueToY = (v: number) =>
    Number((padding + innerHeight * (1 - v / 100)).toFixed(2));

  if (safeValues.length === 1) {
    const val = safeValues[0]!;
    const y = valueToY(val);
    const startX = Number(padding.toFixed(2));
    const endX = Number((padding + innerWidth).toFixed(2));
    return {
      linePath: `M ${startX} ${y} L ${endX} ${y}`,
      areaPath: `M ${startX} ${y} L ${endX} ${y} L ${endX} ${bottomY} L ${startX} ${bottomY} Z`,
      points: [{ x: endX, y, value: val }],
    };
  }

  const stepX = innerWidth / (safeValues.length - 1);
  const points: ChartPoint[] = safeValues.map((value, idx) => ({
    x: Number((padding + idx * stepX).toFixed(2)),
    y: valueToY(value),
    value,
  }));

  const linePath = points
    .map((pt, idx) => `${idx === 0 ? "M" : "L"} ${pt.x} ${pt.y}`)
    .join(" ");
  const first = points[0]!;
  const last = points[points.length - 1]!;
  const areaPath = `${linePath} L ${last.x} ${bottomY} L ${first.x} ${bottomY} Z`;

  return { linePath, areaPath, points };
}
