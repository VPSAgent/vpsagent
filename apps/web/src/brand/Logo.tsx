import { getMark } from "./mark";

/** The pixel "V". Inherits colour from `currentColor`. */
export function LogoMark({
  size = 20,
  small,
  className,
}: {
  /** Rendered height in px. */
  size?: number;
  /** Use the 13×13 lattice version; defaults to it below 24px, where the mesh blurs. */
  small?: boolean;
  className?: string;
}) {
  const mark = getMark(small ?? size < 24);
  const width = (size * mark.width) / mark.height;
  return (
    <svg
      width={width}
      height={size}
      viewBox={`0 0 ${mark.width} ${mark.height}`}
      shapeRendering="crispEdges"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      {mark.rects.map((r, i) => (
        <rect
          key={i}
          x={r.x}
          y={r.y}
          width={r.w}
          height={r.h}
          fillOpacity={r.opacity < 1 ? r.opacity : undefined}
        />
      ))}
    </svg>
  );
}

/** Mark + "VPSAGENT" set in the brand face. */
export function Logo({
  markSize = 18,
  textClassName = "text-[17px]",
  className = "",
}: {
  markSize?: number;
  textClassName?: string;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-2 text-primary ${className}`}
      aria-label="VPSAgent"
      role="img"
    >
      <LogoMark size={markSize} />
      <span aria-hidden="true" className={`font-brand leading-none ${textClassName}`}>
        VPSAGENT
      </span>
    </span>
  );
}
