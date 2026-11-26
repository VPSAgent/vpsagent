import type { TailscaleStatus } from "./api";

export interface TailscaleConflictEffect {
  kind: "private" | "replace" | "remove";
  label: string;
  routes: string;
  explanation: string;
}

export interface TailscaleConflictDescription {
  headline: string;
  effects: TailscaleConflictEffect[];
  confirmButtonLabel: string;
}

/**
 * Splits Tailscale port 443 conflicts into distinct per-route effects so owners
 * can see which sibling routes remain private vs. which `/` or `/mcp` routes
 * will be replaced or removed even inside the tailnet.
 */
export function describeTailscaleConflict(
  status: Pick<TailscaleStatus, "serveConflict" | "serveConflictDetails">,
): TailscaleConflictDescription | null {
  if (!status.serveConflict) {
    return null;
  }

  const details = status.serveConflictDetails;
  if (details) {
    const funnelActive = Boolean(details.funnelActive);
    const preserved = details.preservedFunnelSiblings;
    const replacedRoot = details.replacedRootRoute;
    const removedMcp = details.removedMcpRoute;
    const effects: TailscaleConflictEffect[] = [];

    if (funnelActive && preserved.length > 0) {
      effects.push({
        kind: "private",
        label: "Becomes private (stays reachable in Tailscale)",
        routes: preserved.join(", "),
        explanation:
          "Public Tailscale Funnel turns off across port 443, so these routes lose public internet access unless moved to another port.",
      });
    } else if (funnelActive) {
      effects.push({
        kind: "private",
        label: "Public Tailscale Funnel turned off",
        routes: "port 443",
        explanation:
          "Port 443 stops serving to the public internet and becomes private to your Tailscale network.",
      });
    }

    if (replacedRoot) {
      effects.push({
        kind: "replace",
        label: "Replaced by VPSAgent (loses / even inside Tailscale)",
        routes: replacedRoot,
        explanation:
          "VPSAgent takes over /, so this existing service stops working there even inside your Tailscale network.",
      });
    }

    if (removedMcp) {
      effects.push({
        kind: "remove",
        label: "Removed (loses /mcp even inside Tailscale)",
        routes: removedMcp,
        explanation:
          "This /mcp mount is deleted so VPSAgent's AI doorway works, so that service loses /mcp access even inside your Tailscale network.",
      });
    }

    if (effects.length > 0) {
      let confirmButtonLabel: string;
      if (funnelActive) {
        if (replacedRoot && removedMcp) {
          confirmButtonLabel = "Make private, replace / & remove /mcp";
        } else if (replacedRoot) {
          confirmButtonLabel = "Make private & replace /";
        } else if (removedMcp) {
          confirmButtonLabel = "Make private & remove /mcp";
        } else {
          confirmButtonLabel = "Make port 443 private anyway";
        }
      } else if (replacedRoot && removedMcp) {
        confirmButtonLabel = "Replace / & remove /mcp";
      } else if (removedMcp) {
        confirmButtonLabel = "Remove conflicting /mcp route";
      } else {
        confirmButtonLabel = "Replace port 443 / route with VPSAgent";
      }

      const headline = funnelActive
        ? replacedRoot || removedMcp
          ? "Port 443 currently runs public Tailscale Funnel and has conflicting routes. Turning on private HTTPS applies all of these changes:"
          : "Port 443 currently runs public Tailscale Funnel. Turning on private HTTPS switches the entire port 443 listener to private Tailscale access:"
        : "Tailscale Serve port 443 already has routes configured. Turning on private HTTPS for VPSAgent applies these changes:";

      return {
        headline,
        effects,
        confirmButtonLabel,
      };
    }
  }

  const isFunnelFallback = status.serveConflict.startsWith(
    "public Funnel sibling routes",
  );
  if (isFunnelFallback) {
    return {
      headline:
        "Port 443 currently runs public Tailscale Funnel. Turning on private HTTPS disables public Funnel across port 443 and may replace or remove conflicting / or /mcp routes:",
      effects: [
        {
          kind: "private",
          label: "Affected port 443 routes",
          routes: status.serveConflict,
          explanation:
            "Sibling paths become tailnet-only, while any conflicting / or /mcp route is replaced or removed even inside your Tailscale network.",
        },
      ],
      confirmButtonLabel: "Make port 443 private anyway",
    };
  }

  return {
    headline:
      "Tailscale Serve port 443 already has an existing route configured:",
    effects: [
      {
        kind: "replace",
        label: "Existing port 443 route",
        routes: status.serveConflict,
        explanation:
          "Enabling private HTTPS replaces or removes this conflicting route even inside your Tailscale network.",
      },
    ],
    confirmButtonLabel: "Replace port 443 route with VPSAgent",
  };
}
