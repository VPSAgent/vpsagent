import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { describeTailscaleConflict } from "../src/tailscale-conflict.ts";

describe("describeTailscaleConflict", () => {
  it("returns null when no conflict exists", () => {
    assert.equal(
      describeTailscaleConflict({
        serveConflict: null,
        serveConflictDetails: null,
      }),
      null,
    );
  });

  it("distinguishes preserved Funnel siblings from removed /mcp and replaced / routes", () => {
    const described = describeTailscaleConflict({
      serveConflict:
        "public Funnel sibling routes (/status -> http://127.0.0.1:8080); replaced root route (/ -> http://127.0.0.1:9000); removed /mcp route (/mcp -> http://127.0.0.1:9001)",
      serveConflictDetails: {
        funnelActive: true,
        preservedFunnelSiblings: ["/status -> http://127.0.0.1:8080"],
        replacedRootRoute: "/ -> http://127.0.0.1:9000",
        removedMcpRoute: "/mcp -> http://127.0.0.1:9001",
      },
    });

    assert.ok(described);
    assert.equal(described.confirmButtonLabel, "Make private, replace / & remove /mcp");
    assert.equal(described.effects.length, 3);
    assert.deepEqual(
      described.effects.map((effect) => effect.kind),
      ["private", "replace", "remove"],
    );
    assert.match(described.effects[0]!.label, /stays reachable in Tailscale/i);
    assert.match(described.effects[0]!.routes, /\/status -> http:\/\/127\.0\.0\.1:8080/);
    assert.match(described.effects[1]!.label, /loses \/ even inside Tailscale/i);
    assert.match(described.effects[1]!.routes, /\/ -> http:\/\/127\.0\.0\.1:9000/);
    assert.match(described.effects[2]!.label, /loses \/mcp even inside Tailscale/i);
    assert.match(described.effects[2]!.routes, /\/mcp -> http:\/\/127\.0\.0\.1:9001/);
  });

  it("labels Funnel with preserved sibling + conflicting /mcp accurately", () => {
    const described = describeTailscaleConflict({
      serveConflict:
        "public Funnel sibling routes (/status -> http://127.0.0.1:8080); removed /mcp route (/mcp -> http://127.0.0.1:9001)",
      serveConflictDetails: {
        funnelActive: true,
        preservedFunnelSiblings: ["/status -> http://127.0.0.1:8080"],
        replacedRootRoute: null,
        removedMcpRoute: "/mcp -> http://127.0.0.1:9001",
      },
    });

    assert.ok(described);
    assert.equal(described.confirmButtonLabel, "Make private & remove /mcp");
    assert.deepEqual(
      described.effects.map((effect) => effect.kind),
      ["private", "remove"],
    );
  });

  it("falls back safely when serveConflictDetails is absent", () => {
    const described = describeTailscaleConflict({
      serveConflict: "public Funnel sibling routes (/status -> http://127.0.0.1:8080)",
      serveConflictDetails: null,
    });

    assert.ok(described);
    assert.equal(described.confirmButtonLabel, "Make port 443 private anyway");
    assert.equal(described.effects.length, 1);
  });
});
