import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  appendResourceSample,
  buildChartGeometry,
  clampPercent,
  type ResourceSample,
} from "../src/resource-display.ts";

describe("Resource display helpers", () => {
  it("clamps percentages between 0 and 100", () => {
    assert.equal(clampPercent(-5), 0);
    assert.equal(clampPercent(42.6), 43);
    assert.equal(clampPercent(150), 100);
    assert.equal(clampPercent(Number.NaN), 0);
  });

  it("appends samples, deduplicates matching timestamps, and caps history", () => {
    let history: ResourceSample[] = [];
    history = appendResourceSample(
      history,
      { timestamp: "t1", cpu: 10, memory: 20, disk: 30 },
      3,
    );
    history = appendResourceSample(
      history,
      { timestamp: "t1", cpu: 15, memory: 25, disk: 30 },
      3,
    );
    assert.equal(history.length, 1);
    assert.equal(history[0]?.cpu, 15);

    history = appendResourceSample(
      history,
      { timestamp: "t2", cpu: 20, memory: 30, disk: 31 },
      3,
    );
    history = appendResourceSample(
      history,
      { timestamp: "t3", cpu: 30, memory: 35, disk: 32 },
      3,
    );
    history = appendResourceSample(
      history,
      { timestamp: "t4", cpu: 40, memory: 40, disk: 33 },
      3,
    );

    assert.equal(history.length, 3);
    assert.deepEqual(
      history.map((s) => s.timestamp),
      ["t2", "t3", "t4"],
    );
  });

  it("builds SVG chart geometry for single and multi-point series", () => {
    const single = buildChartGeometry([50], 200, 80, 10);
    assert.equal(single.points.length, 1);
    assert.equal(single.points[0]?.x, 190);
    assert.equal(single.points[0]?.y, 40);
    assert.match(single.linePath, /^M 10 40 L 190 40$/);

    const multi = buildChartGeometry([0, 50, 100], 200, 80, 10);
    assert.equal(multi.points.length, 3);
    assert.equal(multi.points[0]?.y, 70);
    assert.equal(multi.points[1]?.y, 40);
    assert.equal(multi.points[2]?.y, 10);
    assert.ok(multi.areaPath.endsWith("L 190 70 L 10 70 Z"));
  });
});
