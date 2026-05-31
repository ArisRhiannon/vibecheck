import { test, expect, describe } from "bun:test";
import { runBenchmark } from "../benchmark/run";

describe("benchmark (mass labeled corpus)", () => {
  const m = runBenchmark();
  test("every case matches its label (no FP/FN regressions)", () => {
    expect(m.failures).toEqual([]);
  });
  test("precision and recall stay high", () => {
    expect(m.total).toBeGreaterThanOrEqual(40);
    expect(m.precision).toBeGreaterThanOrEqual(0.95);
    expect(m.recall).toBeGreaterThanOrEqual(0.95);
  });
});
