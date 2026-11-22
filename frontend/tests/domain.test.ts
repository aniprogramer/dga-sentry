import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { MESSAGES, normalizeAndValidate, parseBatch } from "../src/lib/domain";

interface Case {
  input: string;
  code: string | null;
  ascii?: string;
  display?: string;
  notes?: string[];
  warnings?: string[];
}
const cases: Case[] = JSON.parse(readFileSync(resolve(__dirname, "../../shared/domain_cases.json"), "utf-8"));
const LOCAL_WARNINGS = new Set(["UNDERSCORE", "HOMOGRAPH"]);

describe("domain.ts parity with shared fixture", () => {
  it.each(cases.map((c) => [JSON.stringify(c.input.slice(0, 40)), c] as const))("%s", (_n, c) => {
    const r = normalizeAndValidate(c.input);
    if (c.code) {
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.code).toBe(c.code);
        expect(r.message).toBe(MESSAGES[c.code]);
      }
      return;
    }
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.info.ascii).toBe(c.ascii);
      expect(r.info.display).toBe(c.display);
      expect(r.info.notes).toEqual(c.notes);
      expect(r.info.warnings).toEqual((c.warnings ?? []).filter((w) => LOCAL_WARNINGS.has(w)));
    }
  });
});

describe("parseBatch", () => {
  it("splits on commas/newlines/spaces and flags statuses", () => {
    const lines = parseBatch("google.com, Google.com.\nbad..com xn--mller-kva.de\nMüller.de");
    expect(lines.map((l) => l.status)).toEqual(["valid", "duplicate", "invalid", "valid", "duplicate"]);
    expect(lines[2].code).toBe("EMPTY_LABEL");
  });
});
