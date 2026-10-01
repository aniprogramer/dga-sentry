import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { TestDomainSampler, BENIGN_DOMAINS, DGA_DOMAINS } from "../src/utils/testDomainPool";
import QuickTestResults from "../src/components/QuickTestResults";
import type { PredictionResult } from "../src/api/client";

describe("TestDomainSampler", () => {
  let sampler: TestDomainSampler;

  beforeEach(() => {
    sampler = new TestDomainSampler();
  });

  it("samples the requested number of domains (default 6)", () => {
    const { domains, remainingPoolSize } = sampler.sample(6);
    expect(domains).toHaveLength(6);
    expect(remainingPoolSize).toBe(sampler.getTotalPoolSize() - 6);
    expect(sampler.getUsedCount()).toBe(6);
  });

  it("contains unique domains within a single batch", () => {
    const { domains } = sampler.sample(6);
    const uniqueDomains = new Set(domains);
    expect(uniqueDomains.size).toBe(6);
  });

  it("samples balanced mix of benign and DGA domains", () => {
    const { domains } = sampler.sample(6);
    const benignCount = domains.filter((d) => BENIGN_DOMAINS.includes(d)).length;
    const dgaCount = domains.filter((d) => DGA_DOMAINS.includes(d)).length;

    expect(benignCount).toBe(3);
    expect(dgaCount).toBe(3);
  });

  it("guarantees non-repetition across consecutive sample calls", () => {
    const run1 = sampler.sample(6);
    const run2 = sampler.sample(6);
    const run3 = sampler.sample(6);

    const set1 = new Set(run1.domains);
    const set2 = new Set(run2.domains);
    const set3 = new Set(run3.domains);

    // Verify disjoint sets
    for (const d of run2.domains) {
      expect(set1.has(d)).toBe(false);
    }
    for (const d of run3.domains) {
      expect(set1.has(d)).toBe(false);
      expect(set2.has(d)).toBe(false);
    }

    expect(sampler.getUsedCount()).toBe(18);
  });

  it("resets tracking manually via reset()", () => {
    sampler.sample(6);
    expect(sampler.getUsedCount()).toBe(6);
    sampler.reset();
    expect(sampler.getUsedCount()).toBe(0);
  });

  it("gracefully resets when the domain pool is exhausted", () => {
    // Total pool size is > 120
    const total = sampler.getTotalPoolSize();
    expect(total).toBeGreaterThanOrEqual(120);

    // Exhaust benign pool by repeated sampling
    // Math.ceil(BENIGN_DOMAINS.length / 3) iterations will consume all benign domains
    const iterations = Math.ceil(BENIGN_DOMAINS.length / 3) + 2;
    for (let i = 0; i < iterations; i++) {
      const result = sampler.sample(6);
      expect(result.domains).toHaveLength(6);
    }

    // After exhaustion, it resets gracefully without throwing errors
    const postReset = sampler.sample(6);
    expect(postReset.domains).toHaveLength(6);
  });
});

describe("QuickTestResults Component", () => {
  const mockOnClose = vi.fn();
  const mockOnSelectDomain = vi.fn();

  const sampleResults: PredictionResult[] = [
    {
      domain: "google.com",
      label: "legitimate",
      risk_tier: "safe",
      action: "allow",
      malicious_probability: 0.02,
      confidence: 0.98,
      family: "legitimate",
      family_confidence: 0.99,
      features: { length: 10, entropy: 2.1 },
    },
    {
      domain: "vbwjjqevqgyl.org",
      label: "malicious",
      risk_tier: "malicious",
      action: "block",
      malicious_probability: 0.96,
      confidence: 0.96,
      family: "emotet",
      family_confidence: 0.91,
      features: { length: 16, entropy: 3.8 },
    },
    {
      domain: "suspicious-rnd-string.biz",
      label: "malicious",
      risk_tier: "suspicious",
      action: "monitor",
      malicious_probability: 0.65,
      confidence: 0.65,
      family: "conficker",
      family_confidence: 0.75,
      features: { length: 25, entropy: 3.4 },
    },
  ];

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders loading state spinner and indicator", () => {
    render(
      <QuickTestResults
        results={[]}
        isLoading={true}
        onClose={mockOnClose}
        onSelectDomain={mockOnSelectDomain}
      />,
    );

    expect(
      screen.getByText(/EXECUTING VECTORIZED BATCH TEST/i),
    ).toBeDefined();
  });

  it("returns null if results are empty and not loading", () => {
    const { container } = render(
      <QuickTestResults
        results={[]}
        isLoading={false}
        onClose={mockOnClose}
        onSelectDomain={mockOnSelectDomain}
      />,
    );

    expect(container.firstChild).toBeNull();
  });

  it("renders header and summary metrics", () => {
    render(
      <QuickTestResults
        results={sampleResults}
        isLoading={false}
        onClose={mockOnClose}
        onSelectDomain={mockOnSelectDomain}
      />,
    );

    expect(
      screen.getByText(/QUICK TEST AUDIT RESULTS \(3 DOMAINS TESTED\)/i),
    ).toBeDefined();
    expect(screen.getByText("1 OK (CLEAN)")).toBeDefined();
    expect(screen.getByText("2 NOT OK (DGA / THREAT)")).toBeDefined();
  });

  it("renders unambiguous OK and NOT OK verdicts with threat badges", () => {
    render(
      <QuickTestResults
        results={sampleResults}
        isLoading={false}
        onClose={mockOnClose}
        onSelectDomain={mockOnSelectDomain}
      />,
    );

    // Google row: OK verdict
    expect(screen.getByText("google.com")).toBeDefined();
    expect(screen.getByText("Legitimate / Clean")).toBeDefined();

    // Emotet row: NOT OK verdict
    expect(screen.getByText("vbwjjqevqgyl.org")).toBeDefined();
    expect(screen.getByText("[EMOTET]")).toBeDefined();
    expect(screen.getByText("Malicious DGA")).toBeDefined();

    // Suspicious row: NOT OK verdict
    expect(screen.getByText("suspicious-rnd-string.biz")).toBeDefined();
    expect(screen.getByText("[CONFICKER]")).toBeDefined();
    expect(screen.getByText("Suspicious DGA")).toBeDefined();
  });

  it("calls onSelectDomain when 'Inspect' button is clicked", () => {
    render(
      <QuickTestResults
        results={sampleResults}
        isLoading={false}
        onClose={mockOnClose}
        onSelectDomain={mockOnSelectDomain}
      />,
    );

    const inspectButtons = screen.getAllByRole("button", { name: /inspect/i });
    expect(inspectButtons).toHaveLength(3);

    fireEvent.click(inspectButtons[1]); // Inspect second domain (vbwjjqevqgyl.org)
    expect(mockOnSelectDomain).toHaveBeenCalledWith("vbwjjqevqgyl.org");
  });

  it("calls onClose when close button is clicked", () => {
    render(
      <QuickTestResults
        results={sampleResults}
        isLoading={false}
        onClose={mockOnClose}
        onSelectDomain={mockOnSelectDomain}
      />,
    );

    const closeBtn = screen.getByRole("button", { name: /close test results/i });
    fireEvent.click(closeBtn);
    expect(mockOnClose).toHaveBeenCalledTimes(1);
  });
});
