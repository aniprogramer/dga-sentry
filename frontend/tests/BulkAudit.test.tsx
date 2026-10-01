import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import BulkAudit from "../src/components/BulkAudit";
import {
  cleanDomainToken,
  extractDomainsFromText,
  extractDomainsFromCSV,
} from "../src/utils/domainExtractor";
import * as client from "../src/api/client";

// Mock the API client
vi.mock("../src/api/client", async () => {
  const actual = await vi.importActual<typeof import("../src/api/client")>(
    "../src/api/client",
  );
  return {
    ...actual,
    predictBatch: vi.fn(),
  };
});

describe("domainExtractor utilities", () => {
  describe("cleanDomainToken", () => {
    it("cleans standard domain strings", () => {
      expect(cleanDomainToken("google.com")).toBe("google.com");
      expect(cleanDomainToken("Sub.Domain.co.uk")).toBe("sub.domain.co.uk");
    });

    it("strips protocols, paths, queries and ports", () => {
      expect(cleanDomainToken("https://example.com/api/v1?test=1")).toBe(
        "example.com",
      );
      expect(cleanDomainToken("http://malware.biz:8080/c2")).toBe("malware.biz");
      expect(cleanDomainToken("ftp://files.org/#anchor")).toBe("files.org");
    });

    it("strips wrapping quotes, brackets, and trailing dots", () => {
      expect(cleanDomainToken('"safe-domain.net"')).toBe("safe-domain.net");
      expect(cleanDomainToken("<threat.cc>")).toBe("threat.cc");
      expect(cleanDomainToken("[badsite.xyz],")).toBe("badsite.xyz");
      expect(cleanDomainToken("dns.google.")).toBe("dns.google");
    });

    it("rejects IP addresses and malformed domains", () => {
      expect(cleanDomainToken("192.168.1.1")).toBeNull();
      expect(cleanDomainToken("localhost")).toBeNull();
      expect(cleanDomainToken("-invalid.com")).toBeNull();
      expect(cleanDomainToken("invalid-.com")).toBeNull();
      expect(cleanDomainToken("")).toBeNull();
      expect(cleanDomainToken("no_dots")).toBeNull();
    });
  });

  describe("extractDomainsFromText", () => {
    it("extracts unique valid domains from multiline text and logs", () => {
      const log = `
        192.168.1.50 8.8.8.8 google.com 443
        192.168.1.50 8.8.8.8 GOOGLE.COM 443
        192.168.1.51 8.8.8.8 evil-c2-server.ru 80
        invalid_token 10.0.0.1
        https://cdn.cloudflare.net/static
      `;
      const domains = extractDomainsFromText(log);
      expect(domains).toEqual(["google.com", "evil-c2-server.ru", "cdn.cloudflare.net"]);
    });
  });

  describe("extractDomainsFromCSV", () => {
    it("extracts domains from CSV using detected domain header", () => {
      const csv = `timestamp,query,client_ip\n2026-09-26,google.com,10.0.0.1\n2026-09-26,matsnu-concatenated.biz,10.0.0.2`;
      const domains = extractDomainsFromCSV(csv);
      expect(domains).toEqual(["google.com", "matsnu-concatenated.biz"]);
    });

    it("falls back to text scanning when no header matches", () => {
      const csv = `val1,val2\nsome_text,fallback-domain.org\nother,another-site.com`;
      const domains = extractDomainsFromCSV(csv);
      expect(domains).toEqual(["fallback-domain.org", "another-site.com"]);
    });
  });
});

describe("BulkAudit Component", () => {
  const dummyFeatures = {
    length: 10,
    entropy: 2.5,
    vowel_consonant_ratio: 0.5,
    digit_ratio: 0,
    hex_char_ratio: 0.2,
    gini_index: 0.8,
    max_consonant_run: 2,
    digit_first: 0,
    n_gram_score: -2.3,
    unique_char_ratio: 0.7,
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders upload mode by default and allows switching to text paste mode", () => {
    render(<BulkAudit />);

    expect(screen.getByText("Bulk DNS Log & Telemetry Audit")).toBeDefined();
    expect(screen.getByText(/Drop DNS log or CSV file here/i)).toBeDefined();

    // Switch to Text Mode
    const pasteTab = screen.getByText("Paste Raw Text / Domains");
    fireEvent.click(pasteTab);

    expect(
      screen.getByPlaceholderText(/Paste domain names, URLs, or query logs/i),
    ).toBeDefined();
  });

  it("loads sample DNS log and parses domains", () => {
    render(<BulkAudit />);

    const loadSampleBtn = screen.getByText("Load Sample DNS Log");
    fireEvent.click(loadSampleBtn);

    // Should switch to text mode and display extracted count badge
    expect(screen.getByText(/10 unique domains detected/i)).toBeDefined();
    expect(screen.getByText(/Ready to audit:/i)).toBeDefined();

    const runBtn = screen.getByRole("button", { name: /Run Audit/i });
    expect(runBtn.getAttribute("disabled")).toBeNull();
  });

  it("clears input when Clear button is clicked", () => {
    render(<BulkAudit />);

    const loadSampleBtn = screen.getByText("Load Sample DNS Log");
    fireEvent.click(loadSampleBtn);
    expect(screen.getByText(/10 unique domains detected/i)).toBeDefined();

    const clearBtn = screen.getByRole("button", { name: "Clear" });
    fireEvent.click(clearBtn);

    expect(screen.queryByText(/10 unique domains detected/i)).toBeNull();
    const runBtn = screen.getByRole("button", { name: /Run Audit/i });
    expect(runBtn.getAttribute("disabled")).not.toBeNull();
  });

  it("executes batch audit and renders metrics summary and interactive table", async () => {
    const mockPredictions: client.PredictionResult[] = [
      {
        domain: "google.com",
        label: "legitimate",
        confidence: 0.98,
        malicious_probability: 0.02,
        risk_tier: "safe",
        action: "allow",
        features: dummyFeatures,
        family: "legitimate",
        family_confidence: 0.99,
        top_risk_factors: [
          {
            feature: "entropy",
            display_name: "Shannon Entropy",
            impact: 0.05,
            value: 2.1,
          },
        ],
      },
      {
        domain: "evil-c2.biz",
        label: "malicious",
        confidence: 0.95,
        malicious_probability: 0.95,
        risk_tier: "malicious",
        action: "block",
        features: dummyFeatures,
        family: "emotet",
        family_confidence: 0.88,
        top_risk_factors: [
          {
            feature: "entropy",
            display_name: "Shannon Entropy",
            impact: 0.65,
            value: 3.8,
          },
        ],
      },
      {
        domain: "borderline-site.net",
        label: "malicious",
        confidence: 0.55,
        malicious_probability: 0.55,
        risk_tier: "suspicious",
        action: "monitor",
        features: dummyFeatures,
        family: "suppobox",
        family_confidence: 0.62,
        top_risk_factors: [
          {
            feature: "length",
            display_name: "Domain Length",
            impact: 0.25,
            value: 19.0,
          },
        ],
      },
    ];

    vi.mocked(client.predictBatch).mockResolvedValueOnce({
      total: 3,
      predictions: mockPredictions,
    });

    render(<BulkAudit />);

    // Switch to paste mode and enter domains
    fireEvent.click(screen.getByText("Paste Raw Text / Domains"));
    const textarea = screen.getByPlaceholderText(
      /Paste domain names, URLs, or query logs/i,
    );
    fireEvent.change(textarea, {
      target: { value: "google.com\nevil-c2.biz\nborderline-site.net" },
    });

    const runBtn = screen.getByRole("button", { name: /Run Audit/i });
    fireEvent.click(runBtn);

    // Wait for audit results to populate
    await waitFor(() => {
      expect(screen.getByText("Total Audited")).toBeDefined();
    });

    // Check Executive Metrics Cards
    expect(screen.getByText("Total Audited")).toBeDefined();
    expect(screen.getByText("Safe (Allow)")).toBeDefined();
    expect(screen.getByText("Suspicious (Monitor)")).toBeDefined();
    expect(screen.getByText("Malicious (Block)")).toBeDefined();

    // Check that family breakdown is shown
    expect(screen.getByText("Detected Threat Families")).toBeDefined();
    expect(screen.getAllByText("emotet").length).toBeGreaterThan(0);
    expect(screen.getAllByText("suppobox").length).toBeGreaterThan(0);

    // Check table rows
    expect(screen.getByText("google.com")).toBeDefined();
    expect(screen.getByText("evil-c2.biz")).toBeDefined();
    expect(screen.getByText("borderline-site.net")).toBeDefined();

    // Test tier filtering
    const safeFilterBtn = screen.getByRole("button", { name: /^Safe \(1\)/i });
    fireEvent.click(safeFilterBtn);
    expect(screen.getByText("google.com")).toBeDefined();
    expect(screen.queryByText("evil-c2.biz")).toBeNull();

    // Reset filter
    const allFilterBtn = screen.getByRole("button", { name: /^All \(3\)/i });
    fireEvent.click(allFilterBtn);
    expect(screen.getByText("evil-c2.biz")).toBeDefined();

    // Test domain search input
    const searchInput = screen.getByPlaceholderText(/Search domain.../i);
    fireEvent.change(searchInput, { target: { value: "evil" } });
    expect(screen.getByText("evil-c2.biz")).toBeDefined();
    expect(screen.queryByText("google.com")).toBeNull();

    // Clear search
    fireEvent.change(searchInput, { target: { value: "" } });
    expect(screen.getByText("google.com")).toBeDefined();

    // Test row expansion for TreeSHAP
    const expandRowBtn = screen.getAllByRole("button", {
      name: "Toggle feature attributions",
    })[0];
    fireEvent.click(expandRowBtn);
    expect(
      screen.getByText(/Top Risk Drivers \(TreeSHAP Positive Marginal Attributions\)/i),
    ).toBeDefined();
  });

  it("handles CSV export trigger safely", async () => {
    const mockPredictions: client.PredictionResult[] = [
      {
        domain: "safe.org",
        label: "legitimate",
        confidence: 0.99,
        malicious_probability: 0.01,
        risk_tier: "safe",
        action: "allow",
        features: dummyFeatures,
        family: "legitimate",
        family_confidence: null,
        top_risk_factors: [],
      },
    ];

    vi.mocked(client.predictBatch).mockResolvedValueOnce({
      total: 1,
      predictions: mockPredictions,
    });

    // Mock URL.createObjectURL and URL.revokeObjectURL
    const createObjectUrlMock = vi.fn().mockReturnValue("blob:http://localhost/test");
    const revokeObjectUrlMock = vi.fn();
    window.URL.createObjectURL = createObjectUrlMock;
    window.URL.revokeObjectURL = revokeObjectUrlMock;

    render(<BulkAudit />);

    fireEvent.click(screen.getByText("Paste Raw Text / Domains"));
    const textarea = screen.getByPlaceholderText(
      /Paste domain names, URLs, or query logs/i,
    );
    fireEvent.change(textarea, { target: { value: "safe.org" } });

    const runBtn = screen.getByRole("button", { name: /Run Audit/i });
    fireEvent.click(runBtn);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /Export CSV/i })).toBeDefined();
    });

    const exportBtn = screen.getByRole("button", { name: /Export CSV/i });
    fireEvent.click(exportBtn);

    expect(createObjectUrlMock).toHaveBeenCalled();
    expect(revokeObjectUrlMock).toHaveBeenCalled();
  });

  it("passes resolveDns=true when Live DNS checkbox is checked and renders DNS badge", async () => {
    const mockPredictions: client.PredictionResult[] = [
      {
        domain: "c2-domain.biz",
        label: "malicious",
        confidence: 0.97,
        malicious_probability: 0.97,
        risk_tier: "malicious",
        action: "block",
        features: dummyFeatures,
        family: "emotet",
        family_confidence: 0.85,
        top_risk_factors: [],
        dns_enrichment: {
          resolved: true,
          operational_status: "active",
          ip_addresses: ["198.51.100.2"],
          name_servers: ["ns1.c2.biz"],
          mail_servers: [],
          dnssec_validated: false,
          response_time_ms: 18.5,
          threat_summary: "Active C2 Server: Resolving to IP(s) [198.51.100.2]",
        },
      },
    ];

    vi.mocked(client.predictBatch).mockResolvedValueOnce({
      total: 1,
      predictions: mockPredictions,
    });

    render(<BulkAudit />);

    fireEvent.click(screen.getByText("Paste Raw Text / Domains"));
    const textarea = screen.getByPlaceholderText(
      /Paste domain names, URLs, or query logs/i,
    );
    fireEvent.change(textarea, { target: { value: "c2-domain.biz" } });

    // Check Live DNS checkbox
    const dnsCheckbox = screen.getByRole("checkbox");
    fireEvent.click(dnsCheckbox);

    const runBtn = screen.getByRole("button", { name: /Run Audit/i });
    fireEvent.click(runBtn);

    await waitFor(() => {
      expect(screen.getByText("c2-domain.biz")).toBeDefined();
    });

    expect(client.predictBatch).toHaveBeenCalledWith(["c2-domain.biz"], true);
    expect(screen.getByText("C2 ACTIVE")).toBeDefined();
  });
});
