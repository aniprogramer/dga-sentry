import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, act, waitFor, cleanup } from "@testing-library/react";
import App from "../src/App";

vi.mock("../src/api/client", () => ({
  getHealth: vi.fn().mockResolvedValue({ status: "healthy" }),
  getModelInfo: vi.fn().mockResolvedValue({
    model_type: "xgboost",
    metrics: { accuracy: 0.9, precision: 0.9, recall: 0.9, f1_score: 0.9, roc_auc: 0.9, train_time_seconds: 1 },
    n_features: 13,
    feature_names: [],
    train_size: 1,
    val_size: 1,
    test_size: 1,
  }),
  checkDomain: vi.fn(),
  checkDomains: vi.fn(),
  ApiError: class extends Error {},
}));

const renderApp = async () => {
  await act(async () => {
    render(<App />);
  });
};

const scrollIntoView = vi.fn();

describe("About page", () => {
  beforeEach(() => {
    cleanup();
    scrollIntoView.mockClear();
    Element.prototype.scrollIntoView = scrollIntoView; // jsdom lacks it
    window.scrollTo = vi.fn() as unknown as typeof window.scrollTo;
    window.location.hash = "";
  });

  it("shows About in the main navigation, last", async () => {
    await renderApp();
    const nav = screen.getByRole("navigation", { name: /main navigation/i });
    const buttons = nav.querySelectorAll("button");
    expect(buttons[buttons.length - 1].textContent).toMatch(/about/i);
  });

  it("selecting About shows the page with one h1 and marks the tab current", async () => {
    await renderApp();
    await act(async () => {
      fireEvent.click(document.getElementById("about-nav-tab")!);
    });
    await waitFor(() => expect(screen.getByRole("heading", { level: 1 })).toBeDefined());
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(window.location.hash).toBe("#/about");
    expect(document.getElementById("about-nav-tab")!.getAttribute("aria-current")).toBe("page");
    expect(document.title).toMatch(/about dga sentry/i);
  });

  it("back button returns to the previous view and restores the title", async () => {
    await renderApp();
    const original = document.title;
    await act(async () => {
      fireEvent.click(document.getElementById("about-nav-tab")!);
    });
    await waitFor(() => expect(screen.getByRole("heading", { level: 1 })).toBeDefined());
    await act(async () => {
      window.history.back();
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(screen.queryByRole("heading", { level: 1 })).toBeNull();
    expect(screen.getByPlaceholderText(/enter domain/i)).toBeDefined();
    expect(document.title).toBe(original);
  });

  it("renders the page on a direct load of the About URL, including a section link", async () => {
    window.location.hash = "#/about#how-it-works";
    await renderApp();
    expect(screen.getByRole("heading", { level: 1 })).toBeDefined();
    expect(screen.getByRole("heading", { name: /how it works/i })).toBeDefined();
    expect(scrollIntoView.mock.contexts.map((el) => (el as Element).id)).toContain("how-it-works");
  });

  it("'Try it now' returns to the analyzer with the input focused", async () => {
    window.location.hash = "#/about";
    await renderApp();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /try it now/i }));
    });
    await waitFor(() => expect(document.activeElement?.id).toBe("domain-input"));
    expect(window.location.hash).toBe("#/");
  });

  it("workbench has a 'How does this work?' link into the About section, and the footer links About", async () => {
    await renderApp();
    expect(screen.getByRole("link", { name: /how does this work/i }).getAttribute("href")).toBe("#/about#how-it-works");
    const footer = document.querySelector("footer")!;
    expect(footer.querySelector('a[href="#/about"]')).not.toBeNull();
  });

  it("external links open in a new tab safely", async () => {
    window.location.hash = "#/about";
    await renderApp();
    const gh = screen.getByRole("link", { name: /github repository/i });
    expect(gh.getAttribute("target")).toBe("_blank");
    expect(gh.getAttribute("rel")).toBe("noopener noreferrer");
  });

  it("main copy has no model or library jargon", async () => {
    window.location.hash = "#/about";
    await renderApp();
    const text = document.querySelector("article")!.textContent!;
    for (const w of ["XGBoost", "Random Forest", "TreeSHAP", "SHAP", "FANCI", "tensor", "dimension"]) {
      expect(text).not.toContain(w);
    }
  });
});
