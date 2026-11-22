import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, act } from "@testing-library/react";
import App from "../src/App";

// Mock API client
vi.mock("../src/api/client", () => ({
  getHealth: vi.fn().mockResolvedValue({ status: "healthy" }),
  getModelInfo: vi.fn().mockResolvedValue({
    model_type: "xgboost",
    model_version: "2.1.0",
    feature_count: 13,
    threshold: 0.5,
  }),
  checkDomain: vi.fn(),
  checkDomains: vi.fn(),
  ApiError: class extends Error {},
}));

describe("App Dropdown Behavior", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("opens status popover on click and closes on outside click", async () => {
    await act(async () => {
      render(<App />);
    });

    const statusPill = screen.getByRole("button", { name: /system status telemetry/i });
    expect(screen.queryByRole("dialog", { name: /system telemetry details/i })).toBeNull();

    // Open dropdown
    act(() => {
      fireEvent.click(statusPill);
    });
    expect(screen.getByRole("dialog", { name: /system telemetry details/i })).toBeDefined();

    // Click outside on document body
    act(() => {
      fireEvent.mouseDown(document.body);
    });
    expect(screen.queryByRole("dialog", { name: /system telemetry details/i })).toBeNull();
  });

  it("closes status popover on outside touchstart", async () => {
    await act(async () => {
      render(<App />);
    });

    const statusPill = screen.getByRole("button", { name: /system status telemetry/i });
    act(() => {
      fireEvent.click(statusPill);
    });
    expect(screen.getByRole("dialog", { name: /system telemetry details/i })).toBeDefined();

    // Touch outside
    act(() => {
      fireEvent.touchStart(document.body);
    });
    expect(screen.queryByRole("dialog", { name: /system telemetry details/i })).toBeNull();
  });

  it("closes status popover on Escape key", async () => {
    await act(async () => {
      render(<App />);
    });

    const statusPill = screen.getByRole("button", { name: /system status telemetry/i });
    act(() => {
      fireEvent.click(statusPill);
    });
    expect(screen.getByRole("dialog", { name: /system telemetry details/i })).toBeDefined();

    // Press Escape
    act(() => {
      fireEvent.keyDown(document, { key: "Escape" });
    });
    expect(screen.queryByRole("dialog", { name: /system telemetry details/i })).toBeNull();
  });
});
