import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, act } from "@testing-library/react";
import DomainInput from "../src/components/DomainInput";

describe("DomainInput", () => {
  const mockSubmitSingle = vi.fn();
  const mockSubmitBatch = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders the input field and analyze button", () => {
    render(
      <DomainInput
        onSubmitSingle={mockSubmitSingle}
        onSubmitBatch={mockSubmitBatch}
        isLoading={false}
      />,
    );

    expect(screen.getByPlaceholderText(/enter domain/i)).toBeDefined();
    expect(screen.getByText("Analyze")).toBeDefined();
  });

  it("allows typing in the domain input", () => {
    render(
      <DomainInput
        onSubmitSingle={mockSubmitSingle}
        onSubmitBatch={mockSubmitBatch}
        isLoading={false}
      />,
    );

    const input = screen.getByPlaceholderText(
      /enter domain/i,
    ) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "google.com" } });
    expect(input.value).toBe("google.com");
  });

  it("calls onSubmitSingle when form is submitted and clears input", () => {
    render(
      <DomainInput
        onSubmitSingle={mockSubmitSingle}
        onSubmitBatch={mockSubmitBatch}
        isLoading={false}
      />,
    );

    const input = screen.getByPlaceholderText(/enter domain/i) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "google.com" } });

    const button = screen.getByText("Analyze");
    fireEvent.click(button);

    expect(mockSubmitSingle).toHaveBeenCalledWith("google.com", false);
    expect(input.value).toBe("");
  });

  it("renders Run Test button without lightning emoji", () => {
    const mockRunTest = vi.fn();
    render(
      <DomainInput
        onSubmitSingle={mockSubmitSingle}
        onSubmitBatch={mockSubmitBatch}
        onRunTest={mockRunTest}
        isLoading={false}
      />,
    );

    const runTestBtn = screen.getByRole("button", { name: /run test/i });
    expect(runTestBtn).toBeDefined();
    expect(runTestBtn.textContent).not.toContain("⚡");
  });

  it("calls onSubmitSingle with resolveDns=true when checkbox is toggled", () => {
    render(
      <DomainInput
        onSubmitSingle={mockSubmitSingle}
        onSubmitBatch={mockSubmitBatch}
        isLoading={false}
      />,
    );

    const input = screen.getByPlaceholderText(/enter domain/i);
    fireEvent.change(input, { target: { value: "threat-c2.biz" } });

    const checkbox = screen.getByRole("checkbox");
    fireEvent.click(checkbox);

    const button = screen.getByText("Analyze");
    fireEvent.click(button);

    expect(mockSubmitSingle).toHaveBeenCalledWith("threat-c2.biz", true);
  });

  it("shows error for empty domain submission", () => {
    render(
      <DomainInput
        onSubmitSingle={mockSubmitSingle}
        onSubmitBatch={mockSubmitBatch}
        isLoading={false}
      />,
    );

    // Try submitting with empty input by directly submitting form
    const button = screen.getByText("Analyze");
    fireEvent.click(button);

    // Should not call onSubmitSingle
    expect(mockSubmitSingle).not.toHaveBeenCalled();
  });

  it("toggles to batch mode", () => {
    render(
      <DomainInput
        onSubmitSingle={mockSubmitSingle}
        onSubmitBatch={mockSubmitBatch}
        isLoading={false}
      />,
    );

    const batchBtn = screen.getByText("Batch Check");
    fireEvent.click(batchBtn);

    // Should now show the textarea
    expect(screen.getByPlaceholderText(/paste domains/i)).toBeDefined();
  });

  it("disables input when loading", () => {
    render(
      <DomainInput
        onSubmitSingle={mockSubmitSingle}
        onSubmitBatch={mockSubmitBatch}
        isLoading={true}
      />,
    );

    const input = screen.getByPlaceholderText(
      /enter domain/i,
    ) as HTMLInputElement;
    expect(input.disabled).toBe(true);
  });
});

describe("DomainInput validation feedback", () => {
  const setup = () => {
    const single = vi.fn();
    const batch = vi.fn();
    render(<DomainInput onSubmitSingle={single} onSubmitBatch={batch} isLoading={false} />);
    return { single, batch, input: screen.getByPlaceholderText(/enter domain/i) as HTMLInputElement };
  };

  it("shows inline error on blur with aria wiring, and disables submit", () => {
    const { input } = setup();
    fireEvent.change(input, { target: { value: "a..com" } });
    expect(screen.queryByText(/empty label/i)).toBeNull(); // not on first keystroke
    fireEvent.blur(input);
    expect(screen.getByText(/empty label/i)).toBeDefined();
    expect(input.getAttribute("aria-invalid")).toBe("true");
    expect(input.getAttribute("aria-describedby")).toBe("domain-feedback");
    expect(document.getElementById("domain-feedback")?.getAttribute("aria-live")).toBe("polite");
    expect((screen.getByText("Analyze").closest("button") as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows error after debounce while typing", () => {
    vi.useFakeTimers();
    try {
      const { input } = setup();
      fireEvent.change(input, { target: { value: "a@b.com" } });
      act(() => {
        vi.advanceTimersByTime(700);
      });
      expect(screen.getByText(/email address/i)).toBeDefined();
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows normalization note for a pasted URL and submits", () => {
    const { input, single } = setup();
    fireEvent.change(input, { target: { value: "https://user@Mysite.com:8080/x" } });
    fireEvent.blur(input);
    expect(screen.getByText(/mysite\.com from the URL you pasted/i)).toBeDefined();
    fireEvent.click(screen.getByText("Analyze"));
    expect(single).toHaveBeenCalledWith("https://user@Mysite.com:8080/x", false);
  });

  it("shows a non-blocking warning for underscores", () => {
    const { input } = setup();
    fireEvent.change(input, { target: { value: "_dmarc.mysite.com" } });
    fireEvent.blur(input);
    expect(screen.getByText(/not a valid hostname/i)).toBeDefined();
    expect((screen.getByText("Analyze").closest("button") as HTMLButtonElement).disabled).toBe(false);
  });

  it("batch: per-line status list and valid-only submit", () => {
    const { batch } = setup();
    fireEvent.click(screen.getByText("Batch Check"));
    fireEvent.change(screen.getByPlaceholderText(/paste domains/i), {
      target: { value: "google.com, bad..com\nGoogle.com. müller.de" },
    });
    const items = screen.getAllByRole("listitem").map((li) => li.getAttribute("data-status"));
    expect(items).toEqual(["valid", "invalid", "duplicate", "normalized"]);
    fireEvent.click(screen.getByText("Analyze"));
    expect(batch).toHaveBeenCalledWith(["google.com", "müller.de"], false);
  });

  it("batch: blocks submit over the server cap", () => {
    setup();
    fireEvent.click(screen.getByText("Batch Check"));
    const text = Array.from({ length: 101 }, (_, i) => `d${i}.com`).join("\n");
    fireEvent.change(screen.getByPlaceholderText(/paste domains/i), { target: { value: text } });
    expect(screen.getByText(/maximum is 100/i)).toBeDefined();
    expect((screen.getByText("Analyze").closest("button") as HTMLButtonElement).disabled).toBe(true);
  });
});
