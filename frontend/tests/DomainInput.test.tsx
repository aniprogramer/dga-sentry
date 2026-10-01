import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
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

  it("calls onSubmitSingle when form is submitted", () => {
    render(
      <DomainInput
        onSubmitSingle={mockSubmitSingle}
        onSubmitBatch={mockSubmitBatch}
        isLoading={false}
      />,
    );

    const input = screen.getByPlaceholderText(/enter domain/i);
    fireEvent.change(input, { target: { value: "google.com" } });

    const button = screen.getByText("Analyze");
    fireEvent.click(button);

    expect(mockSubmitSingle).toHaveBeenCalledWith("google.com", false);
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
