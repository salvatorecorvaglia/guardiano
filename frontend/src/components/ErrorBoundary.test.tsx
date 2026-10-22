import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import ErrorBoundary from "./ErrorBoundary";

afterEach(cleanup);

let broken = true;
function Page() {
  if (broken) throw new Error("render failed");
  return <p>page content</p>;
}

describe("ErrorBoundary", () => {
  it("contains a render error to the page, and recovers when the page changes", () => {
    vi.spyOn(console, "error").mockImplementation(() => {}); // React logs the caught error
    broken = true;
    const { rerender } = render(<ErrorBoundary resetKey="/a"><Page /></ErrorBoundary>);
    expect(screen.getByRole("alert").textContent).toContain("render failed");

    broken = false;
    rerender(<ErrorBoundary resetKey="/b"><Page /></ErrorBoundary>); // navigated elsewhere
    expect(screen.getByText("page content")).toBeTruthy();
  });

  it("recovers on Try again", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    broken = true;
    render(<ErrorBoundary><Page /></ErrorBoundary>);
    broken = false;
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(screen.getByText("page content")).toBeTruthy();
  });
});
