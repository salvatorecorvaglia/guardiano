import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import AsyncState from "./AsyncState";

afterEach(cleanup);
it("waits for every dependency and exposes a named loading state", () => {
  const ready = { isPending: false, error: null, refetch: vi.fn() };
  const { rerender } = render(<AsyncState queries={[ready, { ...ready, isPending: true }]} label="Report">Report data</AsyncState>);
  expect(screen.getByRole("status", { name: "Loading report" })).toBeTruthy();
  expect(screen.queryByText("Report data")).toBeNull();
  rerender(<AsyncState queries={[ready, ready]} label="Report">Report data</AsyncState>);
  expect(screen.getByText("Report data")).toBeTruthy();
});
it("retries failed dependencies and hides stale data during an error", async () => {
  const retry = vi.fn().mockResolvedValue({});
  const healthy = vi.fn();
  render(<AsyncState queries={[{ isPending: false, error: new Error("Unavailable"), refetch: retry }, { isPending: false, error: null, refetch: healthy }]} label="Trend">Stale trend</AsyncState>);
  expect(screen.getByText("Unavailable")).toBeTruthy();
  expect(screen.queryByText("Stale trend")).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Retry trend" }));
  expect(retry).toHaveBeenCalledOnce();
  expect(healthy).not.toHaveBeenCalled();
});
