import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation, useNavigate } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { canonicalQuery, useDebouncedParam, useUrlParams, validCalendarDate } from "./urlState";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

function Harness() {
  const { params, update } = useUrlParams();
  const [q, setQ] = useDebouncedParam("q", params, update);
  const location = useLocation();
  const navigate = useNavigate();
  return (
    <>
      <input aria-label="q" value={q} onChange={(e) => setQ(e.target.value)} />
      <button onClick={() => update({ severity: ["high"] })}>chip</button>
      <button onClick={() => navigate("/findings?status=open")}>nav</button>
      <output>{location.search}</output>
    </>
  );
}

describe("useDebouncedParam", () => {
  it("debounces into the URL without clobbering filters changed meanwhile", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(
      <MemoryRouter initialEntries={["/findings?page=3"]}>
        <Harness />
      </MemoryRouter>,
    );
    await user.type(screen.getByLabelText("q"), "sql");
    await user.click(screen.getByText("chip")); // changed before the debounce fires
    await act(async () => vi.advanceTimersByTime(400));
    const search = new URLSearchParams(screen.getByRole("status").textContent ?? "");
    expect(search.get("q")).toBe("sql");
    expect(search.getAll("severity")).toEqual(["high"]);
    expect(search.get("page")).toBeNull();
  });

  it("follows the URL when it changes elsewhere", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/findings?q=old"]}>
        <Harness />
      </MemoryRouter>,
    );
    expect(screen.getByLabelText("q")).toHaveProperty("value", "old");
    await user.click(screen.getByText("nav"));
    expect(screen.getByLabelText("q")).toHaveProperty("value", "");
  });
});

describe("canonicalQuery", () => {
  it("ignores paging, sort, empty values and parameter order", () => {
    expect(canonicalQuery("?status=open&severity=high&page=3&sort=-due&q=")).toBe("severity=high&status=open");
    expect(canonicalQuery("status=open&severity=high")).toBe(canonicalQuery("severity=high&status=open"));
    expect(canonicalQuery("severity=low&severity=high")).toBe("severity=high&severity=low");
    expect(canonicalQuery("")).toBe("");
  });
});


it("validates actual calendar dates in shared URLs", () => {
  expect(validCalendarDate("2024-02-29")).toBe(true);
  for (const date of ["2025-02-29", "2026-13-01", "2026-04-31", "garbage", "0000-01-01", null]) {
    expect(validCalendarDate(date)).toBe(false);
  }
});
