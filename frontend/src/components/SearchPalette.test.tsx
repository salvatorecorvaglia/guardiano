import { cleanup, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { finding, renderPage, serveApi } from "../test/harness";
import SearchPalette from "./SearchPalette";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const RESULT = {
  vulnerability: "CVE-2021-44228",
  findings: [finding({ id: 7, title: "Log4Shell in log4j-core" })],
  assets: [{ id: 2, name: "payments-api" }],
  packages: [{ name: "log4j-core", ecosystem: "maven", assets: 3 }],
};

describe("SearchPalette", () => {
  it("contains focus and restores it to the opener", async () => {
    serveApi({ "/search": RESULT });
    renderPage(<SearchPalette />);
    const opener = screen.getAllByRole("button", { name: "Search" })[0];
    opener.focus();
    await userEvent.click(opener);
    const query = await screen.findByRole("combobox", { name: "Search query" });
    expect(document.activeElement).toBe(query);
    await userEvent.tab();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Close" }));
    await userEvent.keyboard("{Escape}");
    expect(document.activeElement).toBe(opener);
  });
  it("opens with Ctrl-K and goes where the arrows point", async () => {
    const calls = serveApi({ "/search": RESULT });
    renderPage(<SearchPalette />, { route: "/", path: "*" });
    await userEvent.keyboard("{Control>}k{/Control}");
    await userEvent.type(await screen.findByRole("combobox", { name: "Search query" }), "cve-2021-44228");
    expect(await screen.findByText("Across every asset")).toBeTruthy();
    expect(calls.find((c) => c.path === "/search")!.url.searchParams.get("q")).toBe("cve-2021-44228");

    await userEvent.keyboard("{ArrowDown}{Enter}"); // the vulnerability is first, the finding second
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("/findings/7"));
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("does not take '/' away from a field being typed in", async () => {
    serveApi({ "/search": RESULT });
    renderPage(
      <>
        <input aria-label="elsewhere" />
        <SearchPalette />
      </>,
    );
    await userEvent.type(screen.getByRole("textbox", { name: "elsewhere" }), "a/b");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect((screen.getByRole("textbox", { name: "elsewhere" }) as HTMLInputElement).value).toBe("a/b");
  });
});
