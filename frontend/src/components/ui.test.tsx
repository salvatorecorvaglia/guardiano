import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Modal, Tabs, tabPanel } from "./ui";

afterEach(cleanup);

/** Mirrors UploadDialog: onClose is a new function on every render and the parent owns field state. */
function Harness({ onClose }: { onClose: () => void }) {
  const [open, setOpen] = useState(false);
  const [branch, setBranch] = useState("");
  return (
    <>
      <button onClick={() => setOpen(true)}>open</button>
      <Modal open={open} onClose={() => { onClose(); setOpen(false); }} title="Upload" footer={<button>Import</button>}>
        <input type="file" className="sr-only" aria-label="file" />
        <input aria-label="Branch" value={branch} onChange={(e) => setBranch(e.target.value)} />
        <input aria-label="Commit" />
      </Modal>
    </>
  );
}

describe("Modal", () => {
  it("focuses the first visible field and keeps focus while the parent re-renders", async () => {
    const user = userEvent.setup();
    render(<Harness onClose={() => {}} />);
    await user.click(screen.getByText("open"));
    const branch = screen.getByLabelText("Branch");
    expect(document.activeElement).toBe(branch);
    await user.type(branch, "main");
    expect(branch).toHaveProperty("value", "main");
    expect(document.activeElement).toBe(branch);
  });

  it("closes on Escape and restores focus to the opener", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<Harness onClose={onClose} />);
    const opener = screen.getByText("open");
    await user.click(opener);
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledOnce();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(opener);
  });

  it("traps Tab inside the dialog", async () => {
    const user = userEvent.setup();
    render(<Harness onClose={() => {}} />);
    await user.click(screen.getByText("open"));
    await act(async () => screen.getByText("Import").focus());
    await user.tab();
    expect(screen.getByRole("dialog").contains(document.activeElement)).toBe(true);
    expect(document.activeElement).toBe(screen.getByLabelText("Close"));
  });
});

function TabsHarness() {
  const [active, setActive] = useState<"a" | "b" | "c">("a");
  const tabs = [
    { key: "a", label: "Alpha" },
    { key: "b", label: "Beta" },
    { key: "c", label: "Gamma" },
  ] as const;
  return (
    <>
      <Tabs id="t" label="Letters" tabs={tabs} active={active} onChange={setActive} />
      <div {...tabPanel("t", active)}>panel {active}</div>
    </>
  );
}

describe("Tabs", () => {
  it("is one stop in the tab order, tied to its panel", () => {
    render(<TabsHarness />);
    const tabs = screen.getAllByRole("tab");
    expect(tabs.map((t) => t.tabIndex)).toEqual([0, -1, -1]);
    expect(tabs[0].getAttribute("aria-controls")).toBe(screen.getByRole("tabpanel").id);
    expect(screen.getByRole("tabpanel").getAttribute("aria-labelledby")).toBe(tabs[0].id);
  });

  it("moves with the arrow keys, wrapping, and Home/End", async () => {
    render(<TabsHarness />);
    const user = userEvent.setup();
    screen.getByRole("tab", { name: "Alpha" }).focus();

    await user.keyboard("{ArrowRight}");
    expect(document.activeElement).toBe(screen.getByRole("tab", { name: "Beta" }));
    expect(screen.getByRole("tabpanel").textContent).toBe("panel b");

    await user.keyboard("{ArrowLeft}{ArrowLeft}");
    expect(document.activeElement).toBe(screen.getByRole("tab", { name: "Gamma" })); // wrapped

    await user.keyboard("{Home}");
    expect(screen.getByRole("tab", { name: "Alpha" }).getAttribute("aria-selected")).toBe("true");
    await user.keyboard("{End}");
    expect(screen.getByRole("tabpanel").textContent).toBe("panel c");
  });
});
