import { cleanup, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderPage, serveApi } from "../test/harness";
import NotificationBell from "./NotificationBell";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const LIST = {
  unread: 1,
  items: [
    { id: 4, kind: "mentioned", text: 'Ann mentioned you: "look" — SQL injection', finding_id: 9, actor: null, read_at: null, created_at: "2026-09-22T10:00:00Z" },
    { id: 3, kind: "assigned", text: "Bob assigned you — XSS", finding_id: 8, actor: null, read_at: "2026-09-21T10:00:00Z", created_at: "2026-09-21T09:00:00Z" },
  ],
};

describe("NotificationBell", () => {
  it("shows the unread count, and opening one marks it read and goes to the finding", async () => {
    const calls = serveApi({ "/notifications": LIST, "POST /notifications/read": { ...LIST, unread: 0 } });
    renderPage(<NotificationBell />, { route: "/", path: "*" });
    await userEvent.click(await screen.findByRole("button", { name: "Notifications, 1 unread" }));
    await userEvent.click(screen.getByText(/Ann mentioned you/));

    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("/findings/9"));
    const mark = calls.find((c) => c.path === "/notifications/read")!;
    expect(mark.body).toEqual({ ids: [4] });
  });

  it("marks everything read at once", async () => {
    const calls = serveApi({ "/notifications": LIST, "POST /notifications/read": { ...LIST, unread: 0 } });
    renderPage(<NotificationBell />);
    await userEvent.click(await screen.findByRole("button", { name: /Notifications/ }));
    await userEvent.click(screen.getByRole("button", { name: "Mark all read" }));
    await waitFor(() => expect(calls.find((c) => c.path === "/notifications/read")?.body).toEqual({ ids: null }));
    expect(await screen.findByRole("button", { name: "Notifications" })).toBeTruthy();
  });
});
