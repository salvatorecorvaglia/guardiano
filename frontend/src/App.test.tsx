import { cleanup, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import userEvent from "@testing-library/user-event";
import type { User } from "./api/types";
import App from "./App";
import { ANALYST, renderPage, serveApi } from "./test/harness";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("App routing", () => {
  it("keeps enrollment recovery codes visible after replacing the session", async () => {
    const user = { ...ANALYST, mfa_enrollment_required: true };
    serveApi({
      "/auth/mfa": { enabled: false, required: true, confirmed_at: null, recovery_codes_left: 0 },
      "POST /auth/mfa/setup": { secret: "ABC234", otpauth_uri: "otpauth://totp/Test?secret=ABC234" },
      "POST /auth/mfa/enable": {
        recovery_codes: ["keep-this-code"],
        session: { access_token: "new", user: { ...user, mfa_enabled: true, mfa_enrollment_required: false } },
      },
    }, user);
    renderPage(<App />, { path: "/*" });
    await userEvent.click(await screen.findByRole("button", { name: "Set up two-factor authentication" }));
    await userEvent.type(screen.getByRole("textbox", { name: "Code from your app" }), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Turn on" }));
    expect(await screen.findByText("keep-this-code")).toBeTruthy();
    expect(screen.getByRole("dialog", { name: "Save your recovery codes" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Set up two-factor authentication" })).toBeTruthy();
  });
  it("sends somebody without the role away from an admin page", async () => {
    serveApi({}, ANALYST);
    renderPage(<App />, { route: "/users", path: "/*" });
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("/"), { timeout: 5000 });
  });

  it("lets an administrator in", async () => {
    serveApi({ "/users": [] }, { ...ANALYST, role: "admin" } as User);
    renderPage(<App />, { route: "/users", path: "/*" });
    await screen.findByRole("heading", { name: /users/i });
    expect(screen.getByTestId("location").textContent).toBe("/users");
  });
});
