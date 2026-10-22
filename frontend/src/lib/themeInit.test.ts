import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const script = readFileSync(resolve(__dirname, "../../public/theme-init.js"), "utf8");

/** Runs public/theme-init.js as the browser would, with the OS preferring `dark` or not. */
function boot(prefersDark: boolean) {
  const listeners: (() => void)[] = [];
  const media = {
    matches: prefersDark,
    addEventListener: (_: string, fn: () => void) => listeners.push(fn),
  };
  vi.stubGlobal("matchMedia", () => media);
  new Function(script)();
  return {
    osSwitchesTo(dark: boolean) {
      media.matches = dark;
      listeners.forEach((fn) => fn());
    },
  };
}

const theme = () => document.documentElement.getAttribute("data-theme");

afterEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
});

describe("theme-init", () => {
  it("always sets an explicit theme, from the OS when nothing is saved", () => {
    boot(true);
    expect(theme()).toBe("dark");
    document.documentElement.removeAttribute("data-theme");
    boot(false);
    expect(theme()).toBe("light");
  });

  it("follows the OS live while the choice is 'system'", () => {
    const os = boot(false);
    os.osSwitchesTo(true);
    expect(theme()).toBe("dark");
  });

  it("keeps a saved choice whatever the OS does", () => {
    localStorage.setItem("guardiano-theme", "light");
    const os = boot(true);
    expect(theme()).toBe("light");
    os.osSwitchesTo(true);
    expect(theme()).toBe("light");
  });
});
