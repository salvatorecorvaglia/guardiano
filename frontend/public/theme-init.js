// Resolve the theme before first paint (kept external so the CSP can forbid inline scripts).
//
// The page always carries an explicit data-theme of "light" or "dark": a saved choice, or else what
// the operating system prefers -- followed live, so switching the OS to dark mode switches the app
// while "system" is selected. With the attribute always present, the dark palette is written once in
// index.css under [data-theme="dark"], and Tailwind's dark: variant (keyed on the same attribute)
// works in "system" mode too; it used to apply only after an explicit choice.
(function () {
  var media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  function apply() {
    var saved = null;
    try {
      saved = localStorage.getItem("guardiano-theme");
    } catch (e) {}
    var theme = saved === "light" || saved === "dark" ? saved : media && media.matches ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", theme);
  }
  apply();
  if (media && media.addEventListener) media.addEventListener("change", apply);
})();
