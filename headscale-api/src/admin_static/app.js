// OctraVPN admin GUI v0 — minimal interactivity.
//
// Budget: <10 KiB. No framework, no build step. Vanilla DOM only.
// Real interactive panels (live tailnet view, HuJSON policy editor) land
// in follow-up PRs; this file exists only to attach:
//   1. confirm() prompts on destructive forms (data-confirm attribute)
//   2. client-side hint validation (data-required, data-pattern)
//
// All user-provided strings rendered into the DOM by the server come
// through maud's auto-escape — this script never injects raw HTML.
(function () {
  "use strict";

  // 1. Confirm gate. Any <form data-confirm="..."> shows a JS confirm()
  //    before submission. The text comes from the data attribute so the
  //    page can phrase the warning per-action.
  document.addEventListener("submit", function (ev) {
    var form = ev.target;
    if (!(form instanceof HTMLFormElement)) return;
    var msg = form.getAttribute("data-confirm");
    if (!msg) return;
    if (!window.confirm(msg)) {
      ev.preventDefault();
      ev.stopPropagation();
    }
  }, true);

  // 2. Required-field hint. Mark <input data-required> with a red ring
  //    if the user blurs while empty. Server-side validation still
  //    runs; this is only a hint.
  document.addEventListener("blur", function (ev) {
    var el = ev.target;
    if (!(el instanceof HTMLInputElement)) return;
    if (!el.hasAttribute("data-required")) return;
    if (el.value.trim() === "") {
      el.style.borderColor = "var(--error)";
    } else {
      el.style.borderColor = "";
    }
  }, true);

  // 3. Pattern hint. <input data-pattern="^[a-z0-9_-]{1,32}$"> turns
  //    the border red on mismatched input. Server re-validates.
  document.addEventListener("input", function (ev) {
    var el = ev.target;
    if (!(el instanceof HTMLInputElement)) return;
    var pat = el.getAttribute("data-pattern");
    if (!pat) return;
    try {
      var re = new RegExp(pat);
      el.style.borderColor = (el.value === "" || re.test(el.value))
        ? "" : "var(--error)";
    } catch (_) {
      // bad pattern in the data attribute — fail open, server validates.
    }
  }, true);
})();
