/* Auraline - progressive enhancement only. Every page works without this file.
   No animation, no timers, nothing that could flash. */

(function () {
  "use strict";

  // Confirm destructive submissions. Server-side checks remain authoritative.
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        event.preventDefault();
      }
    });
  });

  // Language picker: <details> alone does not close when you click elsewhere
  // or press Escape. Purely additive -- without this the menu still opens,
  // closes on its own summary, and navigates correctly.
  var pickers = document.querySelectorAll("details.langpicker");

  document.addEventListener("click", function (event) {
    pickers.forEach(function (picker) {
      if (picker.open && !picker.contains(event.target)) {
        picker.open = false;
      }
    });
  });

  document.addEventListener("keydown", function (event) {
    if (event.key !== "Escape") return;
    pickers.forEach(function (picker) {
      if (picker.open) {
        picker.open = false;
        var summary = picker.querySelector("summary");
        if (summary) summary.focus();
      }
    });
  });

  // Warn before navigating away from a half-typed record.
  var editor = document.querySelector("form[data-dirty-guard]");
  if (editor) {
    var dirty = false;
    editor.addEventListener("input", function () {
      dirty = true;
    });
    editor.addEventListener("submit", function () {
      dirty = false;
    });
    window.addEventListener("beforeunload", function (event) {
      if (dirty) {
        event.preventDefault();
        event.returnValue = "";
      }
    });
  }
})();
