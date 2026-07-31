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
