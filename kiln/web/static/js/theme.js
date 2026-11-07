// Applied before first paint to avoid a light/dark flash. "system" follows the OS.
(function () {
  try {
    var t = localStorage.getItem("kiln-theme");
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  } catch (e) { /* storage unavailable: follow the OS */ }
})();
