/* Kiln front-end: small, dependency-free progressive enhancement.
 *
 * Declarative hooks used by the templates:
 *   <button data-api="POST /api/v1/..." data-confirm="..." data-then="reload|redirect:/x|redirect:/x/{id}">
 *   <form data-form="POST /api/v1/..." data-then="...">   (fields → JSON; see serialize())
 *   <button data-open="dialog-id">, <button data-close>
 *   <pre data-deploy-log="/api/v1/deployments/<id>">       (live build log)
 *   <div data-load="/api/v1/..." data-render="containers|logs|readme">
 *   <button data-copy="text"> / data-copy-target="#el"
 */
(function () {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const csrf = () => ($('meta[name="csrf-token"]') || {}).content || "";
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  // ---------------------------------------------------------------- API
  async function api(method, url, body) {
    const opts = { method, headers: { Accept: "application/json" }, credentials: "same-origin" };
    if (method !== "GET") opts.headers["X-CSRF-Token"] = csrf();
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(url, opts);
    if (res.status === 204) return null;
    let data = null;
    try { data = await res.json(); } catch (e) { /* non-JSON */ }
    if (!res.ok) {
      if (res.status === 401) { location.href = "/login?next=" + encodeURIComponent(location.pathname); }
      throw new Error(errorText(data) || res.statusText || "Request failed");
    }
    return data;
  }

  function errorText(data) {
    if (!data || data.detail === undefined) return "";
    if (typeof data.detail === "string") return data.detail;
    if (Array.isArray(data.detail)) {
      return data.detail.map((d) => {
        const field = (d.loc || []).filter((x) => x !== "body").join(".");
        return (field ? field + ": " : "") + (d.msg || "").replace(/^Value error, /, "");
      }).join("\n");
    }
    return JSON.stringify(data.detail);
  }

  // -------------------------------------------------------------- toasts
  function toast(message, kind = "success") {
    const box = $("#toasts");
    if (!box) return alert(message);
    const el = document.createElement("div");
    el.className = "toast " + kind;
    el.textContent = message;
    box.appendChild(el);
    setTimeout(() => el.remove(), kind === "error" ? 8000 : 3500);
  }

  function flashAfterReload(message) {
    try { sessionStorage.setItem("kiln-flash", message); } catch (e) { /* ignore */ }
  }

  function then(spec, data) {
    if (!spec) return;
    if (spec === "reload") return location.reload();
    if (spec.startsWith("redirect:")) {
      const url = spec.slice(9).replace(/\{(\w+)\}/g, (_, k) => encodeURIComponent((data && data[k]) || ""));
      location.href = url;
    }
  }

  function setLoading(btn, on) {
    if (!btn) return;
    btn.classList.toggle("loading", on);
    btn.disabled = on;
  }

  // ------------------------------------------------------ data-api buttons
  document.addEventListener("click", async (ev) => {
    const btn = ev.target.closest("[data-api]");
    if (!btn) return;
    ev.preventDefault();
    if (btn.dataset.confirm && !confirm(btn.dataset.confirm)) return;
    const [method, url] = btn.dataset.api.split(" ");
    const body = btn.dataset.body ? JSON.parse(btn.dataset.body) : undefined;
    setLoading(btn, true);
    try {
      const data = await api(method, url, body);
      if (btn.dataset.success) {
        btn.dataset.then === "reload" ? flashAfterReload(btn.dataset.success) : toast(btn.dataset.success);
      }
      if (btn.dataset.output && data && data.output !== undefined) {
        const target = $(btn.dataset.output);
        if (target) target.textContent = data.output || "(no output)";
      }
      then(btn.dataset.then, data);
    } catch (err) {
      toast(err.message, "error");
    } finally {
      setLoading(btn, false);
    }
  });

  // ------------------------------------------------------------ forms
  function coerce(input) {
    if (input.type === "checkbox") return input.checked;
    if (input.type === "number") return input.value === "" ? null : Number(input.value);
    if (input.dataset.type === "json") return input.value ? JSON.parse(input.value) : null;
    return input.value;
  }

  function serialize(form) {
    const out = {};
    $$("[name]", form).forEach((el) => {
      if (el.tagName === "BUTTON" || el.disabled || el.closest("[data-repeater]") || el.closest("[hidden]")) return;
      if (el.type === "radio" && !el.checked) return;
      if (el.dataset.array !== undefined) {
        out[el.name] = out[el.name] || [];
        if (el.checked) out[el.name].push(el.value);
        return;
      }
      const v = coerce(el);
      if ((v === "" || v === null) && el.dataset.keepEmpty === undefined) return;
      out[el.name] = v;
    });
    $$("[data-repeater]", form).forEach((rep) => {
      if (rep.closest("[hidden]")) return;
      const rows = $$(".repeater-row", rep);
      if (rep.dataset.kind === "map") {
        const obj = {};
        rows.forEach((r) => {
          const k = $("[data-k]", r).value.trim();
          if (k) obj[k] = $("[data-v]", r).value;
        });
        out[rep.dataset.repeater] = obj;
      } else {
        out[rep.dataset.repeater] = rows.map((r) => {
          const item = {};
          $$("[data-f]", r).forEach((el) => {
            const v = coerce(el);
            if (v !== "" && v !== null) item[el.dataset.f] = v;
          });
          return item;
        }).filter((item) => Object.keys(item).length > (rep.dataset.minKeys ? Number(rep.dataset.minKeys) - 1 : 0));
      }
    });
    return out;
  }

  document.addEventListener("submit", async (ev) => {
    const form = ev.target.closest("form[data-form]");
    if (!form) return;
    ev.preventDefault();
    if (form.dataset.confirm && !confirm(form.dataset.confirm)) return;
    const [method, url] = form.dataset.form.split(" ");
    const submit = ev.submitter || $('[type="submit"]', form);
    let body;
    try { body = serialize(form); } catch (err) { return toast("Invalid input: " + err.message, "error"); }
    if (submit && submit.name) body[submit.name] = submit.value === "true" ? true : submit.value === "false" ? false : submit.value;
    setLoading(submit, true);
    try {
      const data = await api(method, url, body);
      form.dispatchEvent(new CustomEvent("kiln:success", { detail: data, bubbles: true }));
      if (form.dataset.resultField && data) {
        const target = $(form.dataset.resultTarget);
        if (target) {
          target.textContent = data[form.dataset.resultField];
          const box = target.closest("[data-result]");
          if (box) box.hidden = false;
        }
        if (submit) submit.hidden = true;
      }
      if (form.dataset.success) {
        (form.dataset.then || "").startsWith("redirect") || form.dataset.then === "reload"
          ? flashAfterReload(form.dataset.success) : toast(form.dataset.success);
      }
      then(form.dataset.then, data);
    } catch (err) {
      toast(err.message, "error");
    } finally {
      setLoading(submit, false);
    }
  });

  // --------------------------------------------------------- repeaters
  document.addEventListener("click", (ev) => {
    const add = ev.target.closest("[data-add-row]");
    if (add) {
      const rep = $(add.dataset.addRow);
      const tpl = $("template", rep);
      rep.insertBefore(tpl.content.cloneNode(true), tpl);
      const rows = $$(".repeater-row", rep);
      const first = rows[rows.length - 1] && $("input", rows[rows.length - 1]);
      if (first) first.focus();
      rep.dispatchEvent(new Event("input", { bubbles: true }));
      return;
    }
    const remove = ev.target.closest("[data-remove-row]");
    if (remove) {
      const rep = remove.closest("[data-repeater]");
      remove.closest(".repeater-row").remove();
      if (rep) rep.dispatchEvent(new Event("input", { bubbles: true }));
    }
    const reveal = ev.target.closest("[data-reveal]");
    if (reveal) {
      const input = reveal.closest(".repeater-row").querySelector("[data-v]");
      input.type = input.type === "password" ? "text" : "password";
    }
  });

  // ----------------------------------------------------------- dialogs
  document.addEventListener("click", (ev) => {
    const opener = ev.target.closest("[data-open]");
    if (opener) {
      const dlg = document.getElementById(opener.dataset.open);
      if (dlg) { dlg.showModal(); const f = $("input:not([type=hidden]), textarea, select", dlg); if (f) f.focus(); }
    }
    const closer = ev.target.closest("[data-close]");
    if (closer) closer.closest("dialog").close();
    if (ev.target.closest("[data-reload-page]")) location.reload();
  });

  // ---------------------------------------------------------- copy
  document.addEventListener("click", async (ev) => {
    const btn = ev.target.closest("[data-copy], [data-copy-target]");
    if (!btn) return;
    const text = btn.dataset.copy || ($(btn.dataset.copyTarget) || {}).textContent || "";
    try { await navigator.clipboard.writeText(text.trim()); toast("Copied to clipboard"); }
    catch (e) { toast("Could not copy: " + e.message, "error"); }
  });

  // ------------------------------------------------------- theme
  document.addEventListener("click", (ev) => {
    if (!ev.target.closest("[data-theme-toggle]")) return;
    const root = document.documentElement;
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    const next = dark ? "light" : "dark";
    root.dataset.theme = next;
    try { localStorage.setItem("kiln-theme", next); } catch (e) { /* ignore */ }
  });

  // ---------------------------------------------------- menus / nav
  document.addEventListener("click", (ev) => {
    $$("details.usermenu[open]").forEach((d) => { if (!d.contains(ev.target)) d.open = false; });
    if (ev.target.closest(".menu-toggle")) $("#sidebar").classList.toggle("open");
    else if (!ev.target.closest("#sidebar")) { const s = $("#sidebar"); if (s) s.classList.remove("open"); }
  });

  document.addEventListener("keydown", (ev) => {
    if ((ev.metaKey || ev.ctrlKey) && ev.key.toLowerCase() === "k") {
      const input = $(".search input");
      if (input) { ev.preventDefault(); input.focus(); input.select(); }
    }
  });

  // -------------------------------------------------- live deploy log
  const STATUS = {
    queued: ["Queued", "spin"], running: ["Building", "warning spin"], succeeded: ["Deployed", "success"],
    failed: ["Failed", "error"], cancelled: ["Cancelled", ""],
  };

  function streamLog(pre) {
    let offset = 0;
    const url = pre.dataset.deployLog;
    const badge = $("[data-deploy-status]");
    const follow = () => { pre.scrollTop = pre.scrollHeight; };
    async function tick() {
      try {
        const d = await api("GET", url + "?log_offset=" + offset);
        if (d.log) {
          const atBottom = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 40;
          pre.textContent += d.log;
          if (atBottom) follow();
        }
        offset = d.log_offset;
        if (badge && STATUS[d.status]) {
          badge.className = "badge " + STATUS[d.status][1];
          badge.textContent = STATUS[d.status][0];
        }
        if (d.status === "queued" || d.status === "running") setTimeout(tick, 1500);
        else if (pre.dataset.reloadOnFinish !== undefined && pre.dataset.initialStatus !== d.status) location.reload();
      } catch (err) {
        setTimeout(tick, 5000);
      }
    }
    tick();
  }

  // ----------------------------------------------------- lazy loaders
  const renderers = {
    containers(el, rows) {
      if (!rows.length) { el.innerHTML = '<p class="muted">No containers found on the host.</p>'; return; }
      el.innerHTML = '<div class="table-wrap"><table class="table"><thead><tr><th>Container</th><th>Image</th><th>State</th><th>Status</th><th>Ports</th></tr></thead><tbody>' +
        rows.map((r) => {
          const cls = r.State === "running" ? "success" : r.State === "exited" ? "error" : "";
          return `<tr><td><strong>${esc(r.Names)}</strong></td><td class="mono subtle">${esc(r.Image)}</td><td><span class="badge ${cls}">${esc(r.State)}</span></td><td class="muted">${esc(r.Status)}</td><td class="mono subtle">${esc(r.Ports)}</td></tr>`;
        }).join("") + "</tbody></table></div>";
    },
    logs(el, data) { el.textContent = (data && data.output) || "No log output yet."; el.scrollTop = el.scrollHeight; },
    readme(el, data) { el.textContent = (data && data.content) || "This repository has no README."; },
  };

  async function load(el) {
    try {
      const data = await api("GET", el.dataset.load);
      renderers[el.dataset.render](el, data);
    } catch (err) {
      el.innerHTML = `<p class="callout error">${esc(err.message)}</p>`;
    }
  }
  document.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-reload-target]");
    if (btn) { const el = $(btn.dataset.reloadTarget); if (el) load(el); }
  });

  // ---------------------------------------------------- branch picker
  async function loadBranches(repoSelect) {
    const target = $(repoSelect.dataset.branches);
    if (!target) return;
    const opt = repoSelect.selectedOptions[0];
    const current = target.dataset.current || (opt && opt.dataset.default) || "main";
    target.innerHTML = `<option>${esc(current)}</option>`;
    if (!repoSelect.value) return;
    try {
      const names = await api("GET", `/api/v1/repositories/${repoSelect.value}/branches`);
      const list = names.includes(current) ? names : [current, ...names];
      target.innerHTML = list.map((n) => `<option ${n === current ? "selected" : ""}>${esc(n)}</option>`).join("");
    } catch (err) {
      target.title = err.message; // keep the default branch so the form still works
    }
    target.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // ------------------------------------------------ instance form preview
  function wirePreview(form) {
    const update = () => {
      const data = serialize(form);
      const repo = $('[name="repository_id"]', form);
      const host = $('[name="host_id"]:checked', form);
      const set = (key, value) => $$(`[data-preview="${key}"]`).forEach((n) => { n.textContent = value || "—"; });
      const compose = data.build_source === "compose";
      set("repository", repo && repo.selectedOptions[0] ? repo.selectedOptions[0].textContent.trim() : "");
      set("branch", data.branch);
      set("source", compose ? `docker compose (${data.compose_file || "docker-compose.yml"})` : `Dockerfile (${data.dockerfile_path || "Dockerfile"})`);
      set("host", host ? host.dataset.label : "");
      set("name", data.name);
      set("env", Object.keys(data.env || {}).length + " variable(s)");
      set("ports", compose ? "Defined by compose file" : (data.ports || []).map((p) => `${p.host} → ${p.container} (${(p.protocol || "tcp").toUpperCase()})`).join(", ") || "None");
      set("volumes", compose ? "Defined by compose file" : (data.volumes || []).map((v) => `${v.source} → ${v.target}`).join(", ") || "None");
    };
    form.addEventListener("input", update);
    form.addEventListener("change", update);
    update();
  }

  // ------------------------------------- conditional fields: data-show-when="field=value"
  function wireShowWhen(form) {
    const targets = $$("[data-show-when]", form);
    if (!targets.length) return;
    const update = () => {
      targets.forEach((el) => {
        const [name, value] = el.dataset.showWhen.split("=");
        const checked = $(`[name="${name}"]:checked`, form);
        const field = checked || $(`[name="${name}"]:not([type=radio])`, form);
        el.hidden = !field || field.value !== value;
      });
    };
    form.addEventListener("change", update);
    update();
  }

  // -------------------------------------------------------------- boot
  document.addEventListener("DOMContentLoaded", () => {
    try {
      const flash = sessionStorage.getItem("kiln-flash");
      if (flash) { sessionStorage.removeItem("kiln-flash"); toast(flash); }
    } catch (e) { /* ignore */ }
    $$("[data-deploy-log]").forEach(streamLog);
    $$("[data-load]").forEach(load);
    $$("select[data-branches]").forEach((sel) => {
      sel.addEventListener("change", () => { $(sel.dataset.branches).dataset.current = ""; loadBranches(sel); });
      loadBranches(sel);
    });
    $$("form").forEach(wireShowWhen);
    $$("form[data-preview-form]").forEach(wirePreview);
    const params = new URLSearchParams(location.search);
    $$("dialog[data-open-on]").forEach((dlg) => { if (params.get(dlg.dataset.openOn)) dlg.showModal(); });
    $$("[data-filter]").forEach((input) => {
      input.addEventListener("input", () => {
        const q = input.value.toLowerCase();
        $$(input.dataset.filter + " tbody tr").forEach((tr) => { tr.hidden = !tr.textContent.toLowerCase().includes(q); });
      });
    });
  });

  window.kiln = { api, toast, serialize };
})();
