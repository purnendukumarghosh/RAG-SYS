"use strict";

// NimbusVPN dashboard. Plain JavaScript, no build step. All untrusted text is inserted with
// textContent (never innerHTML), and the page runs under a strict Content-Security-Policy.

(() => {
  const TOKEN_KEY = "nimbus.token";
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  const state = {
    token: null,
    user: null,
    view: "devices",
    timer: null,
    pendingLogin: null,
  };

  try { state.token = sessionStorage.getItem(TOKEN_KEY); } catch { /* storage unavailable */ }

  // --- Helpers ------------------------------------------------------------------------

  function h(tag, attrs = {}, ...children) {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === "class") el.className = value;
      else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
      else el.setAttribute(key, value === true ? "" : value);
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      el.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return el;
  }

  function formatBytes(n) {
    if (!n) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
    return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
  }

  function relTime(iso) {
    if (!iso) return "never";
    const diff = (new Date(iso).getTime() - Date.now()) / 1000;
    const abs = Math.abs(diff);
    const fmt = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
    if (abs < 60) return fmt.format(Math.round(diff), "second");
    if (abs < 3600) return fmt.format(Math.round(diff / 60), "minute");
    if (abs < 86400) return fmt.format(Math.round(diff / 3600), "hour");
    return fmt.format(Math.round(diff / 86400), "day");
  }

  function absTime(iso) {
    return iso ? new Date(iso).toLocaleString() : "-";
  }

  let toastTimer;
  function toast(message, isError = false) {
    const el = $("#toast");
    el.textContent = message;
    el.classList.toggle("error", isError);
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, isError ? 6000 : 3000);
  }

  function formatDetail(detail) {
    if (!detail) return "";
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail.map((e) => `${(e.loc || []).slice(-1)[0] || "field"}: ${e.msg}`).join("; ");
    }
    return JSON.stringify(detail);
  }

  async function api(path, { method = "GET", body } = {}) {
    const headers = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (state.token) headers.Authorization = `Bearer ${state.token}`;
    const res = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "omit",
      cache: "no-store",
    });
    if (res.status === 204) return null;
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      if (res.status === 401 && path !== "/api/auth/login") signedOut("Your session has ended.");
      const err = new Error(formatDetail(data.detail) || res.statusText);
      err.status = res.status;
      err.detail = data.detail;
      throw err;
    }
    return data;
  }

  async function busy(button, fn) {
    if (button) button.disabled = true;
    try {
      return await fn();
    } catch (err) {
      toast(err.message || "Something went wrong", true);
      return undefined;
    } finally {
      if (button) button.disabled = false;
    }
  }

  function formData(form) {
    return Object.fromEntries(new FormData(form).entries());
  }

  function setToken(token) {
    state.token = token;
    try {
      if (token) sessionStorage.setItem(TOKEN_KEY, token);
      else sessionStorage.removeItem(TOKEN_KEY);
    } catch { /* storage unavailable */ }
  }

  function download(filename, text) {
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const a = h("a", { href: url, download: filename });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function ask(title, label, type = "text") {
    const dialog = $("#ask-dialog");
    const input = $("#ask-input");
    $("#ask-title").textContent = title;
    $("#ask-label").textContent = label;
    input.type = type;
    input.value = "";
    dialog.returnValue = "";
    dialog.showModal();
    return new Promise((resolve) => {
      dialog.addEventListener("close", () => {
        resolve(dialog.returnValue === "ok" ? input.value : null);
        input.value = "";
      }, { once: true });
    });
  }

  // --- Session & navigation -----------------------------------------------------------

  function signedOut(message) {
    setToken(null);
    state.user = null;
    clearInterval(state.timer);
    $("#nav").hidden = true;
    $("#session").hidden = true;
    $$(".view").forEach((v) => { v.hidden = v.id !== "view-login"; });
    $("#totp-field").hidden = true;
    if (message) toast(message);
  }

  function signedIn(user) {
    state.user = user;
    $("#whoami").textContent = `${user.username} · ${user.role}`;
    $("#nav").hidden = false;
    $("#session").hidden = false;
    $$(".admin-only").forEach((el) => { el.hidden = user.role !== "admin"; });
    showView(state.view);
  }

  const loaders = {
    devices: loadDevices,
    account: renderAccount,
    users: loadUsers,
    server: loadServer,
    audit: loadAudit,
  };

  function showView(name) {
    if (!state.user) return;
    if (["users", "server", "audit"].includes(name) && state.user.role !== "admin") name = "devices";
    state.view = name;
    $$(".view").forEach((v) => { v.hidden = v.id !== `view-${name}`; });
    $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.view === name));
    clearInterval(state.timer);
    loaders[name]();
    if (name === "devices") {
      state.timer = setInterval(() => { if (!document.hidden) loadDevices(); }, 10000);
    }
  }

  $$(".tab").forEach((tab) => tab.addEventListener("click", () => showView(tab.dataset.view)));

  $("#logout-btn").addEventListener("click", async () => {
    try { await api("/api/auth/logout", { method: "POST" }); } catch { /* already gone */ }
    signedOut("Signed out.");
  });

  $("#login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const errorEl = $("#login-error");
    const body = formData(form);
    if (!body.totp_code) delete body.totp_code;
    errorEl.hidden = true;
    const button = $("button[type=submit]", form);
    button.disabled = true;
    try {
      const data = await api("/api/auth/login", { method: "POST", body });
      setToken(data.access_token);
      form.reset();
      $("#totp-field").hidden = true;
      signedIn(data.user);
    } catch (err) {
      if (err.detail === "totp_required") {
        $("#totp-field").hidden = false;
        $("input[name=totp_code]", form).focus();
      } else {
        errorEl.textContent = err.message;
        errorEl.hidden = false;
      }
    } finally {
      button.disabled = false;
    }
  });

  // --- Devices ------------------------------------------------------------------------

  function deviceCard(d, showOwner) {
    const statusLabel = { online: "Online", offline: "Offline", disabled: "Disabled", expired: "Expired" }[d.status];
    const toggle = h("button", {
      type: "button",
      class: "switch",
      role: "switch",
      "aria-checked": String(d.enabled),
      "aria-label": `${d.enabled ? "Disable" : "Enable"} ${d.name}`,
      title: d.enabled ? "Disable device" : "Enable device",
      onclick: (e) => busy(e.currentTarget, async () => {
        await api(`/api/devices/${d.id}`, { method: "PATCH", body: { enabled: !d.enabled } });
        toast(`${d.name} ${d.enabled ? "disabled" : "enabled"}`);
        loadDevices();
      }),
    });

    const rows = [
      ["Status", statusLabel],
      ["Address", [d.ipv4, d.ipv6].filter(Boolean).join("  ·  ")],
      ["Handshake", relTime(d.last_handshake_at)],
      ["Traffic", `↓ ${formatBytes(d.tx_bytes)}  ↑ ${formatBytes(d.rx_bytes)}`],
      ["Expires", d.expires_at ? relTime(d.expires_at) : "never"],
      ["Keys", d.key_origin === "client" ? "own key (BYO)" : "server-generated"],
    ];
    if (showOwner) rows.unshift(["Owner", d.owner]);
    if (d.endpoint) rows.push(["Endpoint", d.endpoint]);

    const actions = [
      h("button", {
        type: "button",
        class: "small ghost",
        onclick: (e) => busy(e.currentTarget, async () => {
          if (!confirm(`Rotate keys for "${d.name}"? The current profile stops working immediately.`)) return;
          const prof = await api(`/api/devices/${d.id}/rotate`, { method: "POST" });
          showProfile(prof);
          loadDevices();
        }),
      }, "Rotate keys"),
    ];
    if (d.key_origin === "client") {
      actions.push(h("button", {
        type: "button",
        class: "small ghost",
        onclick: (e) => busy(e.currentTarget, async () => showProfile(await api(`/api/devices/${d.id}/config`))),
      }, "Profile"));
    }
    actions.push(h("button", {
      type: "button",
      class: "small danger",
      onclick: (e) => busy(e.currentTarget, async () => {
        if (!confirm(`Delete "${d.name}"? This revokes its access immediately.`)) return;
        await api(`/api/devices/${d.id}`, { method: "DELETE" });
        toast(`${d.name} deleted`);
        loadDevices();
      }),
    }, "Delete"));

    return h("article", { class: "card device" },
      h("div", { class: "device-head" },
        h("span", { class: `dot ${d.status}`, title: statusLabel }),
        h("h3", {}, d.name),
        toggle),
      h("dl", {}, rows.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])),
      h("div", { class: "device-actions" }, actions));
  }

  async function loadDevices() {
    const all = state.user.role === "admin" && $("#devices-all").checked;
    try {
      const devices = await api(`/api/devices?scope=${all ? "all" : "mine"}`);
      $("#device-list").replaceChildren(...devices.map((d) => deviceCard(d, all)));
      $("#devices-empty").hidden = devices.length > 0;
    } catch (err) {
      if (err.status !== 401) toast(err.message, true);
    }
  }

  $("#devices-all").addEventListener("change", loadDevices);

  const addDialog = $("#add-device-dialog");
  $("#add-device-btn").addEventListener("click", () => {
    $("#add-device-form").reset();
    $(".error", addDialog).hidden = true;
    addDialog.showModal();
  });

  $("#add-device-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const raw = formData(form);
    const body = { name: raw.name.trim() };
    if (raw.expires_in_days) body.expires_in_days = Number(raw.expires_in_days);
    if (raw.public_key && raw.public_key.trim()) body.public_key = raw.public_key.trim();
    const errorEl = $(".error", form);
    const button = $("button[type=submit]", form);
    button.disabled = true;
    try {
      const prof = await api("/api/devices", { method: "POST", body });
      addDialog.close();
      showProfile(prof);
      loadDevices();
    } catch (err) {
      errorEl.textContent = err.message;
      errorEl.hidden = false;
    } finally {
      button.disabled = false;
    }
  });

  let currentProfile = null;
  function showProfile(prof) {
    currentProfile = prof;
    $("#profile-title").textContent = `Profile: ${prof.device.name}`;
    $("#profile-warning").textContent = prof.private_key_included
      ? "Save it now: the private key is shown only once and is not stored on the server. " +
        "Scan the QR code with the WireGuard app or download the file."
      : "This profile has no private key. Paste the private key you generated on the device " +
        "into the PrivateKey line.";
    const qr = $("#profile-qr");
    qr.hidden = !prof.qr_svg;
    if (prof.qr_svg) qr.src = prof.qr_svg;
    $("#profile-config").textContent = prof.config;
    $("#profile-dialog").showModal();
  }

  $("#profile-dialog").addEventListener("close", () => {
    // Drop the private key from memory and the DOM as soon as the dialog closes.
    currentProfile = null;
    $("#profile-config").textContent = "";
    $("#profile-qr").removeAttribute("src");
  });

  $("#profile-download").addEventListener("click", () => {
    if (currentProfile) download(currentProfile.filename, currentProfile.config);
  });

  $("#profile-copy").addEventListener("click", async () => {
    if (!currentProfile) return;
    try {
      await navigator.clipboard.writeText(currentProfile.config);
      toast("Copied to clipboard");
    } catch {
      toast("Copy failed - select the text manually", true);
    }
  });

  $$("[data-close]").forEach((btn) => btn.addEventListener("click", () => btn.closest("dialog").close()));

  // --- Account ------------------------------------------------------------------------

  function renderAccount() {
    const on = state.user.totp_enabled;
    $("#totp-off").hidden = on;
    $("#totp-on").hidden = !on;
    $("#totp-enroll").hidden = true;
  }

  $("#password-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    await busy($("button", form), async () => {
      const data = await api("/api/auth/password", { method: "POST", body: formData(form) });
      setToken(data.access_token);
      state.user = data.user;
      form.reset();
      toast("Password updated; other sessions were signed out");
    });
  });

  $("#totp-setup-btn").addEventListener("click", (e) => busy(e.currentTarget, async () => {
    const data = await api("/api/auth/totp/setup", { method: "POST" });
    $("#totp-qr").src = data.qr_svg;
    $("#totp-secret").textContent = data.secret;
    $("#totp-off").hidden = true;
    $("#totp-enroll").hidden = false;
  }));

  $("#totp-enroll").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    await busy($("button", form), async () => {
      state.user = await api("/api/auth/totp/enable", { method: "POST", body: formData(form) });
      form.reset();
      $("#totp-secret").textContent = "";
      $("#totp-qr").removeAttribute("src");
      renderAccount();
      toast("Two-factor authentication enabled");
    });
  });

  $("#totp-on").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    await busy($("button", form), async () => {
      state.user = await api("/api/auth/totp/disable", { method: "POST", body: formData(form) });
      form.reset();
      renderAccount();
      toast("Two-factor authentication disabled");
    });
  });

  // --- Users (admin) ------------------------------------------------------------------

  function userRow(u) {
    const locked = u.locked_until && new Date(u.locked_until) > new Date();
    const status = !u.enabled
      ? h("span", { class: "pill bad" }, "Disabled")
      : locked ? h("span", { class: "pill warn" }, "Locked") : h("span", { class: "pill ok" }, "Active");
    const patch = (body, msg) => async (e) => busy(e.currentTarget, async () => {
      await api(`/api/admin/users/${u.id}`, { method: "PATCH", body });
      toast(msg);
      loadUsers();
    });
    const self = u.id === state.user.id;
    const buttons = [
      h("button", { type: "button", class: "small ghost", onclick: patch({ enabled: !u.enabled }, `${u.username} ${u.enabled ? "disabled" : "enabled"}`), disabled: self }, u.enabled ? "Disable" : "Enable"),
      h("button", { type: "button", class: "small ghost", onclick: patch({ role: u.role === "admin" ? "user" : "admin" }, "Role updated"), disabled: self }, u.role === "admin" ? "Make user" : "Make admin"),
      h("button", {
        type: "button",
        class: "small ghost",
        onclick: (e) => busy(e.currentTarget, async () => {
          const password = await ask(`Reset password for ${u.username}`, "New password", "password");
          if (!password) return;
          await api(`/api/admin/users/${u.id}`, { method: "PATCH", body: { password } });
          toast("Password reset; the user's sessions were revoked");
        }),
      }, "Reset password"),
    ];
    if (locked) buttons.push(h("button", { type: "button", class: "small ghost", onclick: patch({ unlock: true }, "Account unlocked") }, "Unlock"));
    if (u.totp_enabled && !self) buttons.push(h("button", { type: "button", class: "small ghost", onclick: patch({ reset_totp: true }, "2FA reset") }, "Reset 2FA"));
    buttons.push(h("button", {
      type: "button",
      class: "small danger",
      disabled: self,
      onclick: (e) => busy(e.currentTarget, async () => {
        if (!confirm(`Delete ${u.username} and all of their devices?`)) return;
        await api(`/api/admin/users/${u.id}`, { method: "DELETE" });
        toast(`${u.username} deleted`);
        loadUsers();
      }),
    }, "Delete"));

    return h("tr", {},
      h("td", {}, h("strong", {}, u.username), self ? h("span", { class: "muted" }, " (you)") : null),
      h("td", {}, u.role),
      h("td", {}, status),
      h("td", {}, u.totp_enabled ? "On" : "Off"),
      h("td", {}, `${u.device_count}${u.max_devices ? ` / ${u.max_devices}` : ""}`),
      h("td", { title: absTime(u.last_login_at) }, relTime(u.last_login_at)),
      h("td", {}, h("div", { class: "row-actions" }, buttons)));
  }

  async function loadUsers() {
    try {
      const users = await api("/api/admin/users");
      $("#user-rows").replaceChildren(...users.map(userRow));
    } catch (err) {
      if (err.status !== 401) toast(err.message, true);
    }
  }

  $("#user-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const raw = formData(form);
    const body = { username: raw.username.trim(), password: raw.password, role: raw.role };
    if (raw.max_devices) body.max_devices = Number(raw.max_devices);
    await busy($("button", form), async () => {
      await api("/api/admin/users", { method: "POST", body });
      form.reset();
      toast(`User ${body.username} created`);
      loadUsers();
    });
  });

  // --- Server (admin) -----------------------------------------------------------------

  function renderServer(s) {
    const stat = (value, label) => h("div", { class: "card stat" }, h("div", { class: "value" }, value), h("div", { class: "label" }, label));
    $("#server-stats").replaceChildren(
      stat(s.online_peers, "Online now"),
      stat(s.active_peers, "Active peers"),
      stat(`${s.total_devices} / ${s.address_capacity}`, "Devices / capacity"),
      stat(s.total_users, "Users"));
    const rows = [
      ["Interface", `${s.interface} (${s.interface_up ? "up" : "down"}, ${s.backend} backend)`],
      ["Endpoint", s.endpoint],
      ["Server public key", s.public_key],
      ["IPv4 subnet", s.subnet_v4],
      ["IPv6 subnet", s.subnet_v6 || "disabled"],
      ["Client DNS", s.dns.join(", ") || "-"],
      ["Client isolation", s.client_isolation ? "on (peers cannot reach each other)" : "off"],
      ["Last sync", s.last_sync_at ? `${absTime(s.last_sync_at)} (${relTime(s.last_sync_at)})` : "never"],
      ["Sync error", s.last_sync_error || "none"],
      ["Version", s.version],
    ];
    $("#server-info").replaceChildren(...rows.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
  }

  async function loadServer() {
    try {
      renderServer(await api("/api/admin/server"));
    } catch (err) {
      if (err.status !== 401) toast(err.message, true);
    }
  }

  $("#sync-btn").addEventListener("click", (e) => busy(e.currentTarget, async () => {
    const s = await api("/api/admin/sync", { method: "POST" });
    renderServer(s);
    toast(s.last_sync_error ? `Sync failed: ${s.last_sync_error}` : "WireGuard configuration synced", Boolean(s.last_sync_error));
  }));

  // --- Audit (admin) ------------------------------------------------------------------

  async function loadAudit() {
    const filter = $("#audit-filter").value.trim();
    try {
      const events = await api(`/api/admin/audit?limit=200${filter ? `&action=${encodeURIComponent(filter)}` : ""}`);
      $("#audit-rows").replaceChildren(...events.map((ev) => h("tr", {},
        h("td", { title: ev.created_at }, absTime(ev.created_at)),
        h("td", {}, ev.actor || "-"),
        h("td", {}, h("code", {}, ev.action)),
        h("td", {}, ev.target || "-"),
        h("td", {}, ev.ip || "-"),
        h("td", { class: "details" }, ev.details || ""))));
    } catch (err) {
      if (err.status !== 401) toast(err.message, true);
    }
  }

  let auditDebounce;
  $("#audit-filter").addEventListener("input", () => {
    clearTimeout(auditDebounce);
    auditDebounce = setTimeout(loadAudit, 300);
  });

  // --- Boot ---------------------------------------------------------------------------

  (async () => {
    if (!state.token) return signedOut();
    try {
      signedIn(await api("/api/auth/me"));
    } catch {
      signedOut();
    }
  })();
})();
