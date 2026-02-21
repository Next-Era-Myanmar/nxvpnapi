const state = {
  apiBase: localStorage.getItem("nxvpn_api_base") || "http://127.0.0.1:8080",
  accessToken: localStorage.getItem("nxvpn_access_token") || "",
  refreshToken: localStorage.getItem("nxvpn_refresh_token") || "",
  currentUser: null,
  users: [],
  outlineKeys: [],
};

const el = (id) => document.getElementById(id);

const refs = {
  apiBaseUrl: el("apiBaseUrl"),
  saveApiBaseBtn: el("saveApiBaseBtn"),
  loginSection: el("loginSection"),
  dashboardSection: el("dashboardSection"),
  loginForm: el("loginForm"),
  logoutBtn: el("logoutBtn"),
  currentUserText: el("currentUserText"),
  statusText: el("statusText"),
  refreshUsersBtn: el("refreshUsersBtn"),
  refreshOutlineBtn: el("refreshOutlineBtn"),
  usersTbody: el("usersTbody"),
  outlineTbody: el("outlineTbody"),
  createUserForm: el("createUserForm"),
  createOutlineForm: el("createOutlineForm"),
  outlineFilterForm: el("outlineFilterForm"),
  changeMyPasswordForm: el("changeMyPasswordForm"),
};

function notify(msg, isError = false) {
  refs.statusText.textContent = msg;
  refs.statusText.className = isError ? "text-sm text-red-300" : "text-sm text-cyan-200";
}

function toNaiveDateTime(value) {
  if (!value) return null;
  return value.length === 16 ? `${value}:00` : value;
}

function setTokens(accessToken, refreshToken) {
  state.accessToken = accessToken || "";
  state.refreshToken = refreshToken || "";
  localStorage.setItem("nxvpn_access_token", state.accessToken);
  localStorage.setItem("nxvpn_refresh_token", state.refreshToken);
}

async function api(path, options = {}, allowRefresh = true) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (options.auth !== false && state.accessToken) headers.Authorization = `Bearer ${state.accessToken}`;

  const res = await fetch(`${state.apiBase}${path}`, { ...options, headers });

  if (res.status === 401 && allowRefresh && options.auth !== false && state.refreshToken) {
    const ok = await refreshTokens();
    if (ok) return api(path, options, false);
  }

  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.message || `Request failed (${res.status})`);
  return data;
}

async function refreshTokens() {
  try {
    const data = await api(
      "/auth/refresh",
      {
        method: "POST",
        auth: false,
        body: JSON.stringify({ refresh_token: state.refreshToken }),
      },
      false
    );
    setTokens(data.access_token, data.refresh_token);
    return true;
  } catch (_) {
    return false;
  }
}

async function loadMe() {
  state.currentUser = await api("/me");
  refs.currentUserText.textContent = `${state.currentUser.username} (${state.currentUser.type_})`;
}

function renderUsers(users) {
  state.users = users;
  refs.usersTbody.innerHTML = users
    .map(
      (u) => `
      <tr class="border-t border-slate-800">
        <td class="py-2 pr-2">${u.id}</td>
        <td class="py-2 pr-2">${u.username}</td>
        <td class="py-2 pr-2">${u.contact_email || "-"}</td>
        <td class="py-2 pr-2">${getExpireStatus(u.expired_at)}</td>
        <td class="py-2 pr-2">${u.type_}</td>
        <td class="py-2 pr-2 flex flex-wrap gap-1">
          <button class="btn-secondary !h-8 !text-xs" data-user-action="update" data-user-id="${u.id}">Update</button>
          <button class="btn-secondary !h-8 !text-xs" data-user-action="reset" data-user-id="${u.id}">Reset PW</button>
          <button class="btn-secondary !h-8 !text-xs" data-user-action="assign" data-user-id="${u.id}">Assign Parent</button>
        </td>
      </tr>
    `
    )
    .join("");
}

function getExpireStatus(expiredAt) {
  if (!expiredAt) return "No expiry";
  const expireDate = new Date(expiredAt);
  if (Number.isNaN(expireDate.getTime())) return "Invalid date";
  return expireDate <= new Date() ? "Expired" : "Active";
}

function renderOutlineKeys(rows) {
  state.outlineKeys = rows;
  refs.outlineTbody.innerHTML = rows
    .map(
      (k) => `
      <tr class="border-t border-slate-800">
        <td class="py-2 pr-2">${k.id}</td>
        <td class="py-2 pr-2">${k.name || ""}</td>
        <td class="py-2 pr-2">${k.parent_id ?? "-"}</td>
        <td class="py-2 pr-2 flex flex-wrap gap-1">
          <button class="btn-secondary !h-8 !text-xs" data-outline-action="update" data-outline-id="${k.id}">Update</button>
          <button class="btn-danger !h-8 !text-xs" data-outline-action="delete" data-outline-id="${k.id}">Delete</button>
        </td>
      </tr>
    `
    )
    .join("");
}

async function loadUsers() {
  const data = await api("/users");
  renderUsers(data || []);
}

async function loadOutlineKeys() {
  const parentId = el("filterParentId").value.trim();
  const parentsOnly = el("filterParentsOnly").checked;
  const params = new URLSearchParams();
  if (parentsOnly) params.set("parents_only", "true");
  else if (parentId) params.set("parent_id", parentId);
  const query = params.toString() ? `?${params.toString()}` : "";
  const rows = await api(`/outline-keys${query}`);
  renderOutlineKeys(rows || []);
}

async function initDashboard() {
  await loadMe();
  if (state.currentUser.type_ !== "admin") throw new Error("Only admin can use this panel.");
  await Promise.all([loadUsers(), loadOutlineKeys()]);
}

function setView(loggedIn) {
  refs.loginSection.classList.toggle("hidden", loggedIn);
  refs.dashboardSection.classList.toggle("hidden", !loggedIn);
  refs.logoutBtn.classList.toggle("hidden", !loggedIn);
}

refs.saveApiBaseBtn.addEventListener("click", () => {
  state.apiBase = refs.apiBaseUrl.value.trim().replace(/\/$/, "");
  localStorage.setItem("nxvpn_api_base", state.apiBase);
  notify(`API base set to ${state.apiBase}`);
});

refs.loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const username = el("loginUsername").value.trim();
    const password = el("loginPassword").value;
    const data = await api("/auth/login", {
      method: "POST",
      auth: false,
      body: JSON.stringify({ username, password }),
    });
    setTokens(data.access_token, data.refresh_token);
    await initDashboard();
    setView(true);
    notify("Login success.");
  } catch (err) {
    notify(err.message, true);
  }
});

refs.logoutBtn.addEventListener("click", () => {
  setTokens("", "");
  state.currentUser = null;
  setView(false);
  notify("Logged out.");
});

refs.refreshUsersBtn.addEventListener("click", () => loadUsers().catch((e) => notify(e.message, true)));
refs.refreshOutlineBtn.addEventListener("click", () => loadOutlineKeys().catch((e) => notify(e.message, true)));
refs.outlineFilterForm.addEventListener("submit", (e) => {
  e.preventDefault();
  loadOutlineKeys().catch((err) => notify(err.message, true));
});

refs.createUserForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("/users", {
      method: "POST",
      body: JSON.stringify({
        display_name: el("createDisplayName").value.trim() || null,
        username: el("createUsername").value.trim(),
        password: el("createPassword").value,
        contact_email: el("createContactEmail").value.trim() || null,
        expired_at: toNaiveDateTime(el("createExpiredAt").value),
        type: el("createType").value,
      }),
    });
    refs.createUserForm.reset();
    await loadUsers();
    notify("User created.");
  } catch (err) {
    notify(err.message, true);
  }
});

refs.createOutlineForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("/outline-keys", {
      method: "POST",
      body: JSON.stringify({
        name: el("outlineName").value.trim(),
        outline_key: el("outlineKeyValue").value.trim() || null,
        country: el("outlineCountry").value.trim() || null,
        parent_id: el("outlineParentId").value ? Number(el("outlineParentId").value) : null,
      }),
    });
    refs.createOutlineForm.reset();
    await loadOutlineKeys();
    notify("Outline key created.");
  } catch (err) {
    notify(err.message, true);
  }
});

refs.changeMyPasswordForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const currentPassword = el("myCurrentPassword").value;
    const newPassword = el("myNewPassword").value;
    await api("/me/change-password", {
      method: "POST",
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    });
    refs.changeMyPasswordForm.reset();
    notify("Password changed.");
  } catch (err) {
    notify(err.message, true);
  }
});

window.updateUserPrompt = async (id) => {
  const current = state.users.find((u) => u.id === id);
  if (!current) return;
  try {
    const nextDisplayName = prompt("Display name:", current.display_name || "") ?? "";
    const nextEmail = prompt("Contact email:", current.contact_email || "") ?? "";
    const nextType = prompt("Type (admin/user):", current.type_) ?? current.type_;
    const nextExpired = prompt("expired_at (YYYY-MM-DDTHH:mm:ss or blank):", current.expired_at || "") ?? "";
    await api(`/users/${id}`, {
      method: "PATCH",
      body: JSON.stringify({
        display_name: nextDisplayName || null,
        contact_email: nextEmail || null,
        type: nextType || null,
        expired_at: nextExpired || null,
      }),
    });
    await loadUsers();
    notify(`User ${id} updated.`);
  } catch (err) {
    notify(err.message, true);
  }
};

window.resetPasswordPrompt = async (id) => {
  const newPassword = prompt("New password:");
  if (!newPassword) return;
  try {
    await api(`/users/${id}/reset-password`, {
      method: "POST",
      body: JSON.stringify({ new_password: newPassword }),
    });
    notify(`User ${id} password reset.`);
  } catch (err) {
    notify(err.message, true);
  }
};

window.assignParentPrompt = async (id) => {
  const parentId = prompt("Parent outline key id:");
  if (!parentId) return;
  try {
    await api(`/users/${id}/assign-parent-key`, {
      method: "POST",
      body: JSON.stringify({ parent_outline_key_id: Number(parentId) }),
    });
    notify(`Assigned parent key ${parentId} to user ${id}.`);
  } catch (err) {
    notify(err.message, true);
  }
};

window.updateOutlinePrompt = async (id) => {
  const current = state.outlineKeys.find((k) => k.id === id);
  if (!current) return;
  try {
    const nextName = prompt("Name:", current.name || "") ?? "";
    const nextCountry = prompt("Country:", current.country || "") ?? "";
    const nextParent = prompt("parent_id (blank for null):", current.parent_id == null ? "" : current.parent_id) ?? "";
    const nextOutlineKey = prompt("Outline key (blank for null):", current.outline_key || "") ?? "";
    await api(`/outline-keys/${id}`, {
      method: "PATCH",
      body: JSON.stringify({
        name: nextName || null,
        country: nextCountry || null,
        parent_id: nextParent === "" ? null : Number(nextParent),
        outline_key: nextOutlineKey || null,
      }),
    });
    await loadOutlineKeys();
    notify(`Outline key ${id} updated.`);
  } catch (err) {
    notify(err.message, true);
  }
};

window.deleteOutlineKey = async (id) => {
  if (!confirm(`Delete outline key ${id}?`)) return;
  try {
    await api(`/outline-keys/${id}`, { method: "DELETE" });
    await loadOutlineKeys();
    notify(`Outline key ${id} deleted.`);
  } catch (err) {
    notify(err.message, true);
  }
};

refs.usersTbody.addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-user-action]");
  if (!btn) return;
  const id = Number(btn.dataset.userId);
  if (btn.dataset.userAction === "update") window.updateUserPrompt(id);
  if (btn.dataset.userAction === "reset") window.resetPasswordPrompt(id);
  if (btn.dataset.userAction === "assign") window.assignParentPrompt(id);
});

refs.outlineTbody.addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-outline-action]");
  if (!btn) return;
  const id = Number(btn.dataset.outlineId);
  if (btn.dataset.outlineAction === "update") window.updateOutlinePrompt(id);
  if (btn.dataset.outlineAction === "delete") window.deleteOutlineKey(id);
});

async function boot() {
  refs.apiBaseUrl.value = state.apiBase;
  if (!state.accessToken || !state.refreshToken) return setView(false);
  try {
    await initDashboard();
    setView(true);
    notify("Session restored.");
  } catch (err) {
    setTokens("", "");
    setView(false);
    notify(err.message, true);
  }
}

boot();
