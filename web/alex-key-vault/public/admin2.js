const $ = (id) => document.getElementById(id);
let sessionToken = "";
let workerUrl = "";
let users = [];
let refreshTimer = 0;

function setStatus(message, kind = "") {
  $("status").textContent = message;
  $("status").className = kind;
}

async function request(url, options = {}) {
  const response = await fetch(url, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok || body.ok === false) throw new Error(body.error?.message || `Request failed: ${response.status}`);
  return body;
}

function relativeTime(timestamp) {
  const seconds = Math.max(0, Math.floor((Date.now() - Number(timestamp)) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function render() {
  const query = $("search").value.trim().toLowerCase();
  const visible = users.filter((user) => user.id.includes(query));
  $("users").replaceChildren(...visible.map((user) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td class="userId" title="${user.id}">${user.id.slice(0, 16)}…${user.id.slice(-8)}</td>
      <td>${relativeTime(user.last_seen)}</td>
      <td class="profile">${user.last_profile}</td>
      <td class="${user.active ? "active" : ""}">${user.active}</td>
      <td>${user.used} / 30</td>
      <td>${user.bonus}</td>
      <td>${user.available}</td>
      <td><div class="creditCell"><input type="number" min="1" max="10000" value="10" aria-label="Credits for ${user.id.slice(0, 12)}"><button type="button">Grant</button></div></td>`;
    row.querySelector("button").addEventListener("click", () => grant(user, row));
    return row;
  }));
  $("emptyState").hidden = visible.length !== 0;
}

async function loadUsers() {
  if (!sessionToken) return;
  try {
    const body = await request(`${workerUrl}/v2/admin/users`, { headers: { Authorization: `Bearer ${sessionToken}` } });
    users = body.users;
    $("metricUsers").textContent = body.summary.users.toLocaleString();
    $("metricActive").textContent = body.summary.active.toLocaleString();
    $("metricUsed").textContent = body.summary.used_this_hour.toLocaleString();
    $("metricBonus").textContent = body.summary.bonus_balance.toLocaleString();
    $("updatedAt").textContent = `Synced ${new Date().toLocaleTimeString()}`;
    $("liveState").textContent = "Live";
    $("liveState").className = "live";
    setStatus(`${users.length} hashed identities`, "success");
    render();
  } catch (error) {
    setStatus(error.message, "error");
    if (/session|unauthorized|expired/i.test(error.message)) signOut();
  }
}

async function grant(user, row) {
  const input = row.querySelector("input");
  const credits = Number(input.value);
  const button = row.querySelector("button");
  button.disabled = true;
  try {
    await request(`${workerUrl}/v2/admin/credits`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${sessionToken}` },
      body: JSON.stringify({ user_id: user.id, credits })
    });
    setStatus(`Granted ${credits} credits to ${user.id.slice(0, 12)}…`, "success");
    await loadUsers();
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    button.disabled = false;
  }
}

function signOut() {
  sessionToken = "";
  workerUrl = "";
  users = [];
  clearInterval(refreshTimer);
  $("dashboard").hidden = true;
  $("signOut").hidden = true;
  $("loginPanel").hidden = false;
  $("liveState").textContent = "Locked";
  $("liveState").className = "";
  setStatus("Admin session required.");
}

$("loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = $("password").value;
  $("loginStatus").textContent = "";
  try {
    const session = await request("/api/admin-session", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password }) });
    sessionToken = session.token;
    workerUrl = session.worker_url.replace(/\/$/, "");
    $("password").value = "";
    $("loginPanel").hidden = true;
    $("dashboard").hidden = false;
    $("signOut").hidden = false;
    await loadUsers();
    refreshTimer = setInterval(loadUsers, 15000);
  } catch (error) {
    $("loginStatus").textContent = error.message;
  }
});
$("refresh").addEventListener("click", loadUsers);
$("signOut").addEventListener("click", signOut);
$("search").addEventListener("input", render);
