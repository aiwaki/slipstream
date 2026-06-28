// Settings window: native-style tab switching + wiring to the Rust commands.
// Uses the global Tauri API (withGlobalTauri) so no bundler/import-map is needed
// — a bare ES import of @tauri-apps/api would fail to resolve and kill the whole
// script (which is why the tabs went dead).
const invoke = window.__TAURI__?.core?.invoke;

// ---- toolbar tabs ----
const tabs = document.querySelectorAll(".tab");
const panels = document.querySelectorAll(".panel");
tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    tabs.forEach((t) => t.classList.toggle("is-active", t === tab));
    const id = "panel-" + tab.dataset.panel;
    panels.forEach((p) => p.classList.toggle("is-active", p.id === id));
  });
});

// ---- helpers ----
async function tryInvoke(cmd, args) {
  if (!invoke) return null;
  try {
    return await invoke(cmd, args);
  } catch (e) {
    console.warn(cmd, e);
    return null;
  }
}

// ---- Geph save ----
document.getElementById("geph-save")?.addEventListener("click", async () => {
  const secret = document.getElementById("geph-secret").value.trim();
  const exit = document.getElementById("geph-exit").value;
  const plan = document.getElementById("geph-plan");
  await tryInvoke("save_geph_config", { secret, exit });
  plan.textContent = secret ? "Plus / paid (verifying…)" : "Free tier (5 GB / mo)";
});

// ---- General: launch at login ----
document.getElementById("launch")?.addEventListener("change", (e) => {
  tryInvoke("set_launch_at_login", { enabled: e.target.checked });
});

// ---- About: check updates ----
document.getElementById("check-updates")?.addEventListener("click", () => {
  tryInvoke("trigger_update_check");
});

// ---- live engine status (Network panel) ----
async function refreshStatus() {
  const st = await tryInvoke("daemon_status");
  const el = document.getElementById("net-status");
  if (!el) return;
  if (!st || !st.state || st.state === "off") {
    el.textContent = "Off";
  } else if (st.state === "dormant") {
    el.textContent = "Dormant (VPN active)";
  } else {
    const g = st.geph === "up" ? " · Geph tunnel on" : "";
    el.textContent = `Active — ${st.conns ?? 0} connections${g}`;
  }
}
refreshStatus();
setInterval(refreshStatus, 2000);
