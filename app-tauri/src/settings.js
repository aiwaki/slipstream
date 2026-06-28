// Settings window wiring. Uses the global Tauri API (withGlobalTauri) so no
// bundler is needed — a bare ES import of @tauri-apps/api would fail to resolve.
const invoke = window.__TAURI__?.core?.invoke;

async function tryInvoke(cmd, args) {
  if (!invoke) return null;
  try {
    return await invoke(cmd, args);
  } catch (e) {
    console.warn(cmd, e);
    return null;
  }
}

// Geph: save secret + exit
document.getElementById("geph-save")?.addEventListener("click", async () => {
  const secret = document.getElementById("geph-secret").value.trim();
  const exit = document.getElementById("geph-exit").value;
  await tryInvoke("save_geph_config", { secret, exit });
  document.getElementById("geph-plan").textContent = secret
    ? "Plus / paid (verifying…)"
    : "Free tier";
});

// General: launch at login
document.getElementById("launch")?.addEventListener("change", (e) => {
  tryInvoke("set_launch_at_login", { enabled: e.target.checked });
});

// About: check for updates
document.getElementById("check-updates")?.addEventListener("click", () => {
  tryInvoke("trigger_update_check");
});
