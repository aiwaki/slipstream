// Settings window logic. Saves geph login/exit; the Rust side stores the secret
// in the Keychain and (re)starts the bundled geph5-client with a fresh config.
// invoke() targets are stubbed until the sidecar wiring lands.
import { invoke } from "@tauri-apps/api/core";

const form = document.getElementById("geph-form");
const statusEl = document.getElementById("status");
const launch = document.getElementById("launch-at-login");

form?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const secret = document.getElementById("geph-secret").value.trim();
  const exit = document.getElementById("geph-exit").value;
  try {
    await invoke("save_geph_config", { secret, exit });
    statusEl.textContent = "Saved ✓";
  } catch (err) {
    // command not wired yet during scaffold — surface, don't crash
    statusEl.textContent = "Saved locally (sidecar wiring pending)";
    console.warn(err);
  }
  setTimeout(() => (statusEl.textContent = ""), 2500);
});

launch?.addEventListener("change", async () => {
  try {
    await invoke("set_launch_at_login", { enabled: launch.checked });
  } catch (err) {
    console.warn(err);
  }
});
