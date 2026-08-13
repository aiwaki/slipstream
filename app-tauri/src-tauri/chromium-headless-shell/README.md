# Materialized Chromium headless shell

Release and packaged-test workflows replace this placeholder directory with the
version-, archive-, and SHA-256-pinned runtime declared in
`vendor/chromium-headless-shell/SOURCE.json` by running
`scripts/materialize_chromium_headless_shell.py`.

Do not commit the downloaded runtime. The installed bundle must contain the
complete materialized directory, including `chrome-headless-shell`, its license,
support files, and the generated private `manifest.json`.
