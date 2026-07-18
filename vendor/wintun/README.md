# Wintun Source Record

Slipstream does not build or sign a Windows kernel driver. This directory pins
the official Wintun 0.14.1 package that is being evaluated for the Windows
packet-adapter boundary.

No Wintun binary is vendored here. A future Windows packaging workflow must
download the exact archive recorded in `SOURCE.json`, verify its archive and
architecture-specific DLL hashes, verify Authenticode and the recorded signer,
and preserve the package's `LICENSE.txt`. It must distribute the unmodified
official `wintun.dll` beside software that uses only the permitted Wintun API.

The source record is not permission to activate a TUN adapter. Runtime loading,
owned route installation, packet-stack integration, rollback, and coexistence
qualification remain separate reviewed gates.
