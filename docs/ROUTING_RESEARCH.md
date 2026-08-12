# Routing Research Notes

Updated: 2026-08-12

Purpose: keep a compact record of routing research, graph-tool status, and
safe follow-ups. This is an engineering note, not user-facing documentation.

## Findings Index

| Date | Topic | Status | Decision | Next action |
|---|---|---|---|---|
| 2026-08-12 | Packaged pending-navigation result raced Chrome cleanup and worker-relay recursion | Reproduced from exact job logs; bounded correction implemented in PR #332 | Documentation-only head `79abf93cfa61a448ed7681567f8f3c226b781cd1` left product code unchanged but packaged job `94021442646` failed after roots `original -> worker`: the worker logged `browser_worker_failed:submit_rejected`, then the daemon retried stale secondary jobs as `claimed_job_invalid`. The previous exact code had passed packaged job `94019999739`, making this a real intermittent timing boundary. Source inspection showed the Rust worker performed exact Chrome cleanup before submitting its eight-second observation; that cleanup can consume several seconds. If the original relay closed first, pruning removed its capability and the simultaneously idle worker relay could mint another same-host job. The worker now submits first but still cleans up unconditionally before exit. A submitted result receives a two-second post-result exact-host guard, while a live capability invalidated before worker completion remains guarded through its original 30-second expiry. Capabilities and guards share one 32-entry admission bound; a new job is rejected at capacity rather than evicting live authority or an unexpired guard. This keeps the normal next recovery stage fast without permitting abnormal teardown or host churn to recreate a stale worker job. | Require full local tests, all six PR checks including repeated packaged composition, review resolution, merge, and fresh exact-main CI/audit/native Windows evidence. |
| 2026-08-12 | Composed local pending-navigation recovery | PR #329 implementation head passed all six required checks; release gates still open | The daemon composes the closed broker, one-shot capability, lazy Aqua worker, and exact stale cleanup without adding an idle browser or browser extension. Pinned Chromium job `93979264186` independently proved extension-free retry: after the first top-level request remained pending and closed without a response, Chrome made exactly one second root request and loaded one CSS, JavaScript, image, and ready callback in 11,068 ms. Packaged job `93979264195` passed the hidden sandboxed worker in 13,170 ms and the later install/uninstall lifecycle. Deterministic traffic coverage proves that only the exact relay-bound result advances the local stage. Codebase graph discovery was retried first and again returned `Transport closed`, so inspection stayed limited to the existing relay, IPC, launcher, and lifecycle seams. | Require the docs-only successor checks and merge only the exact green head. Treat installed update, active-worker uninstall, idle cost, and complete composed original-navigation qualification as unresolved. |
| 2026-08-12 | Automatic local browser-signal delivery on unmanaged macOS | Official Chrome surfaces reviewed; no supported silent self-hosted extension install exists for ordinary unmanaged branded Chrome | Chrome's external-extension preference file on macOS must point to the Chrome Web Store and still presents an enable confirmation. A self-hosted extension may be force-installed silently only when Chrome is managed through MDM, MCX/domain membership, or Chrome Enterprise Core. Treating a personal installation as enterprise-managed would add external enrollment or machine policy ownership and is not the local zero-setup product path. Unified Headless Chrome can run extensions and is suitable for a bounded local worker experiment, but a separate synthetic navigation is not route authority unless it safely correlates to and completes the original user-visible navigation. Crawlee and `microlinkhq/browserless` are crawler/Puppeteer orchestration layers, while CloakBrowser and `puppeteer-real-browser` target anti-bot behavior; none supplies ownership of an existing user tab. | Add a headless Chrome for Testing qualification mode to the existing frozen-origin companion harness. Prove extension/native messaging and measure launch/RSS first, then add a closed original-navigation correlation fixture before considering runtime composition. |
| 2026-08-11 | Exact eight-second pending-navigation fixture crossed a floating-point cancellation boundary | Exact-main `checks` failed; the same source passed local, PR, and previous exact-main runs; runner value reproduces locally | Docs-only main `2635f59f742b63a553f0df20f57e79f625b9a2f9` passed audit `31523112491` and Windows `31523112520`, but CI `31523112515` computed `(last_downstream_at + 8.0) - last_downstream_at` as `7.999999999999986` in `test_unknown_handshake_only_idle_waits_for_browser_pending_signal`, so the production `>= 8.0` guard correctly rejected the nominal boundary. This is fixture arithmetic, not routing evidence. Keep `UNKNOWN_PRE_RESPONSE_IDLE = 8.0` and bracket the contract at one millisecond before and after the threshold. | Land the test-only correction, require its PR checks and fresh exact-main CI/audit/Windows evidence, then resume the Chrome Web Store distribution gate. |
| 2026-08-11 | Protected unpacked Chromium success did not transfer to a clean branded-Chrome profile | Exact protected artifact passed; controlled workstation transaction rolled back on the first browser smoke | Main `8fe21229994e0ddc643762d0ece2203bc79313cc` passed CI `31509795963`, audit `31511314605`, Windows `31509795798`, and protected owned-Geph run `31511415912`. Its artifact `9110154812` passed semantic v1/v2/v3, styled-resource, owned-Geph lifecycle, signature, manifest, and ZIP-integrity checks. Transaction `271C43D9-4906-4AF3-88E8-C2EF146A33ED` reached coherent active daemon state, but a fresh isolated headed branded Chrome kept `xpersonatoy.com` pending for 75 seconds and exact rollback restored all binary hashes and network/runtime invariants. The registered native-host manifest was present, yet the clean profile had no unpublished companion; the root log consequently contained no semantic or recovery event. The protected gate loads the source as an unpacked extension, so it proves the product path but not production distribution. This does not justify changing routing, byte-only authority, or the evidence ladder. | Land a deterministic store ZIP/provenance gate plus privacy/listing disclosures. Then require publisher review and a clean branded-Chrome profile with the exact published/enabled extension ID before another exact-main workstation transaction. |
| 2026-08-11 | Browser target remains pending as `about:blank` after valid TLS records | Workstation symptom reproduced; PR #313 review rejected byte-only closure and the branch now requires a browser-owned pending-navigation signal | Main `58a67d0262fc8331dae05e615aaa61ce032a41a6` passed CI `31431925679`, audit `31431925668`, Windows qualification `31431925670`, and protected run `31432845423`. Exact artifact `9079910704` passed the broad local/geo browser matrix in transactions `257E1EB0-1DED-4F17-8963-22550D568B9B` and `D64565C3-A494-4C82-8C15-ABB69275C259`, but fresh headed Chrome kept `xpersonatoy.com` pending for 75 seconds with and without QUIC. Copying the visible `about:blank` address yielded the target URL, proving an uncommitted navigation rather than a wrong destination. Direct Chrome used IPv4 `23.227.38.70:443`; owned Geph loaded the origin, and curl's Cloudflare challenge was not representative. Review correctly identified that a quiet WebSocket can share the same byte shape, so relay silence cannot be closure authority. Frozen semantic signal v3 now reports only a still-loading same-host top-level `pendingUrl` after eight seconds. The daemon correlates its privacy-bounded hostname/request start to one eligible live relay, advances only one incomplete local stage, and leaves the final relay open whenever independent confirmation is not actually scheduled or does not succeed. No hostname rule was added. Full verification passes Python/script `1105` plus `41` subtests, Chromium `24`, Safari `7`, Rust tray `84`, core `35`, Windows `241`, and userspace evaluation `40`/`40`, with all Clippy and continuity checks clean. | Update PR #313, resolve both review threads, and merge only when green. Then require exact-main gates and one fresh protected qualification; install only its artifact and place the real browser case early in a controlled smoke with exact rollback on first failure. |
| 2026-08-10 | Proven owned-Geph handoff arrived after the client TLS deadline | Exact workstation timing defect reproduced; bounded successor passes `1092` tests plus `41` subtests and every cross-language check | Main `38e601e7f52a21805a15b18d62147685431adc1f` passed CI `31423659071`, audit `31423659346`, Windows qualification `31423659158`, and protected run `31424182604`. Exact artifact `9076656013` reached active StatusV2 in transaction `C7208EA1-0999-4BD7-B6AC-3AEFFBDC5133`; broad local and geo smokes passed, but four Modrinth attempts ended before TLS payload and triggered exact rollback with DNS `111.88.96.50/51` and every external owner preserved. The private log showed the one-shot owned-Geph route finally receiving payload at approximately the original client's 15-second deadline. Post-rollback controls proved direct timeout, owned SOCKS HTTP `200` in about 1.3 seconds, and a complete production MemoryBIO TLS exchange through the same listener. The fix retains one 30-second exact-host request-only successor only after owned payload plus downstream/client close, binds the consumed claim to that normalized host, and tries it before the local ladder. It cannot chain, learn, persist, or affect protected/static routes or external state. No hostname rule was added. | Merge only with green PR checks, then require exact-main gates and one fresh protected qualification before another controlled install. Put Modrinth early in that smoke and roll back on first failure. |
| 2026-08-10 | Final unknown-host authorization races found by PR review | Fixed locally; `1087` tests plus `41` subtests pass | Five stale-authority windows remained after the initial Modrinth correction: browser eligibility preceded token reservation, a candidate-backed request could lose its already-spent request right while waiting for owned-Geph recovery, direct semantic/transport precursor workers were absent from noise invalidation, a new precursor could revive an old token, and one worker's cleanup could revive an overlapping precursor. Eligibility plus reservation now share the noise lock; a spent proof remains request-only through the bounded wait; both precursor registries are revoked; and the host marker remains until every precursor and confirmation-token owner has exited. No hostname rule or network-setting mutation was added. | Finish current-head review, then require exact-main CI/audit/Windows and one fresh protected qualification before installation. |
| 2026-08-10 | Complete Modrinth route proof was suppressed by unrelated unknown-host noise | Exact workstation defect reproduced; one-shot correction and deferred-learning hardening under review | Main `4dca2cb602c509ef081a10b85f59ef0b0996a314` passed CI `31400498678`, audit `31400495433`, Windows qualification `31400495510`, and protected owned-Geph run `31401394701`. Exact artifact `9067906813` reached active StatusV2 in transaction `A4FBBC17-F27F-4327-8171-A89E22C27B0C`; Steam, Google, Spotify, Discord updater/gateway, YouTube HTML, real headed-Chromium Googlevideo playback, CrystalIDEA, and ChatGPT transport returned payload. Four Modrinth attempts then ended before TLS payload, so immediate exact rollback restored the previous app, removed the root daemon/listener/private PF/runtime state, and preserved DNS `111.88.96.50/51`, proxy/PAC, default route, Telegram, and the pre-existing owned Geph PID. Post-rollback A/B proved direct Modrinth still timed out while the unchanged owned `:9954` listener returned a complete HTTP `200`. A no-PF production-stage probe independently reproduced system, app-owned DNS, and multiple local-strategy zero-payload closes. Code tracing then found that `note_zero_payload_route_failure()` retained the exact observations but refused to create a candidate whenever five arbitrary unknown hosts were noisy; `_try_unknown_owned_geph_route()` accepted only that candidate, so it never tested the known-live owned backend and emitted no Modrinth event. The correction preserves the global guard for confirmation and persistence but spends a complete exact zero-payload proof on one current replay-safe request. Authorization and stale candidate are marked spent before the first await; the observations remain until normal expiry so the global guard stays active, and every stage must be observed again before another one-shot. First payload remains mandatory and no learning worker is scheduled. Review found that an older post-drain marker could otherwise wait for noise expiry and revive persistent learning. The hardened reducer now discards all candidates and deferred markers and invalidates active confirmation authority as soon as network-wide noise is observed; only a fresh post-noise proof can restore learning authority. Follow-up race review proved that a quiet candidate also has to spend its exact proof before its first await and that regional-denial/incomplete-response workers must consult revoked authority inside their final persistence lock. Both paths now do so, preventing mid-dial noise from authorizing a second request or an already-running semantic worker from learning after the transition. Production noise writers now use the same lock as learned-route commits, removing the remaining final-check interleaving. No hostname rule was added. | Repeat the focused and full local checks, then complete PR review. After merge, require exact-main CI/audit/Windows and exactly one fresh protected qualification; install only that artifact and repeat the controlled browser plus unknown-host smoke with immediate rollback on first failure. |
| 2026-08-10 | Owned Geph accepted SOCKS while a reviewed target stream stalled | Exact runtime handoff defect reproduced; generic same-request fallback passes focused and daemon tests | Main `99da0eded9eaf0a0d629c9bd48f758b013f6d051` passed exact-main CI/audit/Windows and protected run `31389915668`. Artifact `9063320265` reached active StatusV2 in transaction `8EAF7313-02F9-44EE-90C6-F08F341A6E89`; Google, Spotify, Discord, YouTube, and Googlevideo passed, but Steam Store timed out during TLS setup. Exact rollback restored the prior app and preserved DNS `111.88.96.50/51` plus external state. Direct post-rollback Steam returned HTTP `200`, 1,061,394 bytes, in about one second. Code tracing proved that runtime Geph readiness ended at local SOCKS `CONNECT` plus ClientHello send, then committed to an unbounded relay without a target byte. The correction keeps the first flight replay-safe until one target byte arrives under a four-second absolute deadline; pre-payload timeout/EOF/reset closes only that stream, records the Geph failure before any successful fallback return, and continues through the frozen original destination. No hostname rule was added. | Complete full local and PR checks, exact-main gates, and exactly one fresh protected qualification. Install only that newly qualified artifact and require Steam early in the controlled smoke; roll back on the first failure. |
| 2026-08-10 | Owned-Geph replacement exposed SOCKS before its tunnel carried payload | Exact workstation race identified; generic readiness correction passes focused and full Python tests | Main `b9b989680abe4519a8ba2656697d83f175693a89` passed exact-main CI/audit/Windows and protected run `31380099738`; artifact `9059610687` reached active StatusV2 in transaction `7D29A3E8-1B4C-4E51-A2D8-8A2E6A5164C7`, but four incomplete-response smokes remained unlearned and ended `rejected`. The root log records two owned replacements followed immediately by backend-unavailable semantic probes. The user-owned Geph log contains no target tunnel in that window and shows authentication/session establishment completing only after listener startup. Code tracing confirmed that `execute_owned_geph_restart()` returned after exact PID, ownership, listener, and control liveness, and `_retry_semantic_geph_probe_after_owned_restart()` immediately called the target probe. The correction pins the successor and requires a bounded existing-portfolio HTTPS payload canary through the same PID before the target probe; no target rule or weaker proof was added. Exact rollback removed the root interception path and preserved DNS `111.88.96.50/51` plus external state. | Complete all language, browser, continuity, and diff checks; merge a small PR only when green. Then run exact-main gates and exactly one fresh protected qualification before another controlled install. |
| 2026-08-10 | Partial TLS watchdog never reached content confirmation; valid partial HTTP/2 DATA was rejected | Exact workstation failure reproduced; generic correction and review hardening pass focused tests | Qualified main `00c48edad207dfa53442b9b6b713b02908bdeb7e` and artifact `9045740737` reached active StatusV2 in transaction `82D444BE-2F5C-4E7F-85EE-01220B50474F`, but the first required `xpersonatoy.com` smoke twice returned HTTP/2 `200`, `15,041` bytes, and curl error `18` after about 6.6 seconds with no recovery event; exact rollback completed without changing user DNS or external state. Code tracing found that the six-second partial-record watchdog cancelled the relay before the fifteen-second content observer. It now preserves the exact public-IP candidate, but review confirmed that route-authorizing content confirmation must still wait for independent system, app-owned DNS, and two local-strategy failures. A read-only exact-address control exposed a second false negative: after valid HTTP/2 headers and 16,384 body bytes, the peer began a valid 8,192-byte DATA frame on stream 1 but delivered only 1,386 payload bytes before the deadline; the parser classified every partial frame as a protocol error. The correction recognizes only a fully validated unfinished DATA frame on the active response stream after prior body bytes. Review hardening accepts a complete nine-byte nonempty unpadded DATA header and rejects any partial frame whose declared data would exceed `Content-Length`. It does not learn from TLS bytes. Live controls report direct incomplete after 25 seconds and a complete `1,113,091`-byte identity response through the unchanged verified owned-Geph listener in about nine seconds. | Repeat the full local suite and PR gates after review hardening. Then require exact-main gates and one fresh protected qualification before another controlled install; install only that run's artifact and roll back on the first failed smoke. |
| 2026-08-09 | HTTP/2 partial-body confirmation disagreed with its HTTP/1.1 control | Root cause reproduced without PF mutation; protocol-aware correction implemented locally | Exact main `a38c6d12fe2ddc84059c7b77fd7bc97902d0b151` passed CI `30862641149`, audit `30862641178`, Windows qualification `30862641141`, and protected owned-Geph run `31326467025`. Its exact artifact reached active StatusV2 in controlled transaction `C17E2DFE-CC33-4FBE-8C61-8F76418D98C5` and passed Google, Spotify, Discord, YouTube plus a real Googlevideo fragment, Steam, CrystalIDEA, ChatGPT, and Modrinth. Four `xpersonatoy.com` HTTP/2 responses then returned `200` but ended with curl error `18` after 55-70 KiB, so exact rollback removed the daemon/PF/runtime state and preserved DNS `111.88.96.50/51`, both Geph owners, proxy/PAC, and default route. Code tracing showed that the client observation was HTTP/2 while the independent completion probe advertised no ALPN and sent HTTP/1.1, so a complete HTTP/1.1 response rejected the real HTTP/2 evidence. A no-PF live control with the new probe proved direct HTTP/2 incomplete. The owned-Geph HTTP/2 control then exposed two independent local false negatives: the origin ignored `Range` and completed at 1,045,719 bytes, above the old 512-KiB cap, and a six-second deadline stopped after 470,846 bytes. With the existing two-MiB semantic cap and a background-only 20-second deadline, the same owned listener completed all 1,045,719 bytes. No hostname rule was added. Automated review then found that a parser error after payload, a compressed partial response, an immediately handled graceful GOAWAY, GOAWAY interleaved inside an open header block, a new `PUSH_PROMISE` after graceful GOAWAY, an increasing repeated GOAWAY boundary, or an unfinished body exactly at the byte cap could falsely look incomplete. Protocol errors, compressed responses, capped responses, rejecting GOAWAY frames, illegal header-block interleaving, increasing GOAWAY boundaries, and post-GOAWAY new push streams now remain unknown. `GOAWAY(NO_ERROR)` permits only already eligible streams to finish outside a header block, and later GOAWAY frames may only retain or lower its `last_stream_id`. An exact-cap response remains valid only with `END_STREAM`, and a protocol or acknowledgement-write error recorded alongside completion keeps owned-Geph evidence unknown. Full local verification passes with `1047` Python tests plus `41` subtests, `255` script, `21` Chromium companion, `83` Rust tray, and `32` Rust core tests. A clean Python 3.13 PyInstaller build also runs its frozen daemon-free `--status` path with the new helper included. | Repeat PR review and merge only with green PR CI/audit. Then require exact-main gates and one fresh protected qualification before another controlled install. Include Weather regional-denial semantic smoke after the transport case passes. |
| 2026-08-09 | Weather root redirect differs from final regional-denial page | Read-only control confirms the existing semantic split | `www.weather.com` directly returned the generic regional-denial page, while the same host through owned Geph returned a complete bodyless `301` to `https://weather.com/`; the canonical `weather.com` origin then returned payload through the same owned listener. A bodyless redirect is valid HTTP completion but cannot satisfy the nonzero-payload route proof by itself. The existing Chromium companion follows the real browser navigation and remains responsible for final rendered denial plus one bounded reload. No hostname rule or transport relaxation is justified. | Preserve redirect and canonical-host separation in the controlled Weather smoke; do not treat a zero-byte redirect as a usable payload. |
| 2026-08-03 | Live Weather regional-denial control | Exact production helper detects the observed direct response | A read-only exact-IP HTTP/1.1 control on the workstation returned a complete `403`, `Content-Length: 48`, and `This content is no longer available in your area`. The first implementation incorrectly returned false because the shared route-usability helper intentionally rejects all `4xx`. HTTP framing completion is now a separate invariant from response usability: ordinary route qualification still rejects `4xx`, while the semantic canary may inspect a completely framed `2xx`-`4xx` response except `429`. The same production helper then returned `regional_denial=True` for the live response. No Slipstream process, PF, DNS, proxy/PAC/VPN, or Geph state was changed by this control. | Preserve both the synthetic `403` framing regression and the protected generic Chromium scenario; never weaken ordinary successful-response qualification. |
| 2026-08-03 | Browser-independent complete regional-denial canary | Implemented locally; broad daemon/traffic regressions pass | A rendered denial is invisible inside the intercepted TLS stream, but a second independent request can safely inspect the service root without decrypting browser traffic. For the first eligible unknown `system/plain` path, the daemon probes the exact observed public IP with normal hostname certificate validation, no cookies/path/query, identity encoding, a `128 KiB` cap, two-worker limit, eight-host-per-minute budget, and ten-minute exact-host cooldown. A complete body containing a strong generic regional-denial phrase can only schedule the existing owned-Geph semantic proof; it cannot learn a route by itself. Normal, compressed, incomplete, `429 local_rate_limited`, static/protected, and unowned-backend cases stop. This catches the observed Weather-style root denial without naming the service. It cannot diagnose a denial that exists only on another path or after JavaScript execution, and it cannot reload the already rendered page. | Complete the full suite and review, merge only with green PR CI/audit, then run exact-main and one protected account-backed qualification. Keep Chromium/Safari distribution as the complementary path-specific and reload mechanism. |
| 2026-08-03 | Partial HTTP/2 body and rendered regional denial are two generic failure classes, not site rules | Exact artifact rolled back; bounded transport trigger implemented; production companion delivery remains open | Exact main `40fac7693e229de34adb6988fdf7cd08b28d1cbf` passed CI `30845033722`, audit `30845035284`, native Windows `30845034732`, and protected run `30846312090`; artifact `8868928993` passed broad workstation smoke before four HTTP 200 / curl 18 partial-body responses forced exact rollback in transaction `8E4BA969-2C1D-4B89-B9FA-71478789FF9E`. No daemon event existed because the client closed first after complete TLS records and relay teardown cancelled the idle observer. The generic correction requires two bounded unknown `system/plain` observations and then only schedules the independent local HTTP completion probe; ciphertext cannot advance routing. Separately, the exact observed `weather.com` message already passes the host-agnostic `regional_access_denied` browser detector and protected semantic fixture. Transport cannot read rendered meaning. | Pass full checks and merge the small transport PR only when green; requalify exact main before installation. In a separate delivery PR, finish all code-side Chromium/Safari packaging and lifecycle work while keeping store review, signing, and user browser enablement as explicit external gates. |
| 2026-08-03 | Googlevideo still received runtime TLS EOF after the protected short-close correction | Exact artifact rolled back; bounded medium-close correction passes locally | PR #303 is exact main `c0cdeafc3b774facbb04986605c885fc1016bc37`; CI `30837945703`, audit `30837946899`, native Windows `30837945170`, and protected run `30838499747` passed. Artifact `8865902703` reached active StatusV2 in transaction `B06FF48A-C140-4E53-B052-DBEB9CE780BA`; Google, Spotify, Discord, and YouTube HTML returned payload, but a real format-18 Googlevideo download ended all ten retries with `UNEXPECTED_EOF_WHILE_READING`. Exact rollback completed and preserved DNS `111.88.96.50/51` and every external owner. The private log contained no detector event. PR #303 bounded orderly protected closes below `32 KiB`, while generic unknown-host code already recognizes framed closes through `512 KiB`. The real byte class was not measured, so this diagnosis remains an evidence-consistent inference; a roughly `96 KiB` Googlevideo traffic contract reproduces the gap. The correction keeps short and medium evidence separate, requires two matching exact host/strategy medium closes, advances an already active local fallback after one matching close, and remains YouTube-only, local-only, and Geph-ineligible. | Review and merge the small PR only when green. Then require exact-main CI/audit/native, exactly one fresh protected qualification, and another controlled real-media transaction using only that run's artifact. Do not reinstall artifact `8865902703`. |
| 2026-08-03 | Real Googlevideo media retries received TLS EOF after YouTube HTML succeeded | Exact artifact rolled back; generic protected-local correction is locally verified | PR #302 is exact main `00fb7367b2f7262bfd8fa25a2060c3ba487b11ee`; CI `30828097393`, audit `30828098120`, native Windows `30828097061`, and protected run `30828740943` passed. Transaction `D104F3FA-0B0C-4387-919A-AF6666E097DB` reached active StatusV2 and passed Google, Spotify, Discord, and YouTube HTML, but a real format-18 Googlevideo download produced ten `UNEXPECTED_EOF_WHILE_READING` retries. Exact rollback preserved DNS `111.88.96.50/51`, owned Geph, and external state. The root routing-log delta contained no event. Code tracing proved that initial payload was marked successful before relay completion; server-first close handling required an unknown-route stage, while Googlevideo is protected YouTube `direct_first`. The correction tracks TLS framing for every protected local route. One reset/incomplete record or two exact host/strategy short closes demotes only the local strategy and schedules exact-host re-sweep. `direct_first/plain` is skipped for one minute so the next request reaches ranked local desync. No hostname rule or Geph action exists. Local verification passes with `981` Python tests plus `41` subtests, `83` Rust tray tests, and `21` Chromium companion tests. | Review and merge a small PR only when green. After merge, require exact-main gates and exactly one fresh protected run; install only its artifact and repeat the real Googlevideo smoke with immediate rollback on first failure. |
| 2026-08-03 | Payload arrives through complete TLS records and then the direct stream remains open without progress | Exact artifact rolled back; generic non-destructive observer implemented locally | PR #301 merged as exact main `6da4c85c5e19422029eb8cca67fabfb87d26ef4c`; CI `30818005077`, audit `30818006222`, native Windows `30818005042`, and the sole protected run `30818758283` passed. Artifact `8857990162` has GitHub digest `sha256:d5aa7517a6c0faefc215ef666978e0eae7accd5ca4e3e704a3f942094b60e6e7`. Its controlled Mac transaction preserved DNS `111.88.96.50/51` and every external owner; the broad smoke matrix passed, but four `xpersonatoy.com` attempts still returned HTTP 200 and 53-59 KiB before timing out, with no detector event, so exact rollback completed. A direct HTTP/1.1 control then returned HTTP 200 and 20,120 bytes before a 45-second timeout. This is not limited to an HTTP/2 browser error or an incomplete TLS record: the transparent relay lacks an event while a sequence of complete encrypted records simply stops progressing. The correction adds one idle observer to eligible generic local streams. It never ends or reroutes the active stream. Each idle is accepted only after valid TLS framing yields at least one complete record, and records only its actual system, app-owned DNS, or named local-strategy stage. System plus app-owned DNS plus multiple distinct local-strategy observations remain mandatory. Every network-wide guard evaluation prunes expired partial, zero-payload, payload-idle, and server-first evidence before counting hosts. Only the complete ladder may schedule the existing original-system-public-IP, certificate-validating HTTP completion probe; that worker learns nothing unless direct framing is provably incomplete and verified owned Geph independently returns a complete usable response. Probes are exact-host cooled and globally capped at four. Static policy, Discord, YouTube, Googlevideo, external Geph, and external network state remain excluded. | The latest two review findings are fixed and full local verification is `975 passed, 41 subtests passed`. Repeat automated review and PR CI, then merge only when green. After merge, require exact-main CI/audit/native and exactly one fresh protected qualification; use only that run's artifact for another controlled transaction. |
| 2026-08-03 | Share Slipstream bypass with devices connected to a phone or desktop hotspot | Feasibility recorded; no runtime implementation | Android [`VpnService`](https://developer.android.com/develop/connectivity/vpn) owns one user/profile VPN interface, while [`TetheringManager`](https://developer.android.com/reference/android/net/TetheringManager) control starts at API 36 and may reject apps without change permission. AOSP documents that [tethering offload](https://source.android.com/docs/core/data/tethering-offload) can forward between modem and peripheral without the app processor, so ordinary device-VPN success is not evidence that hotspot clients use it. Apple documents [VPN route control](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic) for device traffic and [`NEHotspotConfigurationManager`](https://developer.apple.com/documentation/networkextension/nehotspotconfigurationmanager) for joining/configuring Wi-Fi, not an ordinary-app Personal Hotspot forwarding API. Universal transparent sharing is therefore not promised. The first portable candidate is an authenticated app-owned HTTP/SOCKS relay explicitly configured by the client; a native transparent adapter is allowed only after a per-platform physical-device proof. | Keep in the M4 deferred backlog. Prototype on disposable Android first, then iOS feasibility; require a second-device payload, policy preservation, bounded clients, and exact cleanup without root or external-network mutation. |
| 2026-08-03 | Repeated short server-first closes required at least eight client-visible failures before content confirmation | Exact qualified artifact rolled back; generic convergence correction locally green | Exact main `50fa7a07074f5645afb105943b3a80a1435a38a9` passed CI `30811692452`, audit `30811692302`, native Windows `30811692540`, and the sole protected run `30812213963`; artifact `8855325326` matched inner ZIP SHA-256 `ad0bad2cf354be60bdbcbb7836556f7350ce3b1290f6262b466f4b6fc544e5f5`. Transaction `D4B90B18-B73F-418D-AC83-92DA48C4CFE9` preserved DNS `111.88.96.50/51` and all external state while the broad smoke matrix passed, but four `xpersonatoy.com` responses ended with curl error `18`; exact rollback completed and the root-log delta contained no detector event for those attempts. The frozen regression required two matching closes on system, Xbox DNS, and two local strategies before the content-aware probe: at least eight failures. The correction schedules the existing exact public-IP, certificate-validating HTTP completion probe after the second matching system/plain close. One close remains inert, Xbox DNS remains the next local fallback, the existing network-wide failure guard remains mandatory, and encrypted bytes remain non-authorizing. Only proven local incomplete framing plus complete owned-Geph evidence may learn the exact host. No hostname rule or system-network mutation is added. | Merge only after full local and PR gates. Then require exact-main CI/audit/native and exactly one fresh protected qualification; install only that run's exact artifact with immediate rollback on the first failed smoke. |
| 2026-08-03 | Mutating owned-Geph `kickstart` outlived the shared command timeout | Exact artifact rolled back; full local verification green | Exact main `3d40ce7dbc9c89cdef39f03499062998b3856687` passed CI `30803833248`, audit `30803833308`, native Windows `30803833447`, and the sole protected run `30804356739`; artifact `8852219623` matched inner ZIP SHA-256 `9cdfd2b2b46189bf19b7490006a26ecc9d06e641c79e274a88e0519295b72eb0`. After one operator-threshold false rollback, transaction `38599211-5C24-42B3-953E-D90DD605CB79` preserved DNS `111.88.96.50/51` and all external state while Google, Spotify, Discord, YouTube/Googlevideo, Steam, CrystalIDEA, ChatGPT, and Modrinth returned payload. Repeated `xpersonatoy.com` responses ended with curl error `18` after 53-59 KiB. Root logs show the generic detector learned Modrinth, one owned replacement completed, and the next exact `launchctl kickstart -k` was reported unavailable after the shared five-second timeout. The verified LaunchAgent nevertheless replaced its listener PID later. Main treated `returncode=124` as a definitive no-op and released recovery state before the delayed mutation converged. The correction gives the mutating command completed/rejected/indeterminate outcomes, keeps the existing drain through a bounded exact-successor observer, accepts only a changed fully owned live PID, rejects unknown/external listeners, and never repeats one unresolved indeterminate command. It adds no site rule and changes no routing or system-network policy. | Merge only with green PR CI/audit, then require exact-main CI/audit/native and one fresh protected qualification. Use only that run's exact artifact for the next controlled install. |
| 2026-08-03 | Medium and large framed responses escaped browser-independent incomplete-response recovery | Exact qualified artifact rolled back; generic bounded correction locally green | Exact main `f8fb0c099c41f7e3bbd810042c8990a49febd665` passed CI `30763846949`, audit `30763846945`, Windows qualification `30763846998`, and protected owned-Geph run `30764174229`. Artifact `8838433677` matched inner ZIP SHA-256 `4e46c2c367c67335c60310ce69eeee07be8a628ec3c248559c2e5e62dd9e2c97`. The first one-off installer check raced the intentional dormant-to-active transition; corrected transaction `C3CDCD9F-F3A1-4733-9164-3C0A4A3FF5CB` waited for coherent active StatusV2 and installed successfully without changing DNS `111.88.96.50/51`, proxy/PAC, default route, global PF, owned Geph, or Telegram. Google, Spotify, Discord, YouTube, Steam, CrystalIDEA, and the ChatGPT HTTP path returned payload. Modrinth and `xpersonatoy.com` returned HTTP 200 but ended with curl error 18 after 55-116 KiB, so exact rollback restored the prior app and removed every root-owned runtime component. The production observer treated any orderly response above 32 KiB as complete and cleared evidence, although the existing exact HTTP probe could safely distinguish a complete body from a framed shortfall up to 512 KiB. The correction retains two bounded exact system/plain observations only as permission to run that content-aware probe; it does not advance the local ladder from encrypted byte count. Complete responses stop locally. Only proven incomplete local framing followed by complete owned-Geph evidence may learn the exact host. | Merge only after full local and PR gates. Then require exact-main CI/audit and one fresh protected qualification; install only its exact artifact with immediate rollback on the first failed payload smoke. |
| 2026-08-02 | Generic route was learned from opaque TLS bytes before owned-Geph session stability was proven | Controlled artifact rolled back; focused and full data-plane regressions pass locally | Transaction `5CCAE939-C2D8-4843-AF24-0E2D32C7C3D6` preserved all external state and passed the broad smoke matrix, but repeated `xpersonatoy.com` local partial responses were followed by a one-hour learned route whose next transparent request returned persistent HTTP `429 local_rate_limited`. The current same-request fallback cached the host after only the first encrypted server record, while its independent one-shot `HEAD` probe accepted any HTTP status. A one-shot final Geph attempt may still serve the current replay-safe request, but encrypted bytes cannot authorize future routing. Generic learning now requires two consecutive complete, usable HTTP responses on independent owned SOCKS sessions under one bounded deadline per probe; a failed second response may enter only the existing ownership-verified, two-replacement, globally cooled recovery. No hostname rule or external network mutation was added. | Pass the full suite and review, merge only with green PR CI/audit, require exact-main CI/audit and one fresh protected qualification, then use only that run's artifact for another controlled Mac transaction. |
| 2026-08-02 | Fifteen adjacent routing, DPI, relay, Telegram, QUIC, and platform projects | Code reviewed at pinned commits; no runtime dependency or workstation mutation added | Adopt four bounded contracts: clean-vantage diagnostics without route authority, MTProto protocol liveness with an authenticated continuation, typed local desync plans, and explicit replay-safety evidence. Reuse Android lifecycle and Windows transaction ideas for M4; keep QUIC, padding, multiplexing, and link-health ideas for M5. Reject mutable public-node feeds, global system mutation, public relay backends, and wrapper-driven system proxy control. GPL/AGPL implementations remain reference-only. | Convert only the four near-term contracts into separate small design/test PRs; do not add host rules or import endpoints from this audit. |
| 2026-08-01 | Protected outer Geph lifecycle rejected a valid coordinated replacement | Exact-main product/browser evidence passed; no artifact or install | PR #295 merged as `db5df67c11f72ce36e5e98513ab682a2fbb53174`; exact-main CI `30727142757`, audit `30727142778`, and Windows run `30727142747` passed. The sole protected run `30727352290` passed both complete Chromium semantic scenarios, then the outer account-backed lifecycle rejected `Geph ownership changed before a protected action`. Cleanup passed and artifact upload was skipped. The outer harness retained the initial PID across the semantic coordination window even though the daemon may legitimately replace its exact owned Geph backend there. The bounded fix accepts only a successor that passes the complete existing ownership/listener checks, requires the previous exact identity to disappear, and continues trayless and subsequent KeepAlive evidence from that successor. It does not relax product ownership, routing, PF, DNS, proxy/PAC/VPN, external-Geph, Discord, YouTube, or Googlevideo boundaries. | Pass focused/full checks, merge a small PR, require exact-main CI/audit, and dispatch one protected qualification for the resulting exact SHA. Install only its uploaded qualified artifact. |
| 2026-08-01 | Generic browser-independent incomplete-response evidence | PR #295 under review; automated review exposed and the branch now closes cross-class and single-reset evidence authorization, exact-stage reachability, and HTTP-syntax/coding ambiguity; no workstation mutation | Ordinary Chrome, Safari, and non-browser clients do not receive the unpublished semantic companion. The transparent relay cannot read encrypted HTTP framing, so repeated bounded server-first closes must independently complete the system route, app-owned Xbox DNS, and multiple-distinct-local-strategy evidence ladder; partial-record and zero-payload observations cannot fill missing stages. A single reset may advance only the older local recovery state and retains one exact same-stage retry inside the five-minute evidence window; the retry is claimed once and only a repeated matching failure enters this evidence class. Only then may a separate verifier connect to the original exact system-selected public IP with normal certificate validation and request identity-encoded `/`. It authorizes nothing unless strict HTTP/1 status with every required separator, header, strictly decimal `Content-Length`, content coding, transfer coding, and unpadded hexadecimal chunk syntax prove a 2xx/3xx framed body unfinished at EOF or the shared idle deadline; transfer coding is accepted only on HTTP/1.1. Complete, bodyless including `205`, connection-delimited, malformed, HTTP/1.0 transfer-coded, unsuccessful, compressed, unsupported transfer-coded, conflicting-framing, capped, non-public-IP, non-plain, static-policy, Discord, YouTube, and Googlevideo cases remain non-authorizing. Only after this local proof may the existing ownership-verified bounded Geph completion probe run; route learning still requires its complete usable response and remains exact-host and rate-limited. No hostname rule, PF/DNS/proxy/PAC/VPN mutation, external-Geph control, or current-request replay was added. | Repeat focused and full checks, resolve review threads with evidence, and merge only with green CI/audit. Then require exact-main CI/audit and one protected account-backed qualification; install only that run's exact artifact with prepared immediate rollback. |
| 2026-08-01 | Protected semantic recovery is not delivered to the user's normal browser path | Exact protected run passed; controlled workstation install rolled back | PR #293 is exact main `62aabd64d3f9dd0fd5f08401b198fc2ee35ae37d`; exact-main CI `30693565371`, audit `30693565390`, and Windows native run `30693565372` passed. The sole protected run `30711121048` passed all three account-backed owned-Geph payload phases, both Chromium semantic scenarios, cleanup, and network-state non-mutation. Artifact `8821938264` matched inner ZIP SHA-256 `e50bd77ca4fa94ea8077c5c105bc58ac34463945c50f3d0d29160f5b0f3a64d9`. Its controlled Mac install preserved DNS `111.88.96.50/51`, proxy/PAC, default route, global PF, owned Geph, and Telegram proxy. Discord updater/gateway, YouTube control plus real Googlevideo media, ChatGPT, CrystalIDEA, Modrinth, and Weather completed. `xpersonatoy.com` then returned HTTP 200 but curl error 18 after 16,401 bytes, forcing immediate exact rollback. Direct post-rollback traffic timed out after 50 seconds with 13,672 bytes, while the unchanged owned Geph session returned HTTP 429 with 18 bytes. The bounded two-replacement code is entered only after an authenticated incomplete-response semantic signal; curl cannot emit it, the Chromium extension is not published/installed in the ordinary profile, and Safari remains an unsigned runtime-unqualified preview. Thus CI qualified a real product mechanism but not its delivery to the user's everyday browser. No hostname rule is justified. | Add a generic production-reachable trigger or deliver the companion through a reviewed production path, preserving static-policy precedence, exact-host bounds, owned-Geph proof, and Discord/YouTube exclusion. Requalify before another primary-Mac install. |
| 2026-08-01 | A live owned-Geph exit can remain unusable after one exact replacement | Exact rollback complete; bounded two-replacement correction implemented locally | Exact main `3126f8404419403aee0eac0585a112c20b66cb78` passed protected run `30591636334`; artifact `8778619390` matched archive SHA-256 `3ca16e9303530a0ee288e1803196cd51bcb24146b399beea42a9cd5e674eb879` and inner ZIP SHA-256 `f705c9063108e4d08e070093a4a97f4e0a9d9c235f404b2a24f4a49ac914efaa`. Controlled transaction `C84FCEB4-DBB1-43C9-AA44-B0AF4243B6F7` reached fresh active StatusV2 and preserved DNS `111.88.96.50/51`, proxy/PAC, global PF, and external owners. Modrinth returned a complete 1,959,739-byte response; `xpersonatoy.com` then returned curl error 18 after 19,139 bytes, triggering immediate exact rollback. Post-rollback direct traffic remained partial. The verified owned `:9954` exit returned HTTP `429 local_rate_limited`; the first ownership-verified PID replacement remained `429`, while a second replacement returned a complete 1,058,817-byte HTTP `200` response. The previous one-replacement invariant was therefore false for this live exit state. The correction permits at most two sequential owned replacements under one drain and one global incident cooldown, revalidates ownership and changed PID before each probe, stops on first complete response, and otherwise fails closed. No hostname rule or external mutation was added. | Pass targeted and full local checks, PR CI/audit, exact-main CI/audit, then dispatch one protected qualification for the resulting exact main. Do not reinstall before that exact artifact passes. |
| 2026-07-30 | Live owned-Geph exit returns `local_rate_limited` after direct partial response | Exact rollback complete; generic bounded recovery implemented locally | Exact main `b29be61e554f5ad3ec71d2864e487fabbdb014cf` passed CI `30586625792`, audit `30586625648`, native Windows run `30586625811`, and the sole protected account-backed run `30587085951`. Artifact `8776982805` matched GitHub SHA-256 `83522d4cc9b7064f96d8a942858f869f8550034a676e49be43d176f41a409669` and inner ZIP SHA-256 `c9e5aa78169cc47c767e09b0148458d2141ea7da7c08326007dfec39d48c1439`. Controlled transaction `5B152F0D-7CC2-4160-80B6-10719A14FEB2` reached active StatusV2 and preserved DNS `111.88.96.50/51`, proxy/PAC, global PF, and external anchors. Modrinth returned 1,941,091 bytes; the next `xpersonatoy.com` smoke received a partial response and forced immediate exact rollback. Direct A/B then returned 20,169 bytes before stalling. Verified owned SOCKS `:9954` returned HTTP `429`, body `local_rate_limited`, and `Retry-After: 60`. Restarting only the exact owned `dev.slipstream.geph` LaunchAgent replaced its PID; the same request then returned HTTP `200` and 1,060,480 bytes. Listener/process readiness therefore did not prove exit-session payload usability. The generic correction acts only after an exact browser semantic failure plus failed complete owned-Geph HTTP probe, drains active owned sessions, verifies ownership and PID replacement, retries once, and learns only after a complete usable response. The existing ten-minute global restart cooldown bounds churn. No hostname rule or external mutation was added. | Pass full local, PR, exact-main, and one protected account-backed qualification for the new SHA. Use only that exact artifact for another controlled Mac transaction and retain immediate rollback on the first failure. |
| 2026-07-30 | Complete unknown-host proof still waited for the full local ladder | Exact qualified workstation artifact rolled back; convergence correction locally green | PR #290 merged as exact main `a4628c7301eee187c2dbc300b62adac05ff29846`; CI `30581889243`, audit `30581889244`, and the sole protected run `30582540761` passed. Artifact `8775261865` matched its GitHub and inner ZIP SHA-256 values. Controlled transaction `1FD68287-13D3-44EF-9E58-AF0B25617C80` installed exact daemon SHA-256 `4ad1f755a81d690d1f065d568a97eaad9da49fd26f040b243f83134219c88b5a`, reached active StatusV2 with owned Geph up, and preserved DNS `111.88.96.50/51`, proxy/PAC, global PF, and external anchors through installation. The first mandatory Modrinth request returned zero TLS bytes and hit the client's exact 15-second connect bound. Immediate rollback restored the previous app/runtime and owned Geph, removed every root-owned component and private runtime file, and left DNS and proxy/PAC byte-identical. The timeout correction was active, but production had six general strategies while the complete promotion proof requires only two distinct local strategy outcomes after system and Xbox DNS. `_handle_impl` ignored the `True` result from `note_zero_payload_route_failure()` and waited for the remaining four strategies before trying owned Geph. The previous regression mocked exactly two strategies and therefore hid the delay. The correction stops only the remaining unknown-host local probes once the complete replay-safe proof exists; every existing ownership, network-wide, real-payload, exact-host, protected-route, and external-state guard remains. No hostname rule was added. | Pass full local, PR, exact-main, and one protected account-backed qualification for the new SHA. Only that run's exact artifact may repeat the controlled Mac smoke; retain immediate exact rollback on the first failure. |
| 2026-07-30 | Generic unknown-host first-payload timeout | Exact qualified workstation artifact rolled back; generic correction implemented and locally green | Exact main `60811c1ddeccecb15687978f3bca62d15f4b882c` passed CI `30573765421`, audit `30573765030`, and protected run `30574330659`; artifact `8772158225` installed transactionally without changing DNS `111.88.96.50/51`, proxy/PAC, global PF, or external anchors. Discord gateway, YouTube control, and CrystalIDEA returned payload, while Modrinth timed out during TLS. Immediate rollback transaction `1111DA3F-CFD4-4601-A2A5-A26372E4449D` restored the previous app/runtime and proved root daemon, listener, private PF, token, and status absent. Code tracing found that direct and local first-payload timeouts were published as `pending`; `_handle_impl` therefore committed a silent stream and never reached the already-frozen same-request fallback. A bounded timeout after the complete TLS first flight and before any server byte is now explicit zero-payload evidence. It closes the owned attempt and may advance only after every required address/stage is complete; cancellations, connect failures, generic errors, and partial race evidence remain non-authorizing. No hostname rule was added. | Pass full local, PR, exact-main, and one protected account-backed qualification for the new SHA. Only that run's exact artifact may repeat the controlled Mac smoke; retain immediate exact rollback on the first failure. |
| 2026-07-30 | Protected Chromium top-frame correlation | Narrow browser observer and deterministic startup gate under review; no artifact or workstation mutation | Exact-main protected run `30561342773` passed packaged resources, the daemon-free boundary, account-backed owned-Geph initial/trayless/recovered Steam payload, unchanged system network state, and cleanup. The regional-denial browser scenario completed. The incomplete-response scenario received its first root response but produced no signal, reload, or subresource request. The correlation rejected an otherwise exact request when optional `parentFrameId` was omitted; accepting omission preserves every other scope check. Ordinary real-Chrome run `30563918442` reproduced the missing signal, and diagnostic run `30564634280` produced an empty owner-private trace: command-line fixture navigation raced fresh Manifest V3 registration. Fixed-delay run `30565374098` still produced no worker trace. Extension-page acknowledgement run `30566477975` and expanded-boundary run `30566813738` both made zero fixture requests and emitted no trace, proving that the extension page can itself run before the unpacked extension exists. DevTools target-gated run `30568262971` then opened one fixture document with no observer event, proving that target publication still precedes completion of the worker script. Run `30569114212` reached a terminal in-process marker after production and diagnostic listener registration, yet still made one root request with an empty trace. Run `30570286341` added an address-free native round trip and stopped before navigation, proving that Chrome for Testing 151 did not discover the exact manifest copied inside the temporary user-data directory. The current browser-specific user-level location is `Google/ChromeForTesting/NativeMessagingHosts`; the shared harness now installs only an owner-private exact manifest there for the disposable browser lifetime and refuses collisions or uncontrolled directories. Run `30571120394` reached exact native-host cleanup, confirming discovery, then exposed an over-strict attempt to remove a shared `Google` ancestor populated by Chrome. Cleanup now removes the exact manifest and empty directories it created, then stops at the first non-empty owner-controlled ancestor without deleting independent data. Run `30571398388` then exposed the unmasked readiness defect: the bounded diagnostic native manifest omitted Chrome's required `description` field, although the packaged production manifest already contains it. The diagnostic gate now constructs one complete tested manifest. Navigation uses `Page.navigate` on the single owned `about:blank` page. Protected qualification retains packaged executable identity; the ordinary contract retains its bounded stub. No routing, PF, DNS, Geph, installer, or system-network behavior changes. | Pass the ordinary real-Chrome contract, merge only with all checks green, then run the protected exact-main qualification once. Install only its exact artifact after both browser scenarios and cleanup pass. |
| 2026-07-29 | Disposable Wintun-to-selected-stack IPv6 UDP handoff | Merged and exact-main green; no workstation or production-host mutation | PR #265 merged as `9979889d82316f21701f1ef8304ffe3b8a11bb7d`; exact-main native AMD64/ARM64 run `30476588359`, CI `30476589552`, and audit `30476588735` passed. The isolated `raw_packet_udp_ipv6_v1` boundary leaves frozen IPv4 v1 unchanged while reusing its structured exchange result and error taxonomy. Fixed MTU, queues, burst, poll steps, one request/response, mandatory IPv6 UDP checksum validation, deterministic same-seed output, and fail-closed size/configuration checks are covered by five focused tests. The disposable real OS socket and exact `/128` Wintun route retain the captured Layer 3 packet, pass it through the selected stack, inject only the stack-emitted response, and reject any retained manual IPv6 response builder. The dependency remains dev-only; production host, default route, DNS, external proxy/PAC/VPN, external routes, and Discord/YouTube Geph behavior remain closed. | Add the separate TCP Wintun-to-selected-stack handoff; keep production composition as a later independent gate. |
| 2026-07-29 | Disposable Wintun-to-selected-stack IPv4 UDP handoff | Merged and exact-main green; no workstation or production-host mutation | PR #263 merged as `105551ec27f8139e455783b7ae2bf89d63812166`; exact-main native AMD64/ARM64 run `30472082661`, CI `30472083693`, and audit `30472083055` passed. The existing real Windows UDP socket and exact owned Wintun route retain the exact captured Layer 3 packet and pass it through a reusable bounded `smoltcp 0.13.1` boundary. Only the stack-emitted response packet is injected back into Wintun, so successful receipt by the real OS socket proves checksums and the native return path. Fixed MTU, queues, poll steps, one request/response, deterministic input, and structured errors keep the handoff fail-closed. The stack remains a dev-only qualification dependency; source and contracts reject production service-host composition, default-route/DNS/external proxy/PAC/VPN mutation, external route ownership, and every Discord/YouTube Geph edge. | Completed by the subsequent IPv6 UDP handoff entry; continue with the separate TCP handoff before production composition. |
| 2026-07-29 | Disposable Windows packet-flow architecture gate | Merged and exact-main green; no workstation or production-host mutation | PR #261 merged as `c154f2d880d1d4aad34c83c813a03f11006b5d4e`. Exact-main native run `30465700678`, CI `30465701374`, and audit `30465700386` passed. Each native runner executed the full frozen packet-flow contract and full stack/connector suite before the existing real Wintun lifecycle, exact-route, capture/injection, independent-route-owner, and cleanup gates. Review found that five transitive composition contracts were absent from the workflow path filters; the merged workflow tracks every contract consumed by either invoked suite in both the pull-request and main-push path lists, and the regression test requires both occurrences. This proves architecture and native-loopback behavior adjacent to real Wintun effects, not an integrated Wintun-to-stack path. | Add a test-only Wintun-to-stack packet handoff without composing the production SCM host. Keep production host networking as a later independent gate. |
| 2026-07-29 | Windows selected-stack/native-connector composition | Merged and exact-main green | PR #259 merged as `7abaf556dd98139b0fdcabce0f203f4e9a4a3005`; exact-main CI `30438309120` and audit `30438309270` passed. All three predecessors remain frozen. Client payload passes the existing byte-owner effect into the selected stack before the exact frame enters the existing bounded connector queue. Native backend reads use a separate bounded queue: an error precedes read progress, an accepted frame remains owned across selected-stack failure, and retry commits it once. Both directions revalidate flow, backend, and transport. The exact-flow reverse queue starts at packet-flow v1 sequence 1, rejects stale or skipped sequence before native read, and discards oversized UDP datagrams without advancing sequence. Numeric loopback and the in-memory Layer 3 pair are the only effects. Discord/YouTube and UDP remain excluded from Geph, and no production host or external network state is touched. | Qualify packet flow on disposable Windows AMD64 and ARM64 before any production composition. |
| 2026-07-29 | Protected incomplete-response fixture kept HTTP/1.1 socket open | Narrow fixture correction under review; protected cleanup passed; no artifact or workstation mutation | Protected run `30429690683` proved packaged resources, the daemon-free boundary, unchanged system network state, and complete owned-Geph initial/trayless/recovered Steam payload (`HTTP 200`, TLS 1.3, `67973` bytes). Its second Chromium scenario made one root request and then waited with no reload or subresources. The fixture advertised a larger `Content-Length` and `Connection: close`, but Python's `BaseHTTPRequestHandler` does not update its HTTP/1.1 keep-alive state from a response header. The socket therefore remained open and never produced the EOF required for Chrome's incomplete-response event. Explicitly set `close_connection` after writing the short body and require a real TLS keep-alive client to receive immediate `IncompleteRead` with the exact prefix. | Pass local, PR, and exact-main gates. After the next UTC-day account reset, run the protected workflow exactly once and install only if both Chromium scenarios, cleanup, and exact artifact publication pass. |
| 2026-07-29 | Windows native connector byte ownership | Additive numeric-loopback gate merged and exact-main green | PR #257 merged as `3b9075d8b63e12e9ce93b2a3ac973005f3d43c13`; exact-main CI `30427162038` and audit `30427162047` passed. A native TCP write is not a failure-atomic byte-owner effect because a successful prefix can precede a later error. Transfer the exact frame atomically into a bounded connector-owned queue, then commit exact positive TCP progress while retaining only the suffix. An error is permitted only before progress and retains the complete frame. UDP is one complete datagram. Revalidate the exact flow key, backend, and transport before each write so equal-backend flows cannot cross sockets. Local bypass admits only the local engine; geo exit admits Smart DNS or Geph; Discord/YouTube and UDP cannot use Geph. | Qualify selected-stack-to-connector composition and backend reads separately, then run disposable AMD64/ARM64 packet-flow gates before production composition. |
| 2026-07-28 | Protected owned-Geph/Chromium cleanup interleaving | Coordination fix qualified; later browser-contract correction awaits one post-reset protected run | PR #251 merged as main `8c6814fd6130d7b08e339d6d41eb37922a66973a`; exact-main CI `30396785782` and audit `30396784419` passed. The sole protected run `30397332251` built and verified the exact bundle, established the daemon-free boundary, then received the already-classified upstream `cannot get token: rate limited` failure after shared-secret authentication and tunnel establishment. Because the producer aborted after publishing `ready`, it began user-resource cleanup while the semantic consumer still owned the root daemon and Chromium native-host manifest. That produced secondary `root daemon boundary changed` and missing-manifest cleanup errors; the workflow's independent always-run cleanup still passed, and no artifact was uploaded. PR #252 retained a late abort until the exact private `release`; protected run `30411915972` subsequently passed all three owned-Geph payload phases and exact always-run cleanup, proving that ordering correction. | Keep the coordination fix frozen. The only remaining protected action is the single two-scenario run after the next UTC reset for the then-current live `main` containing product merge `45db4321bafe244c87986c4c08daf1c3afaf8bf2`; do not install before its exact artifact qualifies. |
| 2026-07-28 | Protected incomplete-response v2 runtime signal | Real Chrome contract corrected; local, PR, and exact-main gates passed; no artifact or workstation mutation | Protected run `30411915972` passed packaged resources, daemon-free setup, the frozen regional-denial scenario, all three account-backed owned-Geph payload phases, and final cleanup on `bebb6776b554a01a7885b889d6d98c2a405d570c`. The additive scenario failed before native messaging because real `webRequest.onErrorOccurred` omits `method` and `parentFrameId`, unlike the synthetic test event. PR #254 now correlates only an opaque request ID, tab, normalized hostname, and expiry from read-only `onBeforeRequest`, removes candidates on redirect/completion/final error, serializes ephemeral session operations, and retains the exact two-error allowlist. It merged as `45db4321bafe244c87986c4c08daf1c3afaf8bf2`; exact-main CI `30414420932` and audit `30414420883` passed. | Do not repeat completed focused, full, PR, or exact-main gates. After the next UTC-day account reset, dispatch exactly one protected run for the then-current live `main` after verifying that it contains product merge `45db4321bafe244c87986c4c08daf1c3afaf8bf2` and has green exact-main gates; install only if both browser scenarios and final cleanup publish that run's exact qualified artifact. |
| 2026-07-28 | Generic browser-owned incomplete-response evidence | Additive v2 implemented locally; no workstation mutation | The `xpersonatoy.com` curl error 18 exposed an HTTP-semantic failure that the transparent TLS relay cannot reliably infer from encrypted records. No host rule was added. Semantic signal v2 accepts only Chromium's exact top-level `ERR_CONTENT_LENGTH_MISMATCH` and `ERR_INCOMPLETE_CHUNKED_ENCODING` events, keeps the URL and raw error inside the extension, and sends one frozen `incomplete_response` signal for the browser-derived hostname. Static policy remains authoritative. A distinct owned-Geph probe requires a complete bounded 2xx/3xx HTTP response under one shared deadline; partial framing and ambiguous resets cannot learn the route. Success allows one same-host browser reload but never replays the already-failed transparent request. The protected main-only harness now contains independent generic v1 regional-denial and v2 incomplete-response fixtures, each requiring real account-backed owned-Geph confirmation, exactly one reload, complete CSS/JavaScript/image resources, and one ready callback. | Pass full local checks, PR CI/audit, exact-main CI/audit, then dispatch the protected workflow once for that merged SHA. Install only its exact qualified artifact after both semantic scenarios and cleanup pass. |
| 2026-07-28 | Exact protected artifact passes broad workstation smoke but exposes a generic partial first response | Exact rollback complete; next-connection recovery gap open | Main `8436ddfcfda6d3657912ec05674fb16ad17750d3` passed exact-main CI `30378302132`, audit `30378302209`, and the sole protected run `30379005119`. Protected artifact `8696275919` matched GitHub SHA-256 `d1929ddfc190450bc390026fc4af73bfc71b0510de110b288a363b6e42d0c1ec` and inner ZIP SHA-256 `fc6b974d544b43ee8335251a5fdf3ecec30a8171a9d9d9a400438260ae22f6bf`. The controlled install preserved DNS `111.88.96.50/51`, proxy/PAC, default route, global PF and the existing owned-Geph PID/hash; StatusV2 reported 10/10 healthy canaries. Discord updater/gateway, YouTube control and real Googlevideo media, ChatGPT, CrystalIDEA, Modrinth and Weather returned payload. The first `xpersonatoy.com` request ended with curl error 18 after a partial response. Exact rollback removed every root-owned component and restored the prior app. A direct post-rollback request timed out after 35 seconds with 13,672 bytes, proving an underlying alternate-route need rather than a healthy direct baseline. Once response bytes reach the client, the opaque encrypted request cannot be assumed replay-safe or moved to another backend. The daemon may use this evidence only for a later client connection. | Model the incomplete response as bounded generic evidence for the next connection. Where a browser companion can prove a top-level replay-safe navigation, allow at most one bounded reload through the existing authenticated signal path. Do not add `xpersonatoy.com` to policy, and keep Discord/YouTube, external network owners, and unverified Geph listeners excluded. |
| 2026-07-28 | Exact Googlevideo CDN stalls under direct-only workstation routing | Exact rollback complete; generic local-only correction under review | PR #246 merged as exact main `2b2b2529f3c81be168273b0bf3d0bdab27c1c407`; exact-main CI `30364706410`, audit `30364706201`, and account-backed protected qualification `30365257118` passed. Artifact `8690435788` matched GitHub container SHA-256 `9e679662eaadb7af6678890482dbb1d2dc412d11dc940b4b787748ba6f28e3c8` and internal release ZIP SHA-256 `07e0960e7409fd564947d5021043b904651950c253cbf62f7aa9286df124d9fd`. Two early workstation attempts found only transaction-harness issues and completed exact rollback: the first used an obsolete unavailable YouTube test video, and the second required the installed daemon path even though the product's valid root attestation may expose its hard-link witness for the same inode. The corrected transaction installed the exact artifact, reached active private-PF state, preserved DNS `111.88.96.50/51`, proxy/PAC, external PF owners, and owned Geph, and passed Discord gateway plus YouTube web/control. A valid `yt-dlp` media probe for `dQw4w9WgXcQ` loaded the YouTube page, Android player API, and JavaScript challenge, selected format 18, then timed out on both `manifest.googlevideo.com` and the exact `rr5---sn-ug5onuxaxjvh-n8v6.googlevideo.com` payload edge. The installed policy was `direct_passthrough/direct`, whose handler tries the exact system path once and closes on stall. The transaction immediately restored the previous app and removed the exact root daemon, private PF state, token, status, socket, attestation, witness, and root runtime; DNS, proxy/PAC, and owned Geph remained unchanged. The correction reuses the general `direct_first` route class: plain TLS remains first on every media connection, then only bounded local desync may run. Googlevideo remains excluded from Geph, Smart DNS, app-owned Xbox DNS, semantic promotion, and unknown-host learning. Shared Python/Rust policy, manifest, circuit, packaged classifier, canary, and real-handler contracts freeze that boundary. | Pass full local checks, PR CI/audit, exact-main CI/audit, and one protected account-backed run. Only then repeat the exact-artifact workstation transaction and require real Googlevideo payload before retaining the installation. |
| 2026-07-28 | Controlled exact-artifact workstation smoke exposed an owned-Geph re-admission race | Exact rollback complete; generic fix implemented locally | Main `ef211f9` passed exact-main CI `30356252558`, audit `30356252505`, and protected account-backed run `30356816810`. Artifact `8687069209` matched GitHub SHA-256 `e6a1b6e97487677cc7a13a0d547f50007b39a9eb261ded6716fdf3dbf5b2203c`. Its bounded workstation transaction committed with fresh active StatusV2 and preserved DNS `111.88.96.50/51`, proxy/PAC, external PF anchors, and the existing owned-Geph PID. Discord gateway/updater, YouTube control and real media, ChatGPT transport, and CrystalIDEA returned payload. The first generic unknown-host smoke, Modrinth, timed out during TLS. The root log showed `geo-exit backend unavailable` at `17:31:20` and the exact owned SOCKS backend back up at `17:31:23`; the request had no bounded way to survive that transition, and a previous 30-second backend hold could still reject new resources after an independent exact-host payload proof. The transaction therefore performed immediate exact rollback: the root daemon, label, plist, private PF state, token, status, socket, attestation, and witness are absent; the previous `0.1.9` app hash was restored; DNS and proxy/PAC remain unchanged; the pre-existing owned-Geph LaunchAgent remains PID `52893`. The generic correction separates complete exact-host proof from current backend readiness, permits only an already-proven unknown host to wait up to five seconds while actively probing the exact owned `:9954` backend independently of monitor cadence, rechecks listener conflicts throughout that wait, survives a concurrent background confirmation, and clears the old hold only after real exact-owned payload. Ordinary timeout, protected/direct/static policy, external or conflicting listeners, and network-wide failure still cannot authorize Geph. No Modrinth rule was added. | Pass full local checks, PR CI/audit, exact-main gates, and one new protected account-backed qualification. Only then stage the new exact artifact for another controlled complete-page workstation smoke. |
| 2026-07-28 | Protected semantic browser gate and bounded workstation authorization | Protected gate passed; workstation install blocked by transaction attestation | PR #243 merged as exact main `dde7224`; exact-main CI `30318303005` and audit `30318303014` passed. The sole main-only protected run `30318687293` proved account-backed owned-Geph initial, trayless, and recovered payload, sandboxed Chrome for Testing, one semantic signal and reload, complete CSS/JavaScript/image delivery, styled DOM, one browser-ready callback, and complete user/system cleanup. Exact artifact `8673106618` matched GitHub digest `1cee7cbd6c825e133522b9fbe2d56e9b60c13aefc5c6ecd30299b4037497e347`. Workstation preflight found the earlier app, root daemon, and owned Geph active with DNS `111.88.96.50/51`, proxy/PAC off, and healthy StatusV2. An unattended prompt timed out without privileged mutation. The first user-present transaction then exposed a missing previous-daemon backup in the temporary rollback harness and left a safe daemon-free baseline. A corrected transaction installed the exact daemon, but its unprivileged coordinator tried to hash the root-only installed binary and received `Permission denied`. Immediate privileged rollback published `root-rolled-back`, restored the previous app/tray exactly, preserved owned Geph and network settings, disabled and removed the root daemon, flushed only `com.apple/slipstream`, and removed the plist, token, status, socket, and runtime. Direct post-rollback probes received ChatGPT and CrystalIDEA HTTP responses; Discord timed out directly without local bypass. | Do not retry on the workstation. Verify installed-daemon SHA inside a disposable privileged transaction, export only owner-readable evidence, and prove the daemon-free rollback boundary before one later user-present attempt. |
| 2026-07-28 | Extensionless Chrome for Testing sandbox rendezvous | Protected harness defect isolated in run `30316469657` | The single post-UTC-reset run used exact main `3d58942`, authenticated the owned Geph account, admitted the owned listener, and passed final cleanup. Browser qualification failed because the hosted action exposes Chrome for Testing as an extensionless `arm64` bundle while the harness's private `.app` linked only to that bundle's `Contents`. LaunchServices started the user-owned main process, but its sandboxed helpers resolved the source executable outside the apparent `.app`, received `Permission denied` from `com.google.chrome.for.testing.MachPortRendezvousServer`, repeatedly terminated the network service, and never completed the semantic fixture. A symlink alias is therefore not a valid bundle identity boundary. The follow-up copies the complete validated bundle into the fresh owner-private `.app` and uses that copied executable path for launch, admission, diagnostics, and exact cleanup. No product route or workstation state changed. The codebase graph timed out during discovery, so the investigation used the documented narrow `rtk` fallback. | Pass targeted and full tests, ordinary PR and exact-main gates, then dispatch one protected run for the new exact main SHA. Install nothing unless owned-Geph payload, Chromium semantic reload/resources/callback, and complete cleanup all pass. |
| 2026-07-27 | Protected Geph account authentication rate limit | External gate identified in run `30308703809` | The exact-main artifact reached the ownership-verified Geph listener, but all SOCKS requests stalled while the private client log reported `cannot get token: rate limited` and an overall dial/mux/auth timeout. In pinned Geph client `0.3.0`, `auth.rs` formats broker failures as `cannot get token: {e}` and retries failed token refreshes every ten seconds. The corresponding official source at commit `5334875465f001246380693889a381f9866b6ee6` increments `LOGIN_COUNT_CACHE` by user and UTC day and returns `AuthError::RateLimited` after more than 20 requests for ordinary accounts. Repeated qualification can therefore consume the same finite external budget. Run cleanup still proved the user and system paths absent. This is neither a target-site failure nor routing-regression evidence. | Preserve the safe phrase in redacted diagnostics, stop the gate immediately when it appears, and run the protected workflow only once after the upstream UTC-day bucket resets. Do not install on a workstation until the complete protected browser gate passes. |
| 2026-07-27 | Owned-Geph listener is healthy while every independent HTTPS canary stalls | Diagnostic follow-up after protected run `30305179518` | Exact-main CI and audit passed. The protected run established exact LaunchAgent/PID/executable/config/listener ownership and later proved complete cleanup, but Steam, Cloudflare, and Wikipedia each timed out without a usable HTTPS response. This is not evidence that the production config has never worked: run `30298855867` used the same config and recorded Geph artifact and returned complete 67,973-byte Steam payloads in the initial, trayless, and recovered phases. No production Geph code changed between those commits. The gate must preserve private logs long enough to report a bounded secret-redacted tail and must distinguish SOCKS CONNECT, TLS handshake, request write, and response timeout before any routing change is considered. Codebase-memory MCP again returned `Transport closed`, so discovery used the documented narrow `rtk` fallback. | Pass the diagnostic-only PR, rerun protected main, then fix only the evidenced broker/auth/tunnel/probe layer. Keep the workstation untouched until the complete protected browser gate passes. |
| 2026-07-27 | Protected owned-Geph payload portfolio and failure cleanup | Narrow follow-up after protected run `30301572440` | Exact-main packaging and the daemon-free boundary passed, but the sole Steam HTTPS canary timed out before browser launch. This is insufficient evidence that the owned tunnel as a whole failed and makes one remote site an unnecessary single point of failure. The gate now rotates among independent HTTPS payload canaries while retaining the requirement for a complete HTTP response over verified owned SOCKS/TLS. The same failure exposed a retained exact Chromium native-host manifest because tray startup registered it before the browser harness began; user-level cleanup now removes it only after exact UID, mode, packaged path, host identity, transport, and frozen-origin validation. Codebase-memory MCP again returned `Transport closed`, so discovery used the documented narrow `rtk` fallback. | Pass ordinary PR and exact-main gates, rerun protected CI, inspect all semantic and cleanup evidence, then consider the controlled workstation install. |
| 2026-07-27 | Chrome for Testing GUI bootstrap and LaunchServices | LaunchServices composition merged; extensionless runner bundle compatibility isolated | PR #238 and exact-main CI `30298212955` passed with sandboxed LaunchServices launch and exact cleanup. Protected run `30298855867` passed real account-backed owned-Geph initial, trayless, and recovered payload (`HTTP/1.1 200 OK`, 67973 bytes), external-listener preservation, final cleanup, and unchanged system state. The browser still failed before launch because LaunchServices canonicalized the whole-bundle `.app` symlink back to the extensionless `arm64` root and produced `kLSNoExecutableErr (-10827)`. The narrow follow-up creates a real owner-private `.app` directory in the disposable profile and links only `Contents` to the source bundle. The same wrapper shape passed a local LaunchServices launch while process ownership stayed on the resolved source executable. Codebase-memory MCP again returned `Transport closed`, so discovery used the documented narrow `rtk` fallback. | Pass ordinary PR and exact-main gates, then rerun protected CI and require sandboxed learned exact-host routing, one reload, complete CSS/JavaScript/image delivery, DOM marker, browser-ready callback, and exact cleanup. |
| 2026-07-27 | Branded Chrome packaged semantic gate | Test-composition defect isolated by protected run `30261221677`; follow-up under review | The exact-main GUI harness independently passed real owned-Geph payload, trayless continuity, recovery, and cleanup, but Chrome 148 never requested the fixture. Branded Chrome 137 and later ignore `--load-extension`, so the frozen unpacked companion was not loaded. A fresh `--user-data-dir` also requires the exact packaged native-host manifest inside that profile's `NativeMessagingHosts` directory. The qualification follow-up uses pinned Chrome for Testing and an exact private copy of the installed manifest. It changes no product route, browser detector, external network setting, or production distribution assumption. | Pass ordinary PR and exact-main gates, then require the same learned exact-host route, one reload, complete CSS/JavaScript/image delivery, DOM marker, browser-ready callback, and fail-closed cleanup in a new protected exact-main run. |
| 2026-07-27 | Headless Chromium with unpacked MV3 native messaging | Rejected by protected run `30258690591` | The exact-main packaged run opened and rendered the first regional-denial fixture, while owned Geph payload and recovery remained healthy, but the extension did not send the native message or reload before timeout. Headless page rendering is therefore not evidence that the MV3 native-messaging path is active. Use GUI Chrome in the disposable runner's real user session and require a same-origin ready callback emitted only after the second document, CSS, JavaScript, image, and DOM mutation complete. Keep exact UID/process-group cleanup and a fresh owner-only profile. | Qualify the GUI composition on a new exact-main protected run; do not relax the learned-route or resource-completeness requirements. |
| 2026-07-27 | Codebase graph during packaged Chromium qualification | Tooling unavailable in this session | The codebase-memory graph returned `Transport closed` before discovery, so this pass used narrow `rtk` searches and targeted source reads. No architecture or routing conclusion was inferred from the graph failure. | Repair or re-index the graph separately, then resume graph-first discovery on the next code investigation. |
| 2026-07-27 | Safari semantic companion | Unsigned source and package build implemented; runtime sandbox gate open | Apple's Safari WebExtension model routes `sendNativeMessage` only to the native app extension embedded in the containing app. Slipstream therefore reuses the Chromium detector and frozen signal object, derives hostname from Safari-owned top-level sender metadata, then revalidates and forwards a single bounded little-endian frame from Swift to the existing owner-only daemon socket. A fresh project generated by Apple's current `safari-web-extension-packager`, with the Xcode 15 `safari-web-extension-converter` name as a compatibility fallback, compiles as a macOS 13 app plus `.appex` without signing. Xcode still registers normal app build products with LaunchServices, so the build script unregisters only its exact generated containing app, including the embedded extension, on every exit; it never opens or enables either one. The companion is not installed or bundled into Slipstream. Compilation cannot prove that the signed Safari extension sandbox may connect to `/var/run/slipstream-semantic.sock`. | Build a disposable signed container, enable it only in an isolated Safari profile, prove exact signal/confirmation/reload plus negative privacy cases, and decide whether the companion ships as a separate app or an embedded signed extension. |
| 2026-07-26 | Chromium semantic companion | Preview implemented; not installed | A generic MV3 detector can recognize strong regional-denial semantics locally without hostname rules, then pass only a fixed category and confidence to an exact-origin native host. The browser-owned sender supplies the hostname; the daemon independently confirms that owned Geph clears the denial before learning, and one same-host delayed reload completes the autonomous flow. This does not cover Safari and does not authorize routing from page text alone. | Qualify a packaged app plus real Chrome on a disposable profile, publish through a reviewed extension channel, then build the separately signed Safari container around the same detector and frozen contract. |
| 2026-07-26 | Owned Geph control plane stays ready while payload delivery stalls | Qualified and merged in PR #222 | Runtime A/B evidence showed `xpersonatoy.com` and direct SOCKS payload probes stalling while the owned process, control RPC, and verified `:9954` listener remained up. Exact LaunchAgent restart restored full payload and fresh-browser loads. Process/listener readiness is therefore necessary but not sufficient backend health. Repeated hard payload failure across multiple geo-exit hosts may feed the existing ownership-verified drain-and-restart reducer even without a recent wake; soft canaries never do. Evidence from external or non-owned listeners is discarded. After a verified owned backend down-to-up transition, at most four still-valid generic exact-host candidates have only their failed confirmation cooldown cleared and are rescheduled; protected/static policy remains excluded. | Qualify only the exact merge artifact when workstation installation resumes. Preserve independent canaries, exact ownership, drain-before-restart, and external-state non-mutation. |
| 2026-07-26 | Browser receives a successful page whose content is a regional-denial message | Contract merged in PR #223; bounded daemon adapter under review | Transparent TLS routing sees SNI and encrypted record lifecycle, not the HTTP path, status semantics, DOM, or text. It cannot reliably distinguish a real page from “not available in your area” without decrypting traffic, and Slipstream will not install a MITM root certificate. The language-neutral v1 contract accepts only a normalized non-IP hostname, fixed regional-denial category, bounded confidence/freshness, top-level scope, and replay identity. Unknown or privacy-expanding fields fail closed. Direct, direct-first, local-bypass, reviewed geo-exit, stale, replayed, low-confidence, subframe, and backend-unavailable signals cannot request an action. The daemon adapter uses lifetime-supervised owner-only `0600` Unix IPC with bounded replay/cooldown state and current-policy reclassification. It does not inject the host into the transport-failure candidate map. Instead it performs a distinct exact-host HTTPS GET through the exact owned Geph and learns only when the response is usable and no longer carries bounded regional-denial semantics. The signal itself never changes policy and no hostname enters StatusV2. | Pass full gates and review for the daemon adapter. Then add an explicit Chromium extension plus exact-origin native-messaging host; the service worker must derive host from the browser-owned sender tab and forward no path/query/text/body/cookie/form data. Keep Safari as a separate containing-app/app-extension/signing gate; do not add `weather.com` or phrase-specific host rules. |
| 2026-07-26 | Unknown host delivers an initial TLS payload and then closes before required browser resources complete | Generic exact-host correction implemented locally; full gate pending | The exact PR #220 artifact loaded Modrinth in fresh Chrome with its document, Nuxt CSS/JS, API, fonts, images, and nonblank DOM, proving the zero-payload ladder without a host rule. Crystalidea exposed the next transport shape: its main document and stylesheet could succeed while same-origin JavaScript and images failed with `ERR_CONNECTION_CLOSED`. Direct curl of `assets/js/all.js` ended with code 18 after 16,105 body bytes plus 279 header bytes, exactly 16 KiB, while 167,039 declared bytes remained. The relay swallowed upstream resets, and `_handle_impl` cleared failure state whenever the server ended first after complete TLS records. The correction is generic and exact-host scoped: within the first 32 KiB and 10 seconds, reset/incomplete-record evidence advances the next retry immediately; an orderly complete-record EOF requires two same-host, same-stage observations within five minutes. Real loopback qualification records direction-completion timestamps before transport closure can wake the peer task, and downstream write failure is excluded as browser cancellation rather than server evidence. Large or late closes clear provisional evidence. It never replays a stream after bytes reached the browser, changes static policy, or learns Geph from one close. Discord, YouTube, Googlevideo, direct/reviewed routes, no-SNI traffic, external Geph, and external network settings remain excluded. | Pass full Python/Rust suites and packaged CI, install only the exact merge artifact, then require complete first-load and retry CSS/JS/image plus styled-DOM behavior in fresh Chrome and Safari. Verify that only the exact unknown host advances and that DNS/proxy/PAC, Discord, YouTube, and ChatGPT remain unchanged. |
| 2026-07-26 | Packaged uninstall after qualification plist rewrite | Qualified and merged in PR #220; exact artifact installed | The first packaged run failed with `cleanup incomplete: launchd job remains loaded` because cleanup retried only plist-path `launchctl bootout` after the qualification plist had been atomically rewritten. Cleanup now addresses `system/dev.slipstream.tproxy` directly, falls back to the plist path for compatibility, and polls for exact job absence before any verified PID can be signalled. The complete packaged lifecycle passed on PR and main; the installed daemon and Geph hashes match the exact main bundle. | Preserve the disposable install/restart/uninstall gate and exact-service absence proof. |
| 2026-07-26 | Unknown-host zero-payload routing and browser completeness | Qualified, merged in PR #220, and installed from exact main | Modrinth supplied generic evidence: the system-selected TCP route closed during TLS, while the ownership-verified bundled Geph returned HTTP/2 200. The correction added no Modrinth rule. For any eligible unknown TLS host, the buffered first flight may continue in the same request only while no server byte has reached the client, following `exact system -> per-connection app DNS -> local strategies -> verified owned Geph`. Geph requires confirmed closes from system and app-owned Xbox DNS, every started candidate in at least two distinct local strategies, a clear network-wide guard, and a real owned-Geph payload. Fresh Chrome subsequently loaded the document, Nuxt CSS/JS, API, fonts, images, and nonblank DOM. Protected routes and external network owners remain excluded. | Preserve fresh-profile complete-page qualification. Design scoped QUIC handling separately; never add a global UDP/443 block. |
| 2026-07-26 | Generic browser page can load its document while mandatory same-origin assets truncate inside a later TLS record | PR #219 installed; incomplete-record path qualified, complete-record early close handled separately above | The root daemon remained continuously active before, during, and after the reported Chrome white page and Safari failure, so log inspection did not create the outage. The main document was insufficient evidence: `crystalidea.com/assets/css/all.css` repeatedly stopped inside a later TLS record. System, app-owned Xbox DNS, public DNS, and all six local strategies used the same edge and failed in that shape; ownership-verified bundled Geph returned the complete asset. PR #219 incrementally parses bounded TLSCiphertext framing and requires separate incomplete-record proof from system, Xbox, and two local strategies plus the network-wide guard and exact owned-Geph payload proof. Its exact installed artifact then exposed the distinct complete-record server-first cut documented above. Static policy remains authoritative; Discord, YouTube, direct routes, external Geph, and external DNS/proxy/PAC/VPN cannot enter or be changed by either path. | Keep incomplete-record and bounded server-first evidence as separate contracts; qualify the latter on exact CI/artifact/browser state before merge. |
| 2026-07-25 | Generic Safari page stalls loop between system destination and Xbox DNS | Superseded by real browser-resource evidence on 2026-07-26 | The original system path was already degraded after clean uninstall, but Slipstream's recovery state machine also looped after Xbox failure. PR #215 made generic unknown traffic advance through bounded `system destination -> app-owned Xbox DNS -> local DoH/strategy ladder` states; all three stages were observed on the exact-main installed artifact without Geph or external-state mutation. System, Xbox, and public DNS all returned `173.230.144.164` for `crystalidea.com`. Its synthetic uncompressed HTTP/2 response still stalled after 16,366 of 21,726 bytes, while the browser-like compressed main-document request completed with 5,605 bytes in 0.819 seconds. The later real browser failure showed that mandatory same-origin CSS/JS still stalled, so main-document completion was not sufficient qualification. | Preserve the ordered local recovery regression, but use mandatory subresource and DOM evidence for browser qualification. |
| 2026-07-25 | Historical daemon file-descriptor exhaustion in retained log | Historical; not reproduced in the current exact-artifact session | Older 2026-07-14 lines contained repeated `OSError: [Errno 24] Too many open files`. The 2026-07-25 launchd job used a 16,384 descriptor limit and the failure did not recur during the current smoke. Keep this as a separate lifecycle/soak finding; it is not evidence for the current partial-payload stall. | Add descriptor-use observation to a later soak test if the symptom recurs; do not change routing policy from historical evidence alone. |
| 2026-07-25 | YouTube page succeeds while media TLS fails under installed Slipstream | Qualified on exact main and the installed workstation artifact | The workstation smoke reached YouTube control through local desync, then ten actual `yt-dlp --test` media attempts failed inside the old transparent handling with `SSL: UNEXPECTED_EOF_WHILE_READING` or `SSLV3_ALERT_UNEXPECTED_MESSAGE`. After prepared uninstall, the exact captured `*.googlevideo.com` URL worked over the unchanged system route. PR #214 split the protected family: `youtube.com` and control/static families remain `local_bypass/fake_only`; `googlevideo.com` is exact `direct_passthrough/direct`. Shared Python/Rust/Windows contracts, packaged classification, exact-main CI, and a real installed `yt-dlp --test` Googlevideo download now pass. Both families remain prohibited from Geph, Smart DNS promotion, and external-state mutation. | Keep the shared contracts and exact-main media gate; do not collapse control and media back into one strategy. |
| 2026-07-23 | Windows capture-bound IPv6 fragment input | Additive effect-free composition qualified; native effects closed | Classify through frozen capture v4 before touching fragment state. Bind every retained assembly to one exact capture generation, flow, tuple, transport, and policy result. Reject cross-flow identification collisions without eviction, require classified ports on the first fragment and completed packet, and expire state at the earlier capture-evidence or fragment deadline. With capture v4, the effective maximum is five seconds rather than the normalizer's standalone 60 seconds. Atomic fragments remain stateless even on collision or full capacity. | Add native connector effects as a separate disposable gate; do not instantiate this harness in the production host. |
| 2026-07-23 | Windows byte-owner registry causality | Exact bounded full-registry cursor qualified | Retain the complete latest packet-flow registry after every successful owner operation. Exact unrelated transitions must pass through reconciliation and advance the same cursor. Reject later staging or cleanup from a target-only predecessor that omits that progress, even when the owned target flow itself is unchanged and the stale event freshly reduces. | Preserve the cursor boundary in the selected-stack effect adapter. |
| 2026-07-23 | Windows byte-owner final acknowledgements | Exact effect path and terminal-history pruning qualified | Reject `Forwarded` through generic reconciliation while an owner exists. Commit it only through the injected effect path after exact reducer preflight. If the exact acknowledgement drains and terminalizes the flow but bounded terminal history immediately prunes it, run the effect and release the owner only when both directional queues are empty; never discard remaining bytes. | Keep this invariant in the selected-stack effect adapter. |
| 2026-07-23 | Windows userspace payload ownership | Pure bounded byte owner implemented; selected-stack execution and production composition closed | Open one byte owner only from a current original-tuple binding, the exact packet-flow admission capability retained by that binding, and the complete reducer-issued backend-open and idle-deadline command set; another independently valid destination or request cannot substitute merely because its flow key matches. Every later payload or active reconciliation transition must equal a fresh reduction from its supplied full predecessor and configuration while preserving the complete bound admission. Actual payload enters fixed directional queues only when the supplied predecessor equals the owner's last full packet-flow state, the resulting directional queue grows by the declared length, and flow key, direction, sequence, and length agree. The accepting transition must also contain exactly the permitted forwarding command set, which the frame retains as authorization. This rejects unrelated idle refreshes, caller-constructed commands, and forged public transition state as acceptance evidence. Delayed client payload remains owned and non-forwardable until `BackendReady` supplies an exact one-to-one authorization for the retained queue. Before an injected atomic effect may borrow the front payload, the exact `Forwarded` acknowledgement must reduce successfully from the current full registry and global watermark. Effect failure retains the bytes unchanged; success removes them, advances the retained packet-flow state, and returns the preflighted event. This prevents an unrelated newer flow from making an already-applied effect non-monotonic afterward. Completed prefixes cannot replay and bounds derive from packet-flow configuration. Ordinary terminal cleanup removes only the exact inactive flow; generation retirement removes only flows covered by packet-flow's retired-generation high watermark. Before either path releases bytes, its transition must exactly equal a fresh frozen-v1 reduction from the supplied full registry, including unrelated-flow progress. The frozen selected-stack contract identity is cross-checked, but no `smoltcp`, Wintun, socket, route, DNS, proxy, PAC, VPN, process, service, or production-host effect is linked. | Add a test-only selected-stack effect adapter in the separate evaluation crate. Separately qualify IPv6 fragment input and native backends before production composition. |
| 2026-07-23 | Windows original five-tuple binding | Pure versioned binding implemented; stack execution and production composition closed | Capture v4 extends frozen v3 only after policy classification and retains the original client source IP/port while preserving prior passthrough semantics. It reuses packet-egress's usable-unicast predicate, so link-local and reserved source ranges never become tuples. Userspace-flow-binding v1 joins it to an existing frozen packet-flow-v1 admission only when capture generation, flow ID, transport, destination address/port, IP family, policy, and expiry match, then retains that exact admission capability for downstream open verification. The client source is explicitly not inferred from packet-flow v1's outbound egress source. Language-neutral vectors cover exact binding and every mismatch. The later byte-owner v1 consumes the retained capability and owns payload without changing the original tuple. No `smoltcp`, Wintun, socket, adapter, route, DNS, proxy, PAC, VPN, process, service, or production-host effect is present. | Add a test-only selected-stack effect adapter. Separately qualify IPv6 fragment input before any production-host composition. |
| 2026-07-23 | Windows userspace TCP/UDP stack selection | Selected for effect-free bounded evaluation; production composition closed | Pin `smoltcp 0.13.1` with exact features and checksum in a separate Rust 1.91 test crate. A deterministic fake Layer 3 link with fixed queues and buffers qualifies IPv4/IPv6 TCP, IPv4/IPv6 UDP below the relevant MTU, IPv4 fragmentation/reassembly, and checksum rejection. `ipstack 1.0.1` was rejected because its accepted-stream and packet ownership uses unbounded Tokio channels; `tun2proxy` was rejected as a composition because it owns route, DNS, and proxy behavior outside Slipstream's policy boundary. The selected `smoltcp` version does not emit oversized IPv6 packets. Capture v4, userspace-flow-binding v1, and byte-owner v1 subsequently close the original tuple and payload-lifetime gaps without changing frozen packet-flow v1. | Add a test-only effect adapter in the evaluation crate. Separately qualify IPv6 fragment input, native backends, AMD64/ARM64 packet flow, and lifecycle before production-host composition. |
| 2026-07-22 | Closed Windows IPv6 packet capture and injection | Qualified on PR #196 head, native AMD64/ARM64; exact-main pending | The IPv6 gate reuses the four explicit disposable gates and the already-qualified two-adapter topology: exact `/128` addresses on separate baseline and capture adapters, one owned test-only `/64` baseline route, and one competing owned destination `/128`. A socket bound to the capture source sends one fixed UDP request; the fixture accepts only the exact IPv6 header, addresses, ports, lengths, and payload from that capture session, then injects a synthetic response with the mandatory IPv6 UDP pseudo-header checksum. One absolute deadline covers send, capture, injection, and receive. Exact-route recovery plus explicit removal of the broader route, both addresses, sessions, and adapters remain mandatory. No external endpoint, default route, backend, production-host composition, DNS, proxy, PAC, or VPN state is involved. Native AMD64/ARM64 passed in [run 29954282655](https://github.com/aiwaki/slipstream/actions/runs/29954282655), required/package gates in [run 29954282730](https://github.com/aiwaki/slipstream/actions/runs/29954282730), and audits in [run 29954282707](https://github.com/aiwaki/slipstream/actions/runs/29954282707). | Merge the clean exact head and rerun on exact main. Keep forwarding, pre-existing-flow safety, crash removal, and external-VPN coexistence separate. |
| 2026-07-22 | Closed Windows IPv4 packet capture and injection | Qualified on exact main, native AMD64/ARM64 | The first packet-delivery effect remains inside the four-gate disposable Wintun fixture. One socket bound to the fixture-owned `192.0.2.20/32` sends a fixed UDP request through one owned exact `/32` route. The test reads only the matching Wintun session ring, accepts only the exact IPv4 source, destination, ports, lengths, and payload, injects one checksum-valid synthetic response through that same session, and requires the original socket to receive the exact response within one shared three-second deadline. Route recovery and explicit absence of the exact route, address, session, and adapter remain mandatory even when the active probe fails. There is no external server, default route, backend, production-host composition, DNS, proxy, PAC, or VPN effect. The exact selected test and fixture lint passed on both architectures on PR head in [run 29951216211](https://github.com/aiwaki/slipstream/actions/runs/29951216211) and on the exact merge commit in [run 29952406839](https://github.com/aiwaki/slipstream/actions/runs/29952406839); required/package and audit gates passed on exact main in [run 29952406818](https://github.com/aiwaki/slipstream/actions/runs/29952406818) and [run 29952406838](https://github.com/aiwaki/slipstream/actions/runs/29952406838). | Keep the exact-main gate required. Qualify IPv6 delivery separately before forwarding, pre-existing-flow, crash-removal, or external-VPN claims. |
| 2026-07-20 | Windows no-payload IPv6 socket selection under a competing exact route | Qualified on exact main, native AMD64/ARM64 | IPv6 uses [`IPV6_UNICAST_IF`](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options) with the interface index in host byte order, unlike IPv4's network-order setter. The closed fixture creates two unique Wintun adapters and assigns each one exact `/128` source address. It separately owns one fixed public `/64` baseline route so address creation cannot implicitly create the same controlled prefix, while the production-tested exact-route owner alone creates the competing destination `/128`. The probe reads back the exact interface option, binds the retained baseline source, and performs UDP `connect` without `send` or `recv`. Success requires the route observer to select baseline, then capture, then the identical baseline again, followed by explicit absence of the exact route, broader test route, both addresses, sessions, and adapters. The new broader route exists only in this three-gate disposable fixture, is not a default route, and never enters production. No DNS, proxy, PAC, VPN, backend, or remote payload is touched. Both architectures and strict fixture lint passed on PR head in [run 29745253970](https://github.com/aiwaki/slipstream/actions/runs/29745253970) and on the exact merge commit in [run 29773208168](https://github.com/aiwaki/slipstream/actions/runs/29773208168); required/package and audit gates passed on exact main in [run 29773207895](https://github.com/aiwaki/slipstream/actions/runs/29773207895) and [run 29773208142](https://github.com/aiwaki/slipstream/actions/runs/29773208142). | Keep the exact-main gate required. Qualify actual packet delivery separately; do not call this external-VPN coexistence or production loop avoidance. |
| 2026-07-20 | Windows no-payload IPv4 socket selection under a competing exact route | Qualified on exact main, native AMD64/ARM64 | The feature-only exact-route owner accepts a one-shot read-only active-probe callback. That public callback entrypoint enforces the third socket-binding CI gate itself, while the probe-free exact-route wrapper retains the original two-gate admission. After fresh route attestation, the fixture creates one IPv4 UDP socket, sets [`IP_UNICAST_IF`](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options) with the retained baseline interface index in network byte order, requires `getsockopt` to return that exact index in host byte order, binds the retained baseline source, and performs a UDP `connect` to the exact destination without `send` or `recv`. The active facts simultaneously prove that ordinary route selection points at the Wintun capture identity and its separately owned `192.0.2.2/32` source. Probe failure still runs exact route cleanup and a baseline recovery observation before it is returned; if both fail, the recovery failure is primary and retains the probe failure. The native fixture injects one probe failure before the successful socket proof, then explicitly removes the address and adapter. The socket code exists only in the disposable integration test. It does not enter the route owner or production SCM host and does not touch a default route, DNS, proxy, PAC, VPN, backend, or remote payload. The exact selected test passed on both architectures on PR head in [run 29739433700](https://github.com/aiwaki/slipstream/actions/runs/29739433700) and on the exact merge commit in [run 29741495033](https://github.com/aiwaki/slipstream/actions/runs/29741495033); required/package and audit gates passed on exact main in [run 29741495030](https://github.com/aiwaki/slipstream/actions/runs/29741495030) and [run 29741495046](https://github.com/aiwaki/slipstream/actions/runs/29741495046). | Keep the exact-main fixture required. Qualify packet delivery separately; do not call no-payload selection external-VPN coexistence or production loop avoidance. |
| 2026-07-20 | Exact-route observation on a bare Wintun adapter | Qualified on PR-head native AMD64/ARM64 | The first disposable route-owner run created and verified its exact route, but the post-activation `GetBestRoute2` observation failed with Win32 code `1232` on both architectures. A newly created Wintun adapter has no usable source address by itself; the official Wintun example likewise obtains the adapter LUID and creates a unicast address before packet use. The corrected native fixture creates only `192.0.2.1/32` on its uniquely named disposable adapter through the exact unicast-address row APIs. Mere row presence is not readiness: Windows may report the address as DAD-tentative, so the fixture polls the retained row until its exact interface/address key and `/32` remain unchanged, `DadState` is `Preferred`, and `SkipAsSource` is false. Only then does it run the separately owned exact-route transaction, explicitly delete the retained address row, and prove absence within five seconds. A readiness timeout, lookup error, or vanished row also triggers the same explicit bounded removal before the readiness error is returned; both failures are retained if cleanup also fails. Address APIs remain forbidden in the route owner and production host; `Drop` is only best-effort compensation. The corrected gate passed native AMD64 and ARM64 in [run 29734712632](https://github.com/aiwaki/slipstream/actions/runs/29734712632). | Keep the DAD-safe exact-address and exact-route cleanup gate required. Proceed to socket binding only through a separate disposable fixture. |
| 2026-07-20 | Windows packet egress and loop-avoidance boundary | No-payload IPv4/IPv6 selection qualified; packet delivery remains closed | Windows exposes separate IPv4 and IPv6 per-socket interface selection, while Wintun exposes a stable adapter LUID that can be converted back to the current index. Installing the owned capture route is itself an expected route-epoch transition, so equality between the pre-capture and active epochs would reject every valid plan. The corrected contract pairs fresh pre-capture route evidence with an exact owned activation from that baseline epoch to the current epoch and binds both to the capture generation, destination, exact host prefix, unchanged currently selected source address, and unchanged LUID/index identities. Every later route change invalidates the plan. It always rejects the capture interface and preserves any other system-selected interface, including an external VPN, without classifying or mutating it. IPv4 stores the interface index in network byte order and IPv6 in host byte order. The module has no route query, notification, socket, adapter, route, backend, or production effect. The disposable owner preserves structured Win32 data from route observations, keeps the original activation failure primary when route-epoch invalidation also fails, and makes an unproven cleanup failure primary while retaining both rendered causes. | Keep no-payload selection required. Qualify closed IPv4/IPv6 packet delivery separately before pre-existing-flow, bounded-removal, and external-VPN coexistence gates. |
| 2026-07-20 | Abrupt Wintun owner-process termination | Qualified on exact-main native AMD64/ARM64 runners | The fixture spawns only its exact integration-test executable. The child independently admits the pinned DLL, creates one unique `SlipstreamCI-Crash-*` adapter and minimum session, and atomically publishes its exact adapter name and PID. The parent proves that name is live, terminates only the retained child handle without running Rust destructors, waits for that exact process, and accepts success only after `WintunOpenAdapter` reports the unique name absent within 30 seconds. A 90-second child fail-safe exits without destructors if the parent itself fails. The gate performs no process-name search, adapter/driver deletion, route or address configuration, or DNS/proxy/PAC/VPN mutation. Both native architectures passed in PR [run 29713791755](https://github.com/aiwaki/slipstream/actions/runs/29713791755) and exact-main [run 29714575179](https://github.com/aiwaki/slipstream/actions/runs/29714575179). | Keep the cleanup subgate required. Continue with separate loop, activation, removal, and VPN-coexistence proofs. |
| 2026-07-20 | Wintun native lifecycle and partial artifact delivery | Qualified on exact-main native AMD64/ARM64 runners | A direct download of the pinned 750,540-byte Wintun archive exited successfully after writing only 16,366 bytes and produced no ZIP central directory. The existing artifact admission would reject it, but transport exit status alone is therefore not download evidence. The native fixture retains the exact read-only admission while loading only the matching-architecture DLL, creates one unique adapter, starts/ends a 128 KiB session, and removes only that adapter. Its workflow retries boundedly and accepts the archive and DLL only after exact length and SHA-256 checks. It never calls `WintunDeleteDriver` or configures routes, addresses, DNS, proxy, PAC, or VPN. The first native run proved that Wintun 0.14.1 reports an absent adapter as `ERROR_NOT_FOUND (1168)` on both x64 and ARM64; the pre/post proof accepts only that code or `ERROR_FILE_NOT_FOUND`, and every other open failure remains fatal. The corrected fixture passed in PR [run 29712583287](https://github.com/aiwaki/slipstream/actions/runs/29712583287) and exact-main [run 29713033740](https://github.com/aiwaki/slipstream/actions/runs/29713033740). | Keep this compatibility subgate required. Do not infer capture or routing readiness from it. |
| 2026-07-20 | Packaged qualification used a superseded Geph release | Root cause proven; workflow fix under CI | `ci.yml` and `owned-geph-qualification.yml` derived only `geph-vendor-0.3.0`, while `vendor/geph/SOURCE.json` records revision `1` and `build-app.yml` correctly uses `geph-vendor-0.3.0-r1`. GitHub labels the unrevisioned release superseded; its `geph5-client` SHA-256 is `a1df14cb...`, while r1 is `3299d20f...`. The previous packaged lifecycle therefore qualified the macOS/PF lifecycle around a different Geph binary than the release path. A coincident GitHub `503` exposed the mismatch. Every workflow download now derives the immutable revisioned tag and uses one bounded retry helper that publishes no partial output. | Disqualify the downloaded `140598b` app from workstation testing. Require the exact corrected merge commit to pass packaged lifecycle with r1, then download that artifact without launching it. |
| 2026-07-20 | Packaged daemon blocked before first StatusV2 during controlled install | Root cause reproduced; workstation rollback clean; bounded startup fix under qualification | Exact artifact `c07ade34` started its listener and standalone Telegram-proxy check, then emitted no later session line before the installer reported `status missing`. The private anchor had not armed. Workstation evidence showed synchronous system DNS could stall on the first neutral target while a later target was directly reachable. The resolver ran in the daemon process with no timeout, and `amain()` wrote its first status only after awaiting the whole PF qualification. System-DNS lookups now run under the console user in killable child processes with per-target limits and one monotonic preflight budget. Startup publishes a probe-free `dormant` snapshot immediately after listener creation; regular status consumes cached DNS diagnostics, whose background refresh uses the same bounded resolver helper. A real sleeping child proves timeout and process disappearance. The packaged lifecycle now blackholes the first neutral target at the macOS resolver layer, captures the already-published status at that query, requires a later target to activate, and rejects a surviving helper. | Pass full Python/Rust checks and the exact packaged lifecycle before any new workstation install; do not use the primary workstation as the first privileged gate. |
| 2026-07-19 | Private PF traffic never reached the listener on the primary Mac | Root cause proven; scoped high-port smoke passed; packaged qualification pending | The anchor and listener were individually healthy, but the live kernel interface table contained `lo0 (skip)`. That state was not declared in `/etc/pf.conf`; therefore source inspection and anchor listings could not explain why post-arm probes failed. XNU defines `PFI_IFLAG_SKIP`, `DIOCSETIFFLAG`, and `DIOCCLRIFFLAG`. A bounded probe cleared only that bit, used the four-rule `route-to`/`rdr`/`no state`/`reply-to` topology on TCP/18443 -> 19443, recovered the original destination, then restored the exact flag. The production path now records a durable root-owned lease before clearing the bit and restores it before token release. A separate privileged smoke passed with both owned anchors empty afterward, the external sentinel and global rules unchanged, `lo0 (skip)` restored, no token/lease/status residue, and no test listener. Control-D was rejected because it reloads global PF state even though it also changes loopback visibility. | Run the exact branch through script and packaged lifecycle CI. Keep the primary workstation dormant and do not install until the PR merges with all safety gates green. |
| 2026-07-19 | Automatic macOS HTTPS baseline rollback | Implemented locally; disposable packaged qualification pending | A small neutral canary set is resolved through the console user's current system route, then verified with TLS and an HTTP response before PF. After arming, the same console-user helper replays only the exact pre-proven numeric destinations through the installed daemon. One successful post-arm proof is sufficient; no target hostname or address enters public status. Preflight failure leaves PF dormant and retries after a bounded delay. Postflight failure clears only `com.apple/slipstream`, releases only its enable token, and blocks automatic re-arm until an actual wake/network change. If pfctl cleanup fails, the daemon retains the listener and runtime and retries cleanup; force-stop and install rollback refuse to create a redirect-to-dead-listener state. Local execution proved the hidden helper against the user's unchanged current route, where system DNS selected `8.6.112.0` for `example.com`; the probe received HTTP `206`. | Run the exact packaged branch through the disposable Safari/Chrome/PF-sentinel lifecycle. Do not install it on the primary workstation before that required job passes and the reviewed merge commit is requalified. |
| 2026-07-19 | Clean install left every local-bypass service inactive | Fixed in code; packaged qualification pending | Exact-main `0.1.8` installed successfully but reported `dormant` with `local_engine=inactive` when no owned Geph listener existed, so Discord and YouTube received no local bypass. `pf_setup_if_ready()` incorrectly gated the whole private anchor on geo-exit readiness, while the packaged lifecycle smoke hid the defect by rewriting the installed LaunchDaemon with `SLIP_GEPH=0` before expecting `active`. Local PF readiness is now separate from optional Geph readiness. A geo-exit request with no app-owned backend keeps its reviewed route class and tries only the original pre-PF destination; it performs no alternate DNS lookup and never enters Discord/YouTube desync policy. A full-tunnel `utun*` default route still makes Slipstream yield its own anchor, while split/per-app VPN equivalence remains unqualified. | Require clean install and reinstall to become `active` with no Geph account, listener, or test-only environment patch. Keep the workstation uninstalled until the disposable packaged lifecycle passes, then verify Discord and YouTube locally before resuming M4. |
| 2026-07-18 | Fixed ChatGPT retry burst after uninstall | Owned teardown fixed; Smart-DNS HTTP/3 fallback remains external evidence | The old tray stopped owned Geph before the root daemon, and the daemon handled `SIGTERM` with immediate `os._exit`, so accepted TCP streams were cut. In the same incident, user-managed Smart DNS mapped OpenAI names to `87.228.47.204`; macOS recorded a viable HTTP/3 flow timing out after about 180 seconds and Chromium recorded repeated broken QUIC attempts before stable TCP fallback. PF did not intercept QUIC. Uninstall now closes the listener and private anchor first, drains accepted streams under a deadline while Geph stays alive, then removes the exact Geph job. Only that successful user cleanup authorizes the privileged helper to stage and delete the validated app bundle. Root cleanup fails visibly if a verified daemon survives. | Keep the primary workstation uninstalled. Qualify the exact packaged lifecycle on disposable CI, including absent daemon/Geph PIDs, listeners, app bundle, and preserved external DNS/PF state. Do not hide the external fallback by changing DNS or globally blocking UDP/443. |
| 2026-07-20 | Windows exact-route completeness feasibility | v1 frozen; pure capture-only v2 implemented | Read-only system-DNS observation cannot enumerate every concrete hostname sharing an address: policy suffixes cover an unbounded set, applications may use DoH, and Wintun carries packets rather than hostname-bearing accepted streams. Therefore the existing complete-boundary evidence type is useful only as a conservative pure test gate; no honest native issuer can satisfy it as designed. V2 now classifies each already-observed flow from at most five seconds of transport-matched TLS SNI or QUIC Initial evidence and preserves direct passthrough for direct, unknown, ECH, missing, malformed, stale, unsafe, or mismatched observations. It cannot authorize a backend or perform a native effect. | Specify disposable loop, pre-existing-flow activation, bounded removal, crash rollback, external-VPN coexistence, AMD64, and ARM64 proofs. Do not load Wintun or mutate routes until every gate passes. |
| 2026-07-18 | Windows shared-destination conflict admission | Pure v1 gate implemented; native path abandoned | An exact IP route can capture unrelated domains on the same CDN address. A partial resolver cache or absence of a known conflict is insufficient. The pure gate requires opaque complete-boundary evidence for one exact destination and rejects mixed routing policy. Its admission remains non-authorizing. | Preserve the gate and fixtures as a record of the rejected assumption; do not implement a native issuer or route from it. |
| 2026-07-18 | Native Wintun artifact evidence | Implemented and qualified read-only | The native collector hashes bounded non-reparse archive, license, and DLL handles, parses the exact PE machine, and gives `WinVerifyTrust` the same held DLL handle. It performs no UI or network retrieval, extracts the exact certificate organization and SHA-256, requires a trusted timestamp countersigner, and retains the DLL handle in an opaque admission. Windows CI admitted both official AMD64 and ARM64 DLLs and rejected a tampered copy without loading Wintun or creating adapters/routes. | Keep the collector frozen and offline. It does not justify DLL loading or route mutation; any future use depends on a separately reviewed v2 capture contract. |
| 2026-07-18 | Windows packet-route evidence review | Pure host/address binding fixed; v1 frozen | A policy result and a caller-labeled DNS source did not prove that the selected destination came from resolving the policy host; reserved IPv6 such as `::2` could also pass the former denylist. Route requests now consume opaque host/address evidence and conservatively admit only reviewed global-unicast destinations. This still cannot prove every co-tenant on a shared address. | Retain the non-authorizing fixtures. Do not infer backend safety from a partial DNS view. |
| 2026-07-18 | Windows production signing and packet-adapter pivot | Artifact collection retained; exact-route authorization rejected | Do not ship a Slipstream-owned kernel driver. The official signed Wintun package remains the only reviewed packet primitive, but Wintun is L3 rather than an accepted-stream source. Candidate `/32` and `/128` plans cannot authorize local-bypass or geo-exit and cannot mutate default routes or external DNS/proxy/PAC/VPN. | Evaluate only a capture-only v2 boundary with per-flow reclassification and direct fallback. Keep DLL loading, adapter creation, routes, and production composition disabled. |
| 2026-07-18 | Native Windows TCP capture mechanism | Superseded shipping path; frozen research contracts remain | The WFP wire, runtime, and management-session contracts still document a safe connect-redirect lifecycle, but implementing it requires a separately signed Slipstream kernel driver. Do not build or package that driver. | Preserve v1 fixtures without composing them. Continue through the no-own-driver Wintun packet boundary. |
| 2026-07-17 | Python signed-policy activation adapter | Implemented with parity and effect-failure coverage | The daemon's verified candidate apply, health gate, persistence, rejection restore, startup load, and single-slot rollback now execute behind activation contract v1 under one lock. Current and previous policy files are updated as one compensating transaction; corrupt rollback slots, candidate-write failure, and runtime activation failure preserve the prior files and active manifest. Every consumed generation is written to an owner-only activation sidecar before candidate activation, so rejection followed by daemon restart cannot reuse it; successful policy files also retain backward-compatible generation metadata. Persisted signed provenance remains signed even when a legacy bundle contains the exact bundled manifest. A new signed envelope with the already-active canonical SHA-256 is intentionally the frozen v1 content-addressed `no_change` case and is not persisted. The old direct signed apply/save entry points are removed, while the remote URL remains opt-in and no production trust material is present. | Keep the Python adapter and reducer contract frozen under failure injection. Build the first no-network Windows adapter harness against `slipstream-core` before adding any platform networking effects. |
| 2026-07-17 | Cross-language signed policy activation | Implemented in shared Python/Rust contract v1 | The existing daemon temporarily applied a verified candidate, ran a health callback, then restored or persisted it through one imperative path. That path did not give future adapters a shared transition model or explicit stale-event guard. `route-policy-activation-v1.json` now binds trial start and rollback to the expected active SHA-256 and binds health to both the exact candidate SHA-256 and a reducer-issued monotonic trial generation. The generation persists after abort or rejection, so a delayed result cannot commit a later retry of identical policy content. Only one verified signed candidate may be in trial. A completed gate commits only with at least one success and no degraded or blocked checks; every rejection restores the stable active identity. One previous identity is retained per successful commit, rollback consumes it before falling back to bundled policy, and rollback during trial aborts only that candidate. The reducer emits ordered data-only actions and performs no fetch, signature verification, persistence, runtime apply, PF, DNS, proxy, PAC, VPN, or routing work. | Keep activation contract v1 frozen; the Python runtime migration is recorded in the adapter finding above. |
| 2026-07-16 | Cross-language signed policy canonicalization | Implemented in shared Python/Rust contract v1 | The former signature verifier lived only inside `tproxy.py`, so a future adapter could normalize the same manifest but sign different bytes, especially when `source` contained Unicode. `route-policy-bundle-v1.json` now freezes canonical hashes for ASCII, Unicode, quotes, backslashes, and controls, plus Ed25519 envelope success and structured failure vectors. Rust emits the same sorted compact JSON as Python `json.dumps(..., ensure_ascii=True)`, uses strict verification, and keeps v1 isolated. The pinned crypto graph remains compatible with the core's Rust 1.77 floor. The only committed key is an explicit deterministic fixture key. No production trust, fetch, apply, PF, DNS, proxy, PAC, VPN, or routing behavior changed. | Keep bundle contract v1 frozen. Define the pure signed-policy activation/rollback state transition next; runtime storage and transport remain adapter effects. |
| 2026-07-16 | Public status resurrection during daemon shutdown | Fixed with a deterministic concurrent regression | The first packaged lifecycle attempt in CI run `29523214490` cleared the private PF anchor but still observed `/var/run/slipstream.status`. `pf_teardown()` removed the file without coordinating with `network_monitor`; an in-flight `write_status()` could subsequently complete its atomic replace and recreate stale `active` state. Shutdown now sets a one-way event before cleanup and uses the same reentrant lock as status publication. Teardown removes both the final and temporary paths after any in-flight writer completes; later writers return without touching disk. No PF, DNS, proxy, PAC, VPN, or routing behavior changes. | Keep the concurrent regression in the daemon suite and the packaged lifecycle disappearance assertion required. Treat a surviving status file after daemon exit as a lifecycle defect, not proof that routing is still active. |
| 2026-07-16 | Route-policy manifest first-match validation | Implemented in shared Python/Rust contract v1 | The former validator required a Discord/YouTube group entry and the direct-first suffix strings somewhere in `static_routes`, but classification uses the first matching entry. An earlier generic entry could therefore shadow a later correct entry, including a narrower rule such as `updates.discord.com` before `discord.com`; a `geo_exit` entry placed in `static_routes` would also run before the Russian direct guard. The v1 validators now normalize bounded DNS hostnames, reject static-table geo exit and protected geo overlaps, and classify every bundled protected suffix plus every explicitly listed subdomain inside that family through the normalized table to prove its exact route, service group, and strategy. | Keep manifest contract v1 frozen and require every signed-bundle implementation to consume its normalized result. |
| 2026-07-15 | Bounded persistent route-circuit state | Implemented in shared Python/Rust contracts and the production handler | Injecting one persistent `local_engine` state into each address race would be incorrect: two failed strategies inside one request could open the circuit, and unrelated unknown hosts would suppress one another. Persistence therefore sits above the transport race. A full Discord/YouTube local ladder records one outcome; freshly proven Smart DNS and verified owned Geph record separate geo-exit backend outcomes. Owned Geph closes a half-open circuit on the first downstream payload delivered to the client rather than waiting for a long-lived WebSocket relay to end; zero-payload early close still reopens it. Unknown/direct traffic and external Geph stay one-shot. The registry keeps at most 256 non-default states for five idle minutes, uses deterministic LRU eviction, and fails open to the already-selected route if its own state becomes invalid. Eviction only forgets backend suppression. It cannot promote a host, change policy, or move protected local traffic to Geph. Shared vectors cover TTL, LRU, half-open concurrency, backend isolation, success reset, and protected-key rejection; handler contracts prove per-ladder accounting, long-lived half-open recovery, Smart DNS-to-owned-Geph same-route fallback, and unknown-host non-persistence. | Keep reducer and registry contract v1 frozen. Add any new backend or longer suppression window only with a traffic contract proving that it cannot broaden routing or strand transparent traffic. |
| 2026-07-15 | SafariDriver server startup denied on one hosted worker | Fixed; packaged qualification passed | The final docs-SHA run for PR #112 failed before Slipstream, PF, the daemon, tray, or Geph started because `/usr/bin/safaridriver` could not open the fixed `127.0.0.1:19445` server: `Unable to start the server: Operation not permitted`. Two earlier runs of the exact cleanup code passed on the same macOS 14.8.7 runner image, while the denial occurred on a different worker. `safaridriver(1)` defines immediate startup failure when the requested port is occupied or otherwise unavailable. The disposable-CI wrapper now asks the kernel for an available IPv4 loopback port, enables SafariDriver diagnostics, and permits one fresh-port retry only for the explicit server-start `EPERM` or address-in-use messages. Unknown startup failures remain fatal, and no retry can occur after the privileged lifecycle begins. The hardened wrapper then passed the full packaged lifecycle, including all Chrome and Safari stages, tray crash/restart, PF sentinel preservation, and uninstall. | Keep SafariDriver infrastructure failure distinct from routing failure. If the bounded fresh-port attempt also fails, preserve its diagnostics and fail the release gate rather than skipping Safari coverage. |
| 2026-07-15 | Script installer dependency closure after runtime adapter wiring | Fixed after CI caught the omission | The first PR run passed unit tests but its script-mode lifecycle daemon produced no StatusV2 because `_script_runtime_payload()` copied the older local module set and omitted `connection_probe.py` plus its address-race dependencies. Transactional install rolled back safely and left no daemon/PF log evidence. The payload manifest now includes the complete local dependency closure, and preflight tests remove each new module in turn to require failure before any partial install directory is created. The frozen packaged daemon resolves direct imports separately. | Keep script and frozen lifecycle jobs required whenever a new local runtime import is added; do not infer routing failure from a daemon that never reached module import completion. |
| 2026-07-15 | First-payload address race in the transparent handler | Implemented behind a policy-preserving wrapper | `spike/connection_probe.py` adapts the existing per-IP dialers to the owned connection-race I/O layer. Policy, route class, strategy, and backend are fixed before a race begins; a candidate succeeds only after the existing dialer receives first server bytes. The runtime handler now races resolved local addresses per strategy, app-owned Xbox DNS answers, and freshly proven Smart DNS answers. It does not race or reorder strategies, enter the Geph branch, or mutate system DNS. Fake handler tests prove that a stalled first Discord or Smart DNS edge is cancelled when a second edge returns payload, while Geph is forbidden. Cross-request circuit state now lives in the separate backend-outcome registry above, not inside this address adapter. | Keep connection-race contract v1 frozen. Qualify this exact packaged daemon on disposable CI; add daemon IPv6 dialers only in a separate evidence-backed change. |
| 2026-07-15 | Packaged lifecycle Chrome mixed-UID process-group `EPERM` | Fixed; repeated packaged qualification passed | An earlier PR #107 run and the first two packaged runs for PR #109 ended with a bare `[Errno 1] Operation not permitted` after the private anchor became active, while adjacent `main` runs were green. Stage and operation instrumentation reproduced the denial specifically at `killpg(chrome_pgid, SIGTERM)` after the expected DOM had already loaded; spawn, profile ownership, the daemon, and PF were not failing. Delegating the same group signal to the browser UID still failed intermittently. macOS `kill(2)` documents that signaling a process group returns `EPERM` when any member cannot be signaled, and a Chrome session may contain protected OS/XPC members. The harness therefore enumerates the exact PGID, selects only members with the original browser UID, and delegates those exact PIDs to an isolated helper that rechecks every PID's PGID immediately before signaling it. Different-UID members are never passed to the helper. Missing/reused PIDs are benign; permission denial and every other inspection/helper failure remain fatal. No retry or `EPERM` suppression was added. The exact code revision passed the full packaged lifecycle twice consecutively, including all four Chrome and Safari stages per run, tray crash/restart, PF sentinel preservation, and uninstall. | Preserve exact PID/PGID/UID checks; never replace this with broad process matching or alter routing/PF in response to a browser-cleanup denial. |
| 2026-07-15 | Safari cleanup identity after WebDriver session deletion | Fixed; repeated packaged qualification passed | A post-merge packaged run reached `before-tray-start:safari`, loaded the expected page, deleted its isolated WebDriver session, and then observed the exact Safari PID as `identity=(501, '(Safari)')`. macOS `ps` renders a zombie command in parentheses, so executable-path matching correctly rejected it as unowned but cleanup incorrectly treated the already-exited process as live. Safari inspection now reads UID, process state, and command together. Only a `Z*` state with the expected browser UID is considered stopped without a signal; live unexpected commands, different UIDs, and malformed identities remain fatal. The exact code revision passed the full packaged lifecycle twice, including Safari before tray start and after tray crash/restart. | Keep exact PID/UID/executable checks for live Safari. Never signal a zombie or relax identity matching based on a parenthesized command alone. |
| 2026-07-14 | Address racing and scoped circuit breaking | Scripted cross-language adapters implemented; Python loopback adapter added 2026-07-15 | A resolver result is an ordered set of expiring candidates, not one address. The planner interleaves the preferred and alternate families, bounds concurrent attempts under one deadline, and deterministically cancels losers. The new connection-race state machine gates a route circuit before resolver work, emits only resolver/start/cancel/wake commands, records one result for the whole logical request, and ignores late adapter completions. A deadline wake defers one deterministic turn when an attempt is still running, so an exact-deadline completion wins even if the timer was dequeued first; success after the deadline is rejected. Python and Rust execute the same fake resolver/socket vectors for stalls, resets, family fallback, deadlines, route isolation, half-open recovery, and Discord's no-Geph invariant. No reducer or scripted adapter performs network I/O or changes routing policy, PF, DNS, proxy, PAC, or VPN state. | Keep contract v1 frozen and define any production call site as a separate reviewed change. Never make a circuit opening imply Geph fallback. |
| 2026-07-14 | File-descriptor exhaustion and incomplete uninstall | Relay/FD fixes retained; uninstall ordering revised 2026-07-18 | The daemon log contained 2,115 `Too many open files` entries after roughly 8.5 hours, preceded by half-open relay tasks and repeated geo-exit closes. Direct, Telegram, Smart DNS, and Geph branches did not share the generic relay's first-completion lifecycle; failed async dials and restarted embedded Telegram loops also had incomplete cleanup. Once `accept()` reached `EMFILE`, the listener and private PF redirect remained present although the daemon could no longer serve traffic. All backends now use one bounded relay lifecycle, every opened async writer is closed and awaited on failure, replaced Telegram loops close their selector, and FD pressure releases an emergency reserve then pauses only `com.apple/slipstream` until the low watermark. The earlier user-Geph-first uninstall order was later proven disruptive and is superseded by the 2026-07-18 drain finding above. User DNS remained unchanged throughout diagnosis and cleanup. | Keep the FD and relay regressions. The disposable packaged soak must also prove the revised daemon-first quiesce/drain order and complete process/app removal. |
| 2026-07-13 | Real Safari restart qualification | Implemented; disposable CI required | The macOS runner includes matching Safari and SafariDriver builds. A guarded wrapper enables WebDriver only on disposable CI, starts the exact system driver as the original user on IPv4 loopback, and passes that endpoint explicitly to the privileged lifecycle harness. The WebDriver control connection is direct localhost and cannot inherit proxy settings. Every stage requires no pre-existing Safari process, creates a new isolated automation session, verifies the resulting browser PID by exact UID and executable path, requires the expected HTTPS page source over `h2` or `http/1.1`, deletes the session even after failure, and signals only that verified PID if Safari remains alive. HTTP/3 is rejected as insufficient TCP/PF evidence instead of being blocked. Normal Safari data and external DNS/proxy/PAC/VPN remain untouched. | Keep SafariDriver startup failure distinct from routing failure; add physical default-route/lid transitions and account-backed owned Geph on a disposable Mac. |
| 2026-07-13 | Real Chrome restart qualification | Implemented; disposable CI required | Start the runner's exact Google Chrome binary as the original user, including its real supplementary groups, with a new `0700` profile for each request before tray start and after tray crash/restart. Disable proxy use, background traffic, and QUIC only for that process so a successful DOM load proves a fresh browser TCP/443 path without changing system DNS/proxy/PAC/VPN or a real profile. Hosted macOS runners can emit the valid DOM and then keep helpers alive after repeated `com.apple.backupd.sandbox.xpc` errors, so the harness accepts only the expected page marker and then terminates its dedicated Chrome process group instead of waiting for unrelated runner XPC cleanup. | Keep the exact executable and owned process-group cleanup mandatory in CI; add physical route/lid transitions and account-backed owned Geph on a disposable Mac. |
| 2026-07-13 | Packaged tray-crash independence | Disposable CI implemented | Run the real packaged tray as the original user, kill only an exact UID/path-owned PID, and prove that fresh non-root HTTPS clients plus the same daemon/PF lifecycle survive tray crash and restart. Do not forward proxy or CI-secret environment into either child process. | Keep Chrome and Safari process qualification in this gate; add physical route/lid transitions and account-backed owned Geph on a disposable Mac. |
| 2026-07-13 | Installed wake/network lifecycle soak | Implemented; disposable CI required | The existing monitor already recovered from a cadence gap and default-interface change, but installed qualification only covered daemon restart. Script and packaged-daemon jobs now run two exact-PID cycles: an uncatchable process suspension crosses a CI-only six-second wake threshold through the production cadence detector (the production default remains 30 seconds), and a bounded diagnostic signal queues the same network-change helper used by interface detection. Every cycle requires a fresh StatusV2 recovery count, the original daemon PID, an active private anchor, and an unchanged sibling anchor, PF state, and live connection. The signal handler itself performs no PF or network work. | Keep workstation installation prohibited. Add physical default-route/lid-close and account-backed Geph soak on a sacrificial user session. |
| 2026-07-13 | Transparent lifecycle recurrence and respawning processes | Fixed in this PR; workstation install prohibited | ChatGPT/Codex recovered only after the root job was absent and disabled, the private anchor and token were gone, and no owned daemon or Geph process remained; user DNS was unchanged. `KeepAlive` explained process respawn, while the old installer could report success without verifying status/listener/PF and could leave a half-installed job. Installation is now transactional, failure disables and removes only owned state, startup/watchdog honor absent or disabled launchd state, missing status falls back to exact listener-PID ownership checks, and tray uninstall can use its bundled daemon when `/usr/local/slipstream` was already deleted. | Run packaged install/failure/reinstall/uninstall and PF-sentinel qualification on disposable CI only. Do not install or re-arm this branch on the primary workstation before that gate passes. |
| 2026-07-13 | False generic auto-Geph promotion | Fixed in this PR | `www.google.com` was recorded as a seven-day `geo_exit` after repeated local stalls and a successful Geph payload probe. That observation cannot distinguish IP geo-restriction from an incorrect local strategy, transient edge issue, or normal browser behavior. Generic stalls retain only the bounded exact-host Xbox DNS local retry; they never select or persist Geph. Legacy learned entries are discarded on daemon start. | Keep foreign-exit routes explicit and reviewed; treat a successful Geph payload only as tunnel health evidence. |
| 2026-07-13 | Google and Spotify direct-first local fallback | Fixed in this PR | Runtime strategy cache showed Spotify endpoints using cached `split64+fake` even though the service works natively. `google.com`, `spotify.com`, `spotifycdn.com`, and `scdn.co` now always try direct/plain TLS first, then may use only bounded local desync; Geph is excluded and a signed policy cannot silently omit those protected suffixes. YouTube/googlevideo remains independently local-bypass/fake-only. | Add another direct-first family only from observed native-success evidence; do not turn this into a broad allowlist. |
| 2026-07-13 | OpenAI billing synthetic canary | Fixed in this PR | `billing.openai.com` repeatedly closed a Geph SOCKS connection while `chatgpt.com`, `claude.ai`, and Steam Store passed through the same owned tunnel. The billing probe exercised an edge-specific anti-abuse/exit behavior rather than a dependable primary user flow, so it could falsely turn the whole geo-exit route into `Needs attention`. Billing stays geo-exit when a browser actually uses it, but is removed from canonical health canaries. | Keep health transitions tied to primary end-to-end flows; add a new secondary endpoint only with evidence that its synthetic probe predicts a real user-visible failure. |
| 2026-07-12 | Smart DNS capability path and Telegram proxy semantics | Backend ordering retained; PF pause superseded 2026-07-19 | A user-managed Xbox DNS route is eligible only after a fresh local payload proof, then may be the first geo backend with Geph fallback when owned Geph is ready. The earlier whole-anchor pause is no longer used when those optional backends are absent: the exact pre-PF destination gets a bounded plain probe while local bypass remains active. Raw Telegram DC passthrough is only non-interference; a network that blocks direct MTProto needs the bundled local proxy. | Keep Smart DNS proof and runtime fallback scoped to OpenAI/Anthropic; do not promote Telegram raw DC to a user-facing success state. |
| 2026-07-12 | Deterministic data-plane traffic contracts | Implemented | Routing regressions must cross the real `_handle_impl` with deterministic TLS, DNS, and upstream fixtures. Each named journey asserts its required backend, forbidden backend, and delivered response payload, so a passing isolated canary cannot hide a wrong decision or relay branch. | Add a contract before changing routing for any new incident class; keep PF/lifecycle and live endpoint qualification separate. |
| 2026-07-12 | Stale PF token after false daemon recovery | Fixed in this PR | The old StatusV2 reader could label a fresh V2 snapshot `off`, then recovery cleared the private anchor and released its PF token immediately after daemon boot. The daemon still held that token only in memory, so re-arm attempts stopped after a failed release and repeated `pf anchor vanished` every five seconds. When the token file is absent and PF is definitively disabled, clear only that stale memory reference and acquire a fresh private token. | Preserve the stale-token and enabled-PF fail-closed regression tests. |
| 2026-07-12 | Discord local-bypass canary false negative | Fixed in this PR | The local canary preflight used `build_fake_clienthello()`, an intentionally minimal TLS 1.2 `AES128-SHA` offer. `updates.discord.com` rejects that offer with a handshake-failure alert even while modern browser/curl traffic succeeds, so four Discord endpoint checks could falsely degrade the whole local-bypass route. The canary now starts directly with its existing modern `ssl.MemoryBIO` payload probe, applying the same local fake/desync to that real first flight; its bounded payload budget is eight seconds because the Discord gateway API consistently responded in about 5.18 seconds on the affected network. This never changes route class or uses Geph. | Preserve the no-synthetic-preflight regression; validate a packaged canary run with Discord and YouTube remaining local only. |
| 2026-07-12 | Partial local stream stall after clean client EOF | Fixed; preview and live-verified | A local TLS route can return an initial payload above the former 8 KiB success threshold and then stop. On the affected network, `crystalidea.com` returned HTTP 200 with 16,366 of 21,726 bytes before a 25 s client timeout. The clean-EOF reducer was correct but unreachable: `_handle_impl` used `asyncio.gather`, so after the client timed out it waited forever for a stalled server-to-client `splice`, never recording the exact-host outcome. The generic non-geo local relay now records which direction completed first and cancels the useless peer task; only two client-first EOFs after at least 15 s without downstream progress for the same unknown host in five minutes demote the exact strategy. The next retry makes an app-owned RFC 8484 Xbox DNS query and tries its answer locally with plain TLS. The current resolver and Xbox DNS both returned `173.230.144.164` for this host, so DNS is an exact local attempt, not a promise of an alternate edge. Preview.14 passed packaged lifecycle qualification; three subsequent installed-daemon requests retrieved the complete `crystalidea.com` payload (HTTP 200, 21,726 bytes) in about one second each. Server-first completion clears pending evidence. This path never selects or learns Geph. | Preserve the relay-direction, repeated-EOF, and protected-host regression tests; observe a future genuine partial stall before changing thresholds. |
| 2026-07-11 | Sidecar-only diagnostics | Fixed in this PR | A root daemon can be removed while the independent user Geph LaunchAgent remains. The user job does not by itself prove active transparent routing, but the previous diagnostic snapshot hid the distinction. | Preserve the bounded `summary.geph_lifecycle` signal; do not infer PF without privileged evidence. |
| 2026-07-14 | User Geph lifecycle teardown | Revised in this PR | Removing the root daemon manually leaves the independent user LaunchAgent alive by design. Confirmed uninstall must therefore stop and remove only the verified user-owned Geph state before the root prompt, then remove the exact validated app bundle after the tray exits. A root failure leaves the app available for retry but cannot leave bundled Geph running. | Preserve exact label/PID/executable/config/listener checks and packaged uninstall coverage; never replace them with broad process matching. |
| 2026-07-11 | Geo-exit early payload close | Original whole-anchor recovery superseded 2026-07-19 | Logs showed `chatgpt.com` returning `remote closed without response` after a successful Geph SOCKS connect. The original fix paused the private PF anchor for a native retry. Current behavior instead cools only Geph so Discord/YouTube local bypass remains available; because the consumed stream cannot be replayed, its next client retry may use the exact pre-PF system destination. | Keep the zero-byte early-close and system-destination regressions in the real handler contracts. |
| 2026-07-11 | Geph exit catalog fallback | Fixed | A cold tray launch could expose a hardcoded country-only menu before Geph's live city catalog or cache became available. The cache subsequently contained the correct city entries, but the temporary choices were misleading. | Keep the explicit unavailable state until cache/live data exists; the background refresh replaces it automatically. |
| 2026-07-11 | LaunchAgent ownership record rendering | Fixed in 0.1.6 follow-up | A literal patch marker in the generated shell continuation shifted printf arguments, leaving geph-owned.json invalid although launchd ran. The daemon correctly treats invalid ownership as unowned; it must never guess. | Regression-test the generated ownership write line and requalify a packaged app after launcher-template changes. |
| 2026-07-11 | Packaged-app installed lifecycle | Disposable CI passed | Build the real arm64 Tauri `.app`, install its embedded frozen daemon, and run cold install, same-artifact reinstall, active restart, and uninstall while preserving a non-root sentinel connection, its PF state, the sibling anchor, and the global PF snapshot. Upload only the qualified `.app`. Do not use `v0.1.4` as a rollback fixture because it predates the private-anchor safety fixes. | Make the first safety-qualified release the baseline for a later cross-version update/rollback gate. |
| 2026-07-11 | Live private anchor misread as legacy global PF | Global reload removed 2026-07-16; qualification pending | A forced restart can leave the owned child anchor populated for the next daemon. The former migration treated an exact-looking root listing as ownership evidence and could run `pfctl -f /etc/pf.conf`, replacing unrelated PF state. Root listings cannot prove ownership, so legacy-signature detection is now read-only. A conflict disables only the owned launchd label, clears only the private anchor/token, reports the condition, and exits. Its terminal status survives the live-status TTL in both daemon CLI and tray readers. | Keep the source-level no-global-PF contract and long-lived sentinel restart checks; require the full packaged lifecycle gate before merge. |
| 2026-07-11 | Script-mode installed lifecycle | Disposable CI passed | The dev installer omitted `primes.py`, so a source-installed LaunchDaemon could crash-loop before reaching routing. Copy the complete local Python payload, remove status/TGWS runtime artifacts on uninstall, and qualify cold install, reinstall, active restart, uninstall, sentinel rules, and a long-lived sentinel PF state on a disposable runner only. | Keep this destructive lifecycle smoke restricted to disposable CI. |
| 2026-07-11 | Anchor-scoped `pfctl -F all` | Fixed; disposable privileged smoke passed | macOS documents `-F all` as including the shared state table. An anchor argument scopes rulesets, but it does not make a global state flush acceptable. Flush only `rules` and `nat` in `com.apple/slipstream`; forbid `all` and `states` in daemon recovery, tray recovery, tests, and operator docs. | Keep the disposable sentinel smoke as a required CI gate; extend release qualification to installed restart/uninstall. |
| 2026-07-11 | OpenAI/Codex reconnect incident | Geph-up guard retained; PF dependency superseded 2026-07-19 | Cold-start Geph hysteresis reported `up` after a failed first probe while `_geph_port` was still `None`; PF had already captured all TCP/443, so `chatgpt.com`, `chat.openai.com`, and `ws.chatgpt.com` entered the geo-exit fail-close branch repeatedly. A verified port remains mandatory before reporting Geph `up`, but local PF arm no longer depends on Geph. Runtime failure cools only the verified owned backend and tray polling still cannot restart a live process from endpoint failures. | Keep the regression fixtures and CI sentinel; require packaged clean install to activate local routing without a Geph listener. |
| 2026-07-11 | Geo-exit payload probe shadowing | Fixed in M1 integration | The general canary `_geph_payload_probe` silently overwrote the bounded auto-geo confirmation probe of the same name. Use `_auto_geph_payload_probe` for temporary route learning and keep the general probe for health canaries. | Keep the targeted source-level duplicate-definition guard. |
| 2026-07-10 | Unified runtime recovery reducer | Implemented | Normalize local, geo-exit, and unknown-host evidence as `ConnectionOutcome`; a pure reducer may invalidate only the relevant strategy, re-sweep an exact local host, restart only verified owned Geph, recheck, or warn about external state. | Move owned Geph lifecycle into a user LaunchAgent and expose a privacy-bounded action summary in `StatusV2`. |
| 2026-07-10 | Competing transparent PF interceptors | Fixed and live-verified | An active HTTPS `rdr`/`route-to` before `com.apple/*` receives real app traffic first. Detect nested anchors, pause without mutation, and auto-rearm when clear instead of trusting internal canaries. | Keep a two-interceptor integration fixture and surface the exact paused reason. |
| 2026-07-10 | Global PF ruleset ownership | Fixed and live-verified | Slipstream now loads only `com.apple/slipstream` below the existing `com.apple/*` anchor point; global reload/disable is forbidden during normal lifecycle and recovery. | Keep the privileged sentinel cycle in release qualification. |
| 2026-07-10 | PF reference ownership | Fixed and live-verified | Store the token returned by `pfctl -E` in a root-only runtime file and release it with `pfctl -X`; never infer that Slipstream owns global PF state. | Preserve restart/uninstall/reinstall coverage. |
| 2026-07-10 | Bundled Geph listener ownership | Fixed and live-verified | PID, exact executable, config path, and `:9954` listener must match the private ownership record; unknown listeners fail closed immediately. | Preserve the unknown-listener integration gate. |
| 2026-07-10 | External Geph coexistence | Fixed and live-verified | `:9909` is detected for diagnostics only and is never adopted or stopped without explicit port opt-in. | Preserve this constraint when Geph moves to a user LaunchAgent. |
| 2026-07-10 | Geph secret permissions | Fixed and live-verified | Config directory is `0700`; secret-bearing files and runtime ownership state are atomically written as `0600`, including migration of existing files. | Move the account secret to Keychain in a later hardening PR. |
| 2026-07-10 | PyInstaller spec working directory | Fixed in M0 | Resolve daemon, policy keys, and vendored Telegram proxy from `SPECPATH`; invoking PyInstaller from the repo root must not silently omit `proxy.*`. | Keep the path-stability assertion and frozen Telegram readiness smoke test. |
| 2026-07-18 | Codebase graph MCP transport | Workaround active; repeated during Wintun collector work | Fresh-clone indexing and the later project-list request both returned `Transport closed`; discovery used the audited source plus narrow searches rather than assuming the graph was current. | Repair or restart the MCP transport before relying on graph freshness; keep the documented narrow-search fallback. |
| 2026-07-08 | SonicDPI target identity | Reference only | Copy the principle of verified host/IP identity, not raw packet interception. | Use this when designing any future UDP/QUIC handling. |
| 2026-07-08 | Discord domain family | Partially adopted | Keep Discord on local bypass and cover the broad brand family. | Add only evidence-backed host expansions. |
| 2026-07-08 | Discord voice UDP | Future platform work | Full UDP handling needs packet-level filtering, not broad pf redirects. | Revisit under Network Extension or platform adapter work. |
| 2026-07-08 | SonicDPI adaptive probing | Partially adopted | Strategy health is scored from real endpoint outcomes, not exposed as a manual picker. | Observe real logs and tune score weights only from evidence. |
| 2026-07-08 | SonicDPI forged RST detection | Future platform work | TTL-baseline RST filtering is useful only with inbound packet visibility. | Revisit with Network Extension, WinDivert, or another packet adapter. |
| 2026-07-08 | SonicDPI passive DNS cache | Future platform work | DNS-observed IP binding is the right way to classify hidden-SNI/QUIC targets without global guesses. | Use for future packet adapters; add read-only DNS diagnostics first. |
| 2026-07-08 | SonicDPI MSS clamp | Future platform work | MSS clamp can help Cloudflare-fronted Discord mid-stream resets, but only with SYN visibility and tight target gating. | Revisit under packet adapters; never clamp broadly. |
| 2026-07-08 | SonicDPI macOS Network Extension | Future platform work | Full UDP/voice handling on macOS belongs in a System Extension path, not the current pf/TCP layer. | Keep routing core adapter-independent. |
| 2026-07-08 | Read-only DNS diagnostics | Implemented | Status now records active resolvers and cached sentinel resolution checks for null/private/poison-stub answers. | Keep it diagnostic-only; do not mutate DNS. |
| 2026-07-08 | Unblock-Pro connectivity probes | Adopted where safe | Use real Gateway WebSocket-style probing for Discord readiness. | Keep canaries autonomous and non-mutating. |
| 2026-07-08 | Unblock-Pro endpoint gates | Partially adopted | A route is healthy only when both UI shell and delivery endpoints work. | Keep expanding canary coverage by evidence-backed service class. |
| 2026-07-08 | Slipstream canary check details | Implemented | Group health must not let a passing sibling endpoint hide a failing gateway/CDN/video check. | Use `canaries.checks` in diagnostics; keep tray summary compact. |
| 2026-07-08 | Unblock-Pro Flowseal bundle policy | Backlog | Pinned upstream strategy bundles are useful only with checksums/signatures and regression fixtures. | Consider signed remote policy updates, not raw script sync. |
| 2026-07-08 | Unblock-Pro exclusion lists | Reference only | Broad bypass tools need negative lists to avoid breaking banks, games, and local services. | Use as a reminder for direct-passthrough tests; do not copy wholesale. |
| 2026-07-08 | Unblock-Pro GitHub mirrors | Backlog | App-owned downloads may try mirror URLs only with integrity validation. | Consider for updater/binary fetch reliability. |
| 2026-07-08 | Unblock-Pro DNS/hosts/proxy mutations | Rejected | Do not mutate `/etc/hosts`, system DNS, system proxy, PAC, or external VPN configuration. | Detect and warn only. |
| 2026-07-08 | Unblock-Pro global UDP block | Rejected | Do not block UDP/443 or Discord voice ranges globally. | Keep QUIC/UDP handling scoped to verified host/IP evidence. |
| 2026-07-08 | Install hygiene ideas | Adopted where safe | Safe-copy and binary-format validation are useful for daemon install reliability. | Keep monitoring real reinstall logs for locked-file edge cases. |
| 2026-07-08 | `xbox-dns.ru` external DNS | Active | User-managed resolver settings remain external state that Slipstream never enables or rewrites. Separately, the daemon may make a direct, verified DoH query for one failed generic hostname. | Keep the direct backend exact-host, local-only, and independent from system resolver settings. |
| 2026-07-09 | Darkware Zapret UI | Reference only | Borrow the compact MenuBarExtra-style status layout, not its manual strategy workflow. | Redesign tray diagnostics as short status rows with details behind a button. |
| 2026-07-09 | Darkware Zapret system mutations | Rejected | Do not copy system SOCKS proxy toggles or broad sudoers `NOPASSWD` service control. | Keep Slipstream-owned state scoped to its daemon, pf rules, and status files. |
| 2026-07-09 | Darkware Zapret bruteforce probe | Backlog | Headless re-sweep can borrow the temporary-proxy probing idea without exposing a picker. | Consider only for autonomous local-bypass recovery. |
| 2026-07-09 | Context Mode | Agent tooling | Installed for Codex session context hygiene; not a Slipstream runtime dependency. | Keep out of project code and docs except this research note. |
| 2026-07-09 | Superpowers | Agent tooling | Installed as a general Codex workflow aid; not a Slipstream runtime dependency. | Use opportunistically after session reload exposes its skills. |
| 2026-07-12 | Graphify | Agent tooling | Audited and installed as a local AST graph CLI. Use its explicit user-local binary for scoped symbol explanations; do not run its Codex installer because it appends a broad `PreToolUse` hook to `AGENTS.md`/`.codex/hooks.json`. Existing codebase-memory MCP remains the primary code-discovery tool. | Reuse only for exact-symbol graphs when it adds signal; do not make it a runtime dependency or mutate repository agent hooks. |
| 2026-07-09 | ECC | Not installed | Current Codex plugin path is broad and upstream-doc-fragile for this repo. | Revisit only for a focused workflow need. |
| 2026-07-09 | Ruflo | Not installed | Too much global agent harness behavior for current Slipstream work. | Mine health-check and ADR ideas only. |
| 2026-07-09 | Steam Store web | Adopted narrowly | Route Steam Store web hosts through geo-exit; keep Steam CM/game/download paths out until separately proven. | Watch real Steam logs before widening host coverage. |
| 2026-07-09 | Runtime local-bypass recheck | Implemented | Full local-bypass runtime strategy failure clears only that route group's strategy cache and force-schedules canary recheck. | Keep observing real failures before changing thresholds. |
| 2026-07-09 | Explicit route policy tables | Implemented | Static direct, local-bypass, geo-exit, and attempt-limit policy now lives in inspectable tables instead of a hand-written route-policy branch chain. | Use this shape for signed policy updates and OS adapters. |
| 2026-07-09 | Policy metadata in diagnostics | Implemented | Daemon status and copied diagnostics expose bundled policy version, source, hash, domain counts, and attempt limits. | Use this as the base for signed remote policy verification. |
| 2026-07-09 | Signed policy bundle validator | Implemented | Future policy bundles must pass manifest validation and Ed25519 signature verification; Discord/YouTube are protected from geo-exit policy. | Add remote fetch/apply only after key management and rollback rules are explicit. |
| 2026-07-09 | Policy apply path | Implemented | A verified manifest can be activated in memory and reflected in route lookup/status; default runtime remains bundled until explicit apply. | Add persistence/rollback before any remote fetch is enabled. |
| 2026-07-09 | Policy persistence and rollback | Implemented | Verified policy bundles can be saved under Slipstream-owned state, loaded on daemon start, and rolled back to the previous bundle or bundled policy. | Add remote fetch only after signing keys and post-apply health gates are explicit. |
| 2026-07-09 | Remote policy health gate | Implemented | Remote policy helper is disabled by default, requires HTTPS, trusted Ed25519 keys, and a passing health gate before persisting an update. | Add a scheduler only after cadence, backoff, and production key distribution are explicit. |
| 2026-07-09 | Remote policy scheduler | Implemented | Remote policy fetch is explicit opt-in via `SLIP_ROUTE_POLICY_URL`, uses retry backoff, skips while canaries run, and only persists after the health gate passes. | Define production signing-key distribution and release-channel hosting before enabling for users. |
| 2026-07-09 | Signed policy release tooling | Implemented | `scripts/make_route_policy_bundle.py` generates Ed25519 keypairs, builds and verifies signed policy bundles, signs the bundled manifest directly, writes trusted public-key maps, and includes verifier-checked hashes. | Create real production keys outside git and host the release channel before user enablement. |
| 2026-07-09 | Bundled policy key distribution | Implemented | The daemon loads trusted policy keys from embedded constants, an optional bundled `route-policy-keys.json`, and a root-owned state override; PyInstaller includes the bundled key map only when release tooling provides it. | Generate and protect real production keys outside git before hosting policies. |
| 2026-07-09 | Remote policy channel index | Implemented | `SLIP_ROUTE_POLICY_URL` may point to a stable HTTPS channel index with bundle URL and sha256; the daemon verifies the bundle digest before signature and health-gate checks. | Host this only after real production keys and rollback notes exist. |
| 2026-07-09 | Release policy channel packaging | Implemented | `build-app.yml` now requires production policy key secrets, embeds the public key map in the daemon bundle, signs the bundled policy, verifies it, and publishes `route-policy.json` plus `route-policy-latest.json` release assets. | Configure the real GitHub secrets and publish a release before user enablement. |
| 2026-07-09 | Release artifact preflight | Implemented | `scripts/verify_release_artifacts.py` checks the release dir before publishing: updater appcast URL/signature, signed route-policy bundle, trusted keys, channel URL, and channel hash must agree. | Keep adding release artifact checks when new published files become update-critical. |
| 2026-07-09 | Discord CDN throughput canary | Implemented | Discord CDN local-bypass canary now uses a scoped GET payload threshold, while warning before degrading and leaving YouTube/QUIC/global UDP untouched. | Add throughput thresholds only for endpoints with predictable small payloads. |
| 2026-07-09 | Geo-exit endpoint gates | Implemented | Repeated failure of important secondary geo-exit endpoints, such as OpenAI billing, can degrade the group after a grace threshold instead of being hidden by a passing core endpoint. | Keep adding endpoint gates only where user-visible workflows are proven to fail independently. |
| 2026-07-09 | GitHub developer endpoints | Implemented | GitHub HTTPS/Git endpoints are direct-passthrough and plain-only; generic desync can break longer smart-HTTP transfers even when short API calls succeed. | Use direct-passthrough for similar developer/download endpoints only with evidence, not as a broad allowlist. |
| 2026-07-09 | Steam Store payload canary | Implemented | Steam Store geo-exit health now requires a real HTTPS GET payload through Geph, not just SOCKS CONNECT or TLS first bytes. | Add payload probes for other geo-exit flows only when TLS success can hide a user-visible stalled page. |
| 2026-07-09 | Lid-close wake recovery | Revised 2026-07-11 | Adrafinil keeps idle sleep away but does not prevent macOS lid-close SleepService/DarkWake cycles. Repeated post-wake failures remain diagnostic evidence; tray polling must not restart a live Geph process because it can tear down streaming sessions. | Move lifecycle ownership into the daemon before adding coordinated restart of a live backend. |
| 2026-07-09 | Stale proxy exceptions | Implemented | External proxy tools can leave disabled `ExceptionsList` entries after proxy autoconfigure is turned off; Slipstream reports them in status without treating the proxy as active or mutating settings. | Use diagnostics to explain stale browser/network behavior; do not auto-delete user-owned proxy state. |
| 2026-07-09 | Runtime re-arm visibility | Implemented | Daemon status now records the last wake/network re-arm reason, interface, gap, count, and age so sleep-related recovery is visible without reading logs first. | Keep using logs for full `pmset` correlation; status is a compact runtime snapshot. |
| 2026-07-10 | Auto geo-exit stale learned hosts | Superseded 2026-07-13 | The old runtime reset avoided some bad learned routes, but the learning premise was still unsound: a working Geph payload does not prove geo-restriction. | Unknown hosts no longer learn Geo-exit; retain only exact local recovery. |
| 2026-07-10 | Wake canary recovery rerun | Implemented | Forced canary triggers that arrive during an in-flight wake check are queued for a short rerun instead of being dropped by the force cooldown. | Keep wake recovery event-driven; do not lengthen normal canary cadence. |
| 2026-07-10 | Exact-host local-bypass re-sweep | Implemented | A real Discord/YouTube runtime miss starts a deduplicated background strategy sweep for that exact host and clears its negative cache only after a fake/desync strategy succeeds. | Tune cooldowns only from observed runtime evidence. |
| 2026-07-10 | Geph-down log semantics | Superseded 2026-07-11 | A proxied geo-exit attempt still never falls through local desync, but persistent fail-close under an active global redirect was unsafe. Backend loss now pauses only the private PF anchor and leaves native networking in control. | Keep runtime messages aligned with dormant/active PF state. |

## Automatic Local Browser Signal (2026-08-12)

The installed-product requirement is `install Slipstream -> sites work`,
including rendered regional denial, incomplete top-level responses, and a
pre-document navigation that remains pending after valid TLS records. Manual
Developer Mode, a separate extension install, a publisher account, and a cloud
browser are not acceptable production prerequisites. The normal transport path
must remain browser-free; a heavier worker may run only behind bounded concrete
failure evidence.

Official Chrome distribution boundaries:

- Chrome documents only Chrome Web Store distribution or self-hosting in a
  managed environment. Windows and macOS allow self-hosted extensions only
  through enterprise policy:
  <https://developer.chrome.com/docs/extensions/how-to/distribute>.
- The macOS external-extension preference file may associate an installed app
  with an extension, but its update URL must point to the Chrome Web Store and
  the user must still enable the extension. Local CRX installation on macOS has
  been rejected since Chrome 44:
  <https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions>.
- `ExtensionInstallForcelist` installs silently, but an extension outside the
  store is admitted on macOS only when Chrome is managed by MDM, joined through
  MCX/domain management, or enrolled in Chrome Enterprise Core:
  <https://chromeenterprise.google/policies/extension-install-forcelist/>.
- Unified Headless Chrome uses the normal Chrome implementation and supports
  extensions during automation. It is a valid local qualification candidate,
  not automatic authority over a separate user tab:
  <https://developer.chrome.com/docs/chromium/headless> and
  <https://developer.chrome.com/blog/tools-from-chrome-for-frictionless-testing>.

Adjacent browser projects do not remove that ownership boundary. Crawlee is a
crawling framework with queues, sessions, proxy rotation, and Playwright or
Puppeteer integration (<https://github.com/apify/crawlee>).
`microlinkhq/browserless` is a Puppeteer wrapper around isolated headless
contexts (<https://github.com/microlinkhq/browserless>). CloakBrowser supplies a
separately downloaded fingerprint-modified Chromium binary aimed at anti-bot
automation (<https://github.com/CloakHQ/CloakBrowser>).
`puppeteer-real-browser` targets anti-bot/headful automation and its README says
it no longer receives updates
(<https://github.com/ZFC-Digital/puppeteer-real-browser>). None observes or
reloads an already-running user tab merely by being launched locally.

PR #324 implements the immediate experiment without runtime composition. The
ordinary macOS Chrome for Testing gate now launches the exact-origin companion
through LaunchServices in unified-headless mode, keeps the Chrome sandbox and
avoids a visible browser window, uses an owner-private fresh profile, and
requires the existing native-message and styled-resource callbacks. It records
launch-to-worker latency,
launch-to-semantic latency, and sampled aggregate RSS for the exact owned Chrome
process family. The fail-closed budgets are 15 seconds, 25 seconds, and 768 MiB
of de-duplicated physical footprint. Aggregate RSS remains diagnostic because
shared mappings appear in each process's RSS. Local unit and daemon suites
pass; successful real-browser evidence is recorded below.

The first two CI attempts (`31532156159` job `93914552229` and `31532531700`
job `93915774541`) also established a macOS constraint: direct binary launch
both outside and nominally inside the Aqua session starts the parent process,
but sandboxed helpers cannot look up Chrome's per-process Mach rendezvous
service (`bootstrap_look_up ... Permission denied`). The worker therefore
remains absent. The harness now uses LaunchServices for the macOS application
bootstrap context while still passing `--headless`; this keeps the sandbox and
does not create a visible browser window. The later successful run below
validates that boundary.

The third attempt (`31532847620`, job `93916800053`) passed the actual browser
path: extension worker readiness, native messaging, the real incomplete-frame
`webRequest` event, one reload, and styled-page completion. The sole failure was
the initial memory metric: summing per-process RSS produced 1,142,496 KiB and
crossed the 768 MiB budget, but that sum counts shared mappings once per Chrome
process. The corrected measurement uses Apple's multi-process `footprint`
total, which de-duplicates shared objects, and keeps the RSS sum only as a
diagnostic. The 768 MiB gate is unchanged and now applies to physical
footprint.

Run `31533358388`, job `93918488548`, passed on Chrome for Testing 151 with the
corrected metric. Worker readiness was 5,476 ms, the real incomplete-frame
event crossed the native boundary, one reload completed the styled page in
6,495 ms, and the de-duplicated physical footprint was 374,369 KiB against the
786,432 KiB budget. Aggregate RSS was 1,234,672 KiB across four samples,
confirming why it remains diagnostic rather than the physical-memory gate.
System network state was not mutated.

Two PR #328 jobs later resolved `stable` to Chrome for Testing
`151.0.7922.138` rather than the proven `151.0.7922.77`. Both unchanged legacy
extension runs failed because the exact MV3 service-worker target never became
available; setup and LaunchServices completed, and the final DevTools retry
reported connection refusal. This is upstream browser drift, not evidence
against the new worker: the legacy job does not build or invoke the new Rust
observer. The extension/webRequest contract is therefore pinned to the exact
proven `.77` version for reproducibility.

The new observer then exposed a separate `.138` macOS packaging failure. PR
runs `31545667200` and `31546818641` both copied the setup action's complete
extensionless bundle into a real private `.app`, but LaunchServices exited
without creating any exact profile-owned Chrome process. Downloading the same
official arm64 archive locally reproduced the failure: both the source and
private copy lack `_CodeSignature/CodeResources`, and
`codesign --verify --deep --strict` reports `code has no resources but signature
indicates they must be present`. Ad-hoc deep signing made LaunchServices create
a process but the DevTools listener disappeared before the bounded client could
use it. That workaround would also replace the production signing authority,
so it is rejected. The official
[GitHub macOS image manifest](https://github.com/actions/runner-images/blob/main/images/macos/macos-15-Readme.md#browsers)
already lists installed Google Chrome. Run `31547878092` temporarily omitted
the executable override and let the worker discover and verify that installed
browser through the exact production bundle/team boundary. The run
created the exact profile-owned main process through that boundary, but the
browser remained silent and did not publish `DevToolsActivePort` within the
fixed ten-second startup budget. The same path passed twice locally on signed
Google Chrome 151 in 10,797 and 15,785 ms end to end, including the eight-second
observation and cleanup. Hosted CI therefore pins the packaged observer to the
already-proven `.77` Chrome-for-Testing bundle as well; production
current-Chrome compatibility is evidenced by the exact local signed-browser
runs rather than by relaxing the hosted startup or accepting an ad-hoc
signature.

Pinned packaged run `31549041776` then completed the hidden worker, exact
hanging request, result submission, and launcher cleanup. The only failure was
the harness's final residue query: its broad
`slipstream-browser-probe-*` glob also selected the harness's own live
`slipstream-browser-probe-smoke-*` temporary root. The production worker profile
has an exact 32-character lowercase-hex nonce. The residue gate now matches
only that shape, with focused exclusions for the smoke root, non-hex suffixes,
and wrong lengths; no cleanup behavior or product path changed.

The correction passed on exact head
`c9720bb58482ce37ded2dc37f3d8fea0cc39bb10`. Run `31549452164`, packaged job
`93968755542`, produced exactly one hanging main-document request and one
`navigation_pending` result in 13,009 ms. The sandbox remained enabled, no
window was visible, the worker profile and exact Chrome family were absent
after cleanup, and later packaged lifecycle stages passed. The same run passed
common job `93968755462`, Windows-adapter job `93968755558`, and pinned legacy
Chromium job `93968755604`; audit run `31549452162` passed dependency job
`93968755330` and vendored-Geph job `93968755382`. This closes the isolated
observer qualification, not the remaining daemon composition and original
navigation-completion gate.

Code discovery for the following correlation slice attempted the repository's
required knowledge-graph search first, but the MCP transport returned
`Transport closed`. The fallback was therefore limited to exact v3 signal,
active-relay, and native-message symbols. That inspection confirms the existing
browser extension correlates only a tab it owns: `onBeforeRequest` records its
request start, `chrome.tabs.get` proves the same tab still has the same pending
host, and the daemon matches that timestamp to one live relay. A separate
headless probe cannot reuse that authority merely by loading the same host; the
next design must use an owned daemon-issued probe identity tied to the original
relay, or choose a local browser surface that actually owns the original
navigation. Expanding the existing semantic signal with an unbound hostname is
not acceptable.

The following closed fixture must prove that the worker's evidence can be
correlated to one original pending relay and that the original navigation
completes. A synthetic worker page by itself cannot authorize production
routing. Installed package size, update/uninstall behavior, idle cost, and
clean-profile behavior remain separate product gates.

Branch `codex/owned-browser-probe-correlation` now implements that closed
daemon-side seam without composing a runtime worker and freezes its job/result
shape in `contracts/pending-navigation-probe-v1.json`. The daemon mints a
random 128-bit capability only for an already-live relay that independently
satisfies the existing public unknown-host, eight-second idle, low-byte,
complete TLS record, and policy exclusions. The capability retains the exact
relay object, host, browser-request start, and local recovery stage; it is
process-local,
one-shot, capped at 32 entries, expires after 30 seconds, and is revoked when
the relay closes. Its result must report the same host/start after a separate
eight-second `navigation_pending` observation. A valid capability is consumed
even if wrong-host, early, expired, rebound, or otherwise invalid, and replay is
inert. Acceptance calls the existing local-stage reducer on the bound relay,
never another same-host lookup. The async fixture starts two same-host relays
with the same request timestamp and proves only the capability owner exits;
the second remains open. Focused relay and traffic verification covers 556
tests; the complete daemon suite passes 854, script tests pass 278, and the
unchanged Chromium companion passes 24. The next boundary is owner-only
job/result IPC plus a lazy worker that cannot recursively create its own probe
jobs; neither is runtime-composed yet.

PR #326 adds the next closed boundary as a
dedicated owner-only local protocol, not an extension/native-message variant.
The contract freezes `/var/run/slipstream-browser-probe.sock`, console-user
mode `0600`, exact versioned `claim` and `submit` envelopes, and a 2 KiB request
cap. The current fixture uses a temporary path and proves ownership plus exact
socket removal, so no production socket is created. The broker copies only the
existing privacy-bounded job, retains at most 32 entries, rejects stale or
future issue times, derives one monotonic expiry, leases a claim for five
seconds, and redelivers it after worker loss only while the original 30-second
capability remains live. Submit removes the queue copy and calls the existing
capability reducer; it has no independent relay-selection authority. The full
daemon suite passes 861 tests. The module is present in the script install
payload for reproducibility, but no socket supervisor, poller, browser process,
or routing effect is composed. Script tests pass 278 and the unchanged
Chromium companion passes 24. Python compilation, JSON parsing, project
continuity, and `git diff --check` also pass. PR #326 merged as
`2f37488d3c55f3ca29a622f6cc00455267ce1028`; exact-main CI `31538670468`,
dependency audit `31538670392`, and Windows qualification `31538670429`
passed for that SHA. Lazy lifecycle and a proof that worker traffic cannot
recursively create probe jobs remain the next gate.

PR #327 from branch `codex/lazy-pending-navigation-worker` adds that
closed lifecycle seam without pretending that a browser is already composed.
A one-shot client checks the exact owner UID and mode `0600` before connecting,
applies the same 2 KiB frame limit in both directions, rejects duplicate or
expanded responses,
and exposes only claim and submit. The lazy controller creates no thread until
the broker has a live job, admits only one blocking worker, stops as soon as the
queue is empty, and retries a vanished worker only after the existing
five-second lease. Host-level exclusion in the daemon now refuses a second
capability while any capability for that normalized host is live. A worker's
synthetic same-host relay therefore cannot recursively create another job; the
host becomes eligible again only after the original capability is revoked or
consumed and the worker relay has closed. Focused coverage passes 16 tests and
the complete daemon suite passes 866. No production socket, browser, process
launcher, PF rule, DNS setting, proxy, PAC, VPN, or route effect is added by
this seam. The next gate is the real sandboxed observer plus exact console-user
launch/cleanup, followed by proof that its result completes the original
navigation.

All six PR checks passed. PR #327 merged as
`86966e9e93b6344c13c5704f311e5468be17a35c`; exact-main CI `31541339436`,
dependency audit `31541339377`, and Windows qualification `31541339387`
passed for that exact SHA.

Branch `codex/sandboxed-browser-probe-worker` implements the next closed slice
without creating the production socket or wiring the daemon lifecycle. The
existing packaged Slipstream executable has one exact hidden worker argument,
so no second executable, embedded browser engine, Chrome extension, publisher
account, or user-profile setup is needed. The root-side launcher prepares one
random owner-private plist and log directory, bootstraps the packaged worker in
the active console user's Aqua domain, verifies its exact UID and command, and
removes only that verified job and runtime after exit. The worker itself asks
LaunchServices to open installed Chrome in sandboxed unified-headless mode with
extensions disabled and a fresh mode-`0700` profile. It retains no ordinary
idle process or thread. The production Chrome bundle is admitted only from the
fixed system or user Applications path, under the current user or root, without
world-write permission, after code-signature verification and exact Google
bundle/team identity. The installed workstation copy uses ordinary `0775`
owner/admin permissions, so rejecting every group-writable bit would reject a
valid signed Chrome; signature identity plus the world-write prohibition is the
compatible boundary.

The worker uses the local Chrome DevTools Protocol only for the exact synthetic
`https://host/` main document. `Network.requestWillBeSent` starts the separate
eight-second observation; response headers, redirect, load failure, or
navigation error are terminal, while an exact document request that remains
outstanding for the full interval is `navigation_pending`. A terminal
observation consumes its one-shot capability through the broker but is rejected
by the route reducer and therefore has no route effect. The worker closes the
browser, revalidates and removes only the exact profile-owned Chrome family and
LaunchServices waiter, waits for stable absence, and removes the profile before
submitting either outcome. Production paths are fixed. Executable, socket,
origin, resolver, and certificate overrides require the complete disposable
GitHub Actions gate. The packaged hosted gate materializes only the pinned
complete `.77` Chrome-for-Testing root into its private `.app`; production never
adapts an extensionless bundle and retains exact installed-Google signature,
bundle-ID, and Team-ID admission. The deterministic local HTTPS origin, socket,
resolver, and certificate remain disposable overrides. That gate requires one
hanging
main-document request, one
privacy-bounded pending result, no `--no-sandbox`, no visible window, no profile
residue, and at most 25 seconds end to end.

PR #328 merged the isolated observer as
`aa6288da945a2551be4203fbda2965907b285ad2`; exact-main CI, audit, and Windows
qualification passed. PR #329 then merged production composition as
`a2312a54949102be5a5fc2abb4a341078f591b55`; its exact-main CI
`31553860792`, audit `31553860796`, and Windows qualification `31553860798`
passed. The daemon starts the owner-only socket supervisor, queues a job
directly from the existing complete-record idle observer, wakes the single lazy
worker, and performs exact stale worker cleanup during startup and uninstall.
The ordinary path retains no browser or worker thread. A deterministic
relay-to-job-to-result fixture proves only the bound live relay advances.

A separate local signed branded-Chrome HTTPS diagnostic provided the missing
retry compatibility observation: the first top-level request remained open for
8.2 seconds and closed without an HTTP response; the original Chrome page then
issued a second request to the same URL and loaded its CSS, JavaScript, image,
and ready callback without an extension or reload command. The ordinary pinned
Chromium job now freezes that behavior with an extension-free scenario. This
does not by itself qualify installation, update, exact packaged uninstall,
idle cost, or the complete composed original-navigation transaction; those
remain release gates until their matching evidence passes.

Branch `codex/qualify-composed-original-navigation` adds the first complete
installed-package transaction to the ordinary packaged lifecycle job. A fresh
extension-free Chrome process resolves one `.invalid` fixture hostname to a
globally routable numeric identity so the real PF and public unknown-host relay
gates remain active. Only under exact `CI=true`, `GITHUB_ACTIONS=true`, and
`SLIPSTREAM_DISPOSABLE_CI=1` markers may the connector map that one configured
hostname/IP/443 tuple to a loopback TLS server. Missing markers, a noncanonical
port, a non-global or mismatched IP, a protected/static host, or any other
destination uses the unchanged production endpoint. The daemon-only mapping
is not included in the worker LaunchAgent environment; the launcher continues
to forward only its frozen browser override allowlist.

The shared fixture requires the request order `original -> worker -> original`.
The first original TLS navigation remains live for the daemon's eight-second
complete-record idle gate. The packaged hidden worker then keeps its own main
document pending for another eight seconds and submits the existing bounded
capability. Only then may the daemon advance and close the original relay;
Chrome itself must repeat the unchanged original URL and fetch exactly one CSS,
JavaScript, image, and ready resource. No extension or reload command exists in
the scenario. Before the first request, a three-second installed idle sample
requires the production broker to be owned by the console user with mode
`0600`, the worker runtime to be empty, worker processes and profiles to be
absent, and daemon CPU growth to remain at most one second.

PR #330 merged as exact live main
`9b500a40af3f8ddbc8dff7301b88aca82a7b3484`. Exact-main packaged job
`94001999674` observed the worker root at 16,637 ms and the automatic original
retry at 28,933 ms on the fixture clock, followed by exactly one CSS,
JavaScript, image, and ready callback; the separately measured captured Chrome
transaction completed in 25,003 ms without an extension or manual reload and
left no worker residue. The prior three-second idle sample had zero worker
processes/profiles, an empty worker runtime, a mode-`0600` broker, and 490 ms
daemon CPU growth. The lifecycle preserved its sentinel connection and PF
state, left global PF unchanged, and uninstalled cleanly. Exact-main common,
Chromium, Windows adapter, dependency, Geph-vendor, AMD64 Wintun, and ARM64
Wintun jobs also passed.

The failed attempts exposed a real packaging defect rather than a browser or
relay failure: the daemon's default worker path assumed
`/Applications/Slipstream.app`, while the lifecycle correctly installed the
frozen daemon from the exact built app bundle. The frozen installer now derives
only the sibling `Contents/MacOS/slipstream`, rejects an absent, symlinked,
non-executable, or group/world-writable worker, XML-escapes the path, and pins
it into the root-owned LaunchDaemon environment. Normal routing remains usable
if that optional worker later disappears; the private log records only the
bounded worker failure class.

Branch `codex/qualify-active-worker-uninstall` adds the remaining installed
ownership transaction. A fresh exact fixture keeps the original Chrome request
and correlated worker request pending. Before uninstall the gate requires one
matching live Aqua LaunchAgent PID, packaged worker process, private Chrome
profile, and owner-private runtime directory. The first packaged attempt proved
that a hosted console user's live profile is not reliably rooted in `/tmp`.
The corrected gate derives the one exact random `--user-data-dir` only from a
matching non-root Chrome process, requires its owner and mode `0700`, saves that
path before uninstall, and requires it to disappear afterward. It then invokes the normal
installed uninstall and requires the LaunchDaemon, broker, installed payload,
worker LaunchAgent/process/profile/runtime, and the fixture-owned original
Chrome capture all to be absent or stopped. Sentinel connection/state and the
global PF snapshot remain mandatory invariants. This adds no production code
path or normal idle work. Local verification passes 1,185 Python tests plus 54
subtests; the real packaged active-worker transaction remains open.

The next packaged attempt reached the exact active worker and invoked the
normal installed uninstaller, which failed closed before removing the owned
worker. The separate uninstaller inherited the three disposable markers but
not the daemon's complete fixture override set, while stale cleanup correctly
required an exact plist environment. The correction preserves exact matching
in production. Only under all three exact disposable markers may stale cleanup
accept persisted additional values, and then only for the frozen worker
allowlist with the original nonempty, 1024-byte, and NUL constraints. This is
needed to remove the already-owned CI LaunchAgent; it cannot admit a new key,
expand production cleanup ownership, or affect routing.

The following packaged attempt confirmed that the separate CLI uninstaller
also lacks the LaunchDaemon-only worker executable pin. Cleanup now recovers
that exact string only from the still-present root-owned, nonsymlinked,
mode-`0644`, size-bounded LaunchDaemon plist after validating its label,
installed daemon command and port, installed working directory, and canonical
`Contents/MacOS/slipstream` shape. It still validates the active worker's exact
UID, command, random label, plist, and owner-private files before signalling
the LaunchAgent. An absent, mutable, malformed, or mismatched LaunchDaemon
remains a fail-closed uninstall instead of broad process cleanup.

That correction let the next packaged transaction remove every installed and
LaunchAgent/runtime artifact, but the gate still found the exact saved Chrome
profile. The worker's Rust cleanup was never reached because launchd's
`SIGTERM` used the default process termination before `ChromeSession::cleanup`.
The hidden worker now converts only `SIGTERM` into a flag, checks it after each
bounded 250 ms DevTools read, and then runs the same exact-profile process
validation, TERM/KILL sequence, settled-absence check, and private profile
deletion already used on normal completion. Stale cleanup waits no more than
eight seconds for the validated worker PID to exit, requires its private stderr
to contain only the bounded `worker_terminated` class, and only then performs
`bootout`; failure does not authorize a broader Chrome scan or cleanup.

PR-head packaged job `94013960155` on
`ef1d465a97e176f208179336c8e6249cdedbc3fd` passed this boundary. Before
uninstall it proved exactly one worker process, exact live profile, private
runtime directory, and loaded matching LaunchAgent with root channels
`original -> worker`. The normal installed uninstaller then left worker cleanup
and the original Chrome capture clean, installed state absent, the lifecycle
sentinel connection/state preserved, global PF unchanged, and final uninstall
clean. The same run retained the normal idle boundary: zero worker processes or
profiles, a mode-`0600` broker, and 590 ms daemon CPU during three seconds.

PR #331 merged as exact qualified product-code main
`aa10f16409ab8775647749517f79faea7b066926`. Exact-main packaged job
`94017024721` repeated the complete active-worker uninstall: one worker,
profile, runtime, and loaded LaunchAgent before uninstall; clean worker and
original-capture cleanup plus absent installed state afterward; preserved
sentinel connection/state and unchanged global PF. Its idle sample retained
zero workers/profiles, mode-`0600` broker, and 400 ms daemon CPU over three
seconds. Exact-main common, Chromium, Windows adapter, dependency audit, Geph
vendor, AMD64 Wintun, and ARM64 Wintun jobs also passed.

## Adjacent Routing Projects Audit (2026-08-02)

This audit read implementation code at the commits below rather than treating
project READMEs as proof. The comparison is against Slipstream's current
ownership, exact-host, fail-closed, external-state, and route-class invariants.
It did not install software, import endpoints, open listeners, or change the
workstation.

| Project | Reviewed commit | Code-backed finding | Slipstream decision |
|---|---|---|---|
| [`celzero/rethink-app`](https://github.com/celzero/rethink-app) | `d9140d3cbe09` | Android network callbacks become explicit added/lost/capability/link-property events; policy separates restart preference, validation monitoring, bounded delays, and deterministic active/unmetered/metered ordering. | M4 architecture reference for the Android adapter. Copy the event/reducer contract, not the full VPN implementation. |
| [`xvzc/spoofdpi`](https://github.com/xvzc/spoofdpi) | `90441f46c36b` | TLS desync has typed SNI/random/chunk/first-byte/custom segment plans; optional fake sends use observed remote TTL and ordinary segmentation can continue when the fake send fails. | Near-term reference for typed, testable local-strategy plans. TTL-derived packet work is M5-only and requires real packet evidence. Never adopt broad system proxy, TUN, or DNS mutation. |
| [`enfein/mieru`](https://github.com/enfein/mieru) | `83dc9e2d7429` | The protocol exposes lifecycle state, multiplex scheduling, pending counts, disable/idle state, bounded padding, and broad tests. | M5 reference for bounded scheduling, backpressure, session reuse, and owner cleanup. GPL-3.0 code is reference-only and Mieru is not a route-classification dependency. |
| [`F0rc3Run/F0rc3Run`](https://github.com/F0rc3Run/F0rc3Run) | `b5476c829339` | The tree is generated proxy/config/stat data with no source generator, validation workflow, or tests in the reviewed commit. | Reject as a runtime source. Mutable public endpoints and secrets have no acceptable provenance; at most use sanitized data as offline parser fixtures. |
| [`therealaleph/MasterHttpRelayVPN-RUST`](https://github.com/therealaleph/MasterHttpRelayVPN-RUST) | `b37f7beb4e44` | Relay retry distinguishes definitely-unsent from maybe-sent requests, fans out only replay-safe methods, serializes non-idempotent requests, and stops retries on confirmed quota evidence. Framed HTTP readers reject premature EOF. | Near-term reference for request replay classification and pre-send/post-send evidence. Reject its Apps Script/VPS relay backend and never extend close-delimited HTTP EOF rules to WebSocket or streaming responses. |
| [`belotserkovtsev/Ladon`](https://github.com/belotserkovtsev/Ladon) | `8af5e68cadea` | Diagnostics separate TCP, TLS, and HTTP stages, compare TLS 1.3/1.2, retain DNS-observed endpoints, distinguish HTTP 451, and consult a clean vantage only after local failure. Its reducer preserves a local blocked verdict when the remote vantage is unavailable. | Near-term diagnostic classifier, but remote comparison is never route authority. Remote failure or absence must remain unknown and cannot authorize Geph; eTLD+1 aggregation is diagnostic-only. |
| [`litvinovtd/qeli`](https://github.com/litvinovtd/qeli) | `fd8d402f4b39` | Route setup is re-read after mutation, incomplete composite routes fail closed, and prewarmed Wintun ownership is disposed if transfer never completes. | M4 reference for Windows transactional ownership and complete-or-fail route state. AGPL-3.0 code is reference-only; host-wide full-tunnel mutation is outside Slipstream's boundary. |
| [`cheburnetik/AutoConnector_for_Telegram`](https://github.com/cheburnetik/AutoConnector_for_Telegram) | `72fa0ee8c022` | The project grades a check fully healthy after opening the proxy, performing Obfuscated2 with the proxy secret and Telegram DC, sending `req_pq_multi`, and receiving `resPQ`; its FakeTLS persistence grade is weaker and the project has no detected tests. | `resPQ` is stronger protocol-aware liveness than TCP connect but is not authenticated Telegram reachability. A production canary must select a known Telegram RSA fingerprint and continue far enough to prove possession of its private key. Do not import public proxy feeds; Telegram remains separate from Geph. |
| [`MustafaBaqer/VestraNet-Nodes`](https://github.com/MustafaBaqer/VestraNet-Nodes) | `2da9786c8f64` | The reviewed tree contains subscription/protocol lists and translated documentation, but no source generator, validation workflow, or tests. | Reject as a runtime source for the same provenance, privacy, and revocation reasons as F0rc3Run. |
| [`refraction-networking/uquic`](https://github.com/refraction-networking/uquic) | `bea508ff0d81` | The quic-go fork exposes transport-parameter ordering and suppression with tests; one shuffle path uses global `math/rand`, so output is not independently stable unless the caller controls global state. | M5-only reference for scoped QUIC fingerprint experiments. Any implementation must be deterministic, target-specific, DNS-observed, and backed by a packet adapter; never block or rewrite UDP/443 globally. |
| [`Scratch-net/telego`](https://github.com/Scratch-net/telego) | `83fe8faf8bb8` | The Telegram probe performs a direct/SOCKS connection and a 64-byte garbage handshake, but accepts success after the read closes or times out and avoids IPv6 through SOCKS. | Retain the lesson that TCP connect is insufficient and avoid impossible address-family claims; reject its false-positive success rule. Prefer the MTProto-aware probe and authenticated continuation above. |
| [`yanisplugg/olcvpn-client`](https://github.com/yanisplugg/olcvpn-client) | `c2693462741d` | Its transport layer records immutable pong/missed-pong/reconnect snapshots, detects control staleness, reacts to wake/network events, and verifies real Telegram reachability before caching an endpoint. | M5 reference for application/control-plane health feedback and event-triggered retry. Do not vendor the large GPL/multi-license monorepo or its bundled transports. |
| [`tiredvpn/tiredvpn`](https://github.com/tiredvpn/tiredvpn) | `50a74a80ad23` | Connection management separates network-down from strategy failure, reuses an active multiplexer, skips expensive preflight on hot reconnect, and implements sliding-window/half-open circuit recovery. | Later refinement for existing scoped circuits and backend reuse. AGPL-3.0 code is reference-only; do not copy its full-VPN or broad strategy ladder. |
| [`kian-irani/mhrv-setup-full-tunell`](https://github.com/kian-irani/mhrv-setup-full-tunell) | `b59c1f26b1e3` | The installer runs mutable remote shell as root, resets UFW, pulls tag-only images, replaces containers, and prints an authentication secret; update rollback is image-name based. | Reject implementation and supply-chain model. Only the human-readable setup/rollback presentation is useful. Slipstream must pin provenance, preserve external firewall state, and never log secrets. |
| [`Bes-js/MacDPI`](https://github.com/Bes-js/MacDPI) | `3dedf72af3d0` | The SwiftUI wrapper installs SpoofDPI through Homebrew, starts it with system-proxy and DoH flags, infers success from command output, and has no detected tests. | UI/process-state reference only. Reject runtime Homebrew, shell-string control, output-text success parsing, and system proxy/DNS ownership. |

### Near-term contracts

1. Add a diagnostic-only clean-vantage result type derived from Ladon's staged
   probing. It may explain likely local DPI versus origin/WAF/rate-limit/geo
   denial, but it cannot choose a route or fill missing local evidence.
2. Replace Telegram's socket-level readiness with a bounded Obfuscated2
   `req_pq_multi`/`resPQ` protocol-liveness stage through the exact owned proxy,
   then continue with a known Telegram RSA fingerprint until the peer proves
   possession of its private key. Neither persistence nor `resPQ` alone is
   authenticated health.
3. Express local desync attempts as typed segment plans with stable fixtures,
   borrowing SpoofDPI's vocabulary without importing system mutation or packet
   behavior.
4. Add a language-neutral replay-safety classification: definitely unsent,
   maybe sent, and response started. Only definitely unsent, replay-safe work
   may be retried automatically.

### Platform and later work

- For M4, use Rethink's explicit Android network-event reducer and QELI's
  post-mutation re-read/prewarmed-resource ownership as design references.
- For M5, evaluate uQUIC transport-parameter fixtures, Mieru's bounded
  scheduling/padding, tiredvpn's half-open circuit recovery, and olcRTC's
  immutable link-health snapshots. Each stays behind Slipstream's route policy
  and OS adapter; none justifies a global VPN or UDP rule.
- MHRV relay infrastructure, MacDPI's system-control wrapper, and both generated
  node feeds are rejected. They change trust or workstation ownership instead
  of improving Slipstream's autonomous evidence model.

License boundary: MIT and Apache-2.0 projects may inform an adapted
implementation with required notices. GPL-3.0 and AGPL-3.0 projects are
behavioral references only unless a separately reviewed licensing decision is
made. No code or generated endpoint list from this audit was copied.

## Windows Userspace Stack Selection (2026-07-23)

The pure packet-flow contract needs a userspace TCP/UDP stack before raw Layer
3 packets can become owned flows. The selection gate evaluated three current
families without loading Wintun, opening sockets, or mutating the workstation:

- [`smoltcp 0.13.1`](https://docs.rs/smoltcp/0.13.1/smoltcp/) exposes explicit
  polling, caller-supplied device tokens, and fixed socket, fragmentation, and
  reassembly storage. Exact features and the crates.io checksum are frozen in
  `windows-userspace-stack-selection-v1.json`. The latest version requires Rust
  1.91, so it lives in a separate evaluation crate; the production core and
  Windows adapter keep their existing MSRV and dependency graph.
- [`ipstack 1.0.1`](https://github.com/narrowlink/ipstack) converts packets to
  async accepted streams, but the reviewed implementation uses unbounded Tokio
  channels for accepted streams and packet delivery. Its background-task and
  queue ownership cannot satisfy the current fixed memory and cancellation
  contract without maintaining a fork, so it is not selected.
- [`tun2proxy`](https://github.com/tun2proxy/tun2proxy) currently uses
  `ipstack` and also owns routing, DNS, and proxy orchestration. Those are
  application-level effects that Slipstream must keep behind its own policy,
  coexistence, and rollback contracts; the project is useful research but not
  a reusable stack boundary here. The older `ipstack-geph` crate was also not
  selected: its published source points at a repository that was not available
  during review and it does not improve the ownership boundary.

The fake Layer 3 qualification proves deterministic IPv4/IPv6 TCP round trips,
IPv4 and below-MTU IPv6 UDP, IPv4 outbound fragmentation plus inbound
reassembly, dual-stack UDP checksum rejection, and exact frame/socket limits.
It also freezes an important limitation rather than hiding it: the selected
version's dispatch path states that IPv6 fragmentation is unimplemented and
drops an oversized packet without emitting a frame. Incoming IPv6 fragment
reassembly is not implemented by the selected stack either: the feature flag
exposes Fragment Header wire types and shared bounded storage, but the IPv6
ingress path sends `Next Header = Fragment` through its unsupported-protocol
branch. An executable raw-fragment test confirms that no UDP payload reaches
the socket. The additive
`windows-userspace-stack-ipv6-fragment-input-v1.json` contract therefore
qualifies a separate pre-stack normalizer instead of mutating frozen selection
v1. It reconstructs exact in-order and out-of-order packets inside fixed
assembly, payload, fragment-count, and timeout bounds, rejects overlap and
conflicts, and delivers the completed packet to the selected stack with the
original UDP source endpoint. RFC 6946 atomic fragments are reconstructed
without allocating, expiring, or otherwise touching reassembly state, including
when their identification collides with an incomplete assembly or both bounded
slots are occupied. It accepts only a Fragment Header immediately after the
IPv6 base header. The additive capture-fragment effect contract now classifies
through frozen capture v4 before any fragment-state operation and binds each
ordinary assembly to one exact capture generation, flow, source, destination,
transport, ports, and policy result. Its deadline is the earlier of the
standalone 60-second fragment timeout and the capture evidence expiry, so v4
limits the composed state to five seconds. Direct passthrough and malformed or
mismatched input allocate nothing; same-identification input from another flow
cannot evict its owner. This remains a test-only composition outside native
packet effects and production composition.

Selection is not integration. Capture v4 now extends frozen capture v3 only
after policy classification and retains the original client source address and
port. Userspace-flow-binding v1 joins that endpoint to an already-admitted
frozen packet-flow-v1 capability only when the exact generation, flow ID,
transport, destination address/port, IP family, active policy, and expiry
agree, then retains that exact admission capability for open-transition
verification. Opening also requires the complete reducer-issued backend-open
and idle-deadline command set and must exactly equal a fresh reduction from its
supplied full predecessor. Every payload and active reconciliation transition
must also equal a fresh reduction from its supplied full predecessor and
configuration while preserving that complete admission capability. The owner
retains the exact full registry as a bounded cursor, including unrelated
transition progress, so a stale target-only snapshot cannot roll it back. Userspace
byte-owner v1 now bridges actual payload through an injected
atomic effect: it retains exact bytes only when the supplied packet-flow
predecessor equals its last snapshot, the accepted queue grows by the exact
declared length, and the transition supplies exactly the permitted forwarding
authorization. It preserves queued client payload in a non-forwardable state
until an exact `BackendReady` authorization. Delivery preflights the exact
acknowledgement from the current full registry and global watermark before the
effect, then advances the retained state only after success. It prevents replay of a committed
prefix. Generic reconciliation rejects `Forwarded` while the owner exists, so
the injected effect cannot be bypassed. A terminal final acknowledgement
releases its empty owner in the same successful commit even when bounded
terminal-history pruning removes the flow from the reducer output. Cleanup
stays event-scoped: ordinary terminal evidence removes only
its exact inactive flow, while explicit generation retirement is bounded by the
packet-flow high watermark. Before either path releases bytes, its transition
must exactly equal a fresh reduction from the supplied full registry, including
unrelated-flow progress. The selected stack is still not instantiated in the
Windows adapter. Native connector effects, disposable AMD64/ARM64 packet flow,
and production service-host composition remain closed.

## Windows Packet Capture Selection (2026-07-18)

### Why Slipstream will not own a kernel driver

Microsoft requires a driver submission to be certificate-signed and requires
an EV certificate associated with the Hardware Dev Center account for
attestation or WHCP submission. The alternative development path enables
Windows test-signing mode, may require disabling Secure Boot, and is not an
acceptable user installation model:

- [Driver code signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs)
- [Loading test-signed drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)

Slipstream therefore will not build, distribute, or seek production signing
for its own WFP callout. The already-frozen `windows-wfp-*` fixtures remain
useful records of safe stream-redirection ownership and teardown, but they are
dormant research contracts rather than the Windows shipping architecture.
This removes the kernel-driver certificate blocker; optional signing and
reputation for the userspace application remain a separate release concern.

### Selected primitive: official Wintun

[Wintun](https://www.wintun.net/) publishes precompiled, signed DLLs that may
be distributed unchanged with software. Version 0.14.1 includes AMD64 and
ARM64 builds and exposes an L3 adapter for userspace IPv4/IPv6 packet handling.
It is a local adapter API, not the WireGuard network protocol: this choice adds
no WireGuard tunnel, peer, endpoint, or wire traffic.
It therefore avoids a Slipstream-owned driver certificate, but it is not a
drop-in replacement for the old WFP stream boundary: Wintun supplies packets,
not an accepted TCP socket or original-destination context.

`vendor/wintun/SOURCE.json` pins the official archive URL, archive and license
hashes, publisher and signing-certificate identity, plus the exact AMD64 and
ARM64 DLL sizes, SHA-256 hashes, and PE machine values. The official archive is
`750540` bytes with SHA-256
`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`.
Its architecture DLLs are not committed to this repository.

Static inspection of both PE certificate tables produced the same WireGuard
LLC signer-certificate SHA-256,
`c9e1b3127c2f1312056d49a93ac4bd700393fd323d2bf3b2235aff52bea8d136`.
The disposable Windows 11 ARM64 VM also exposed the embedded PKCS#7 signer and
DigiCert timestamp chain with `certutil` without loading the DLL. This is
provenance evidence, not a substitute for the next native `WinVerifyTrust`
qualification; an expired leaf can remain valid only when Windows accepts its
trusted timestamp.

`contracts/windows-packet-adapter-v1.json` and pure Rust
`packet_adapter::v1` currently do only three things:

- admit caller-provided artifact evidence when every pinned package, DLL,
  architecture, Authenticode publisher, signer, and timestamp field matches;
- prepare a non-authorizing candidate only when fresh resolver evidence binds
  the canonical policy host to an observed public exact `/32` or `/128`
  destination whose active classification is `local_bypass` or `geo_exit`;
- reject that candidate unless opaque, complete, generation-bound evidence for
  the destination contains only canonical hosts with the same active route
  class and strategy.

IPv6 admission is frozen against the
[IANA IPv6 Global Unicast Address Space](https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xhtml)
snapshot dated 2025-10-10. IANA states that unlisted space within `2000::/3`
is reserved; the contract therefore uses the allocated-prefix list rather than
treating the whole assignable block as globally routable. Special-purpose
exceptions also follow the
[IANA IPv6 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml).

No current code downloads or loads `wintun.dll`, creates an adapter, installs a
route, handles a packet, changes the default route, or composes network effects
into the production Windows service. External DNS, proxy, PAC, and VPN state
remain read-only.

### Native artifact collector

The Windows collector opens the already-staged archive, license, and DLL with
`FILE_FLAG_OPEN_REPARSE_POINT` and read-only sharing, verifies each final path,
and hashes each exact handle. It parses only the bounded DOS and PE headers for
the machine value. The DLL stays open while its same handle is supplied through
`WINTRUST_FILE_INFO.hFile` to
[`WinVerifyTrust`](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust),
which prevents a path replacement between hashing and signature validation.

The Authenticode operation uses no UI and
`WTD_CACHE_ONLY_URL_RETRIEVAL`; it does not perform hidden online revocation
lookups. A result is valid only when Windows returns exact success, the leaf
certificate organization is `WireGuard LLC`, its SHA-256 matches the pinned
certificate, and the provider exposes a successful timestamp countersigner.
Every verification state is closed through `WTD_STATEACTION_CLOSE`. Microsoft
documents both the optional held handle in
[`WINTRUST_FILE_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_file_info)
and the required verify/close lifecycle in
[`WINTRUST_DATA`](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data).

The returned native admission is non-cloneable and retains the read-only DLL
handle. No loader exists in this change. CI first verifies the official archive
length and SHA-256 before extraction, then asks the collector to admit both the
AMD64 and ARM64 DLLs and reject a changed copy. Adapter creation, exact-route
ownership, packet processing, and production composition remain absent.

### Shared-destination conflict admission

A system exact route is wider than the hostname that motivated it. The same
CDN address can concurrently serve Discord, OpenAI, Google, or an unrelated
direct destination, so one successful DNS answer cannot authorize capture.
The pure conflict gate accepts only an opaque snapshot claiming a complete
owned resolution boundary for that exact address. A partial observation fails
closed. The snapshot is limited to 256 canonical policy hostnames, must be
strictly sorted and unique, must contain the candidate host, and may live for no
more than 30 seconds. Every host is reclassified against the active policy and
must select the same route class and strategy set.

The resulting admission carries the collector generation and expires at the
earlier route or conflict-evidence deadline. It is intentionally not native
authorization.

A later feasibility review rejected the planned native issuer. System DNS is
not a complete observation boundary: Windows supports
[encrypted DNS](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-encryption-dns-over-https),
applications may own their resolver path, and a suffix policy represents an
unbounded set of concrete hostnames.
[Wintun](https://git.zx2c4.com/wintun/about/) exposes L3 packets rather than an
accepted stream with trusted hostname or original-destination context.
Advancing a generation whenever the *observed* cache changes would therefore
measure cache freshness, not shared-destination completeness.

Packet-adapter v1 remains frozen with no route effect. Any successor must use
exact routes only as a capture mechanism and reclassify each flow from bounded
in-band evidence. A flow with missing, encrypted, or otherwise ambiguous
hostname evidence must remain direct passthrough. That design must also prove
that Slipstream's outbound sockets cannot re-enter its own adapter, that route
activation does not strand pre-existing flows, that capture expires and is
removed promptly, and that an external VPN remains unmodified and usable.
Windows exposes explicit per-socket interface selection such as
[`IP_UNICAST_IF`](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options),
and
[`IPV6_UNICAST_IF`](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options),
but the v2 feasibility gate must prove the complete IPv4/IPv6 behavior rather
than assume that one socket option solves loop avoidance. Wintun exposes the
adapter LUID through its
[`WintunGetAdapterLUID`](https://git.zx2c4.com/wintun/tree/api/wintun.h?h=0.14.1)
API. A future read-only collector must obtain the pre-capture route through
[`GetBestRoute2`](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/getbestroute2),
revalidate its current interface index through
[`ConvertInterfaceLuidToIndex`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceluidtoindex),
record the baseline route epoch, and after activation repeat the read-only
best-route/source lookup constrained to that preserved egress interface. The
current source must exactly match the baseline; interface identity alone does
not prove that an address remains selected. Installing the exact owned capture
route
is itself an expected epoch transition, so a separate trusted issuer must
serialize that operation and attest its destination, exact host prefix,
capture interface, previous epoch, and active epoch. Every later
[`NotifyRouteChange2`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyroutechange2)
epoch advance invalidates the admission.

`windows-packet-egress-v1` freezes only the pure admission produced from that
future trusted evidence. It permits any non-capture egress selected by the
system, including an external VPN, and contains no interface-type allowlist.
IPv4 special-purpose ranges, including the deprecated `192.88.99.0/24` 6to4
relay block, fail closed. Public IPv6 destinations are frozen against the
[IANA IPv6 Global Unicast Address Space](https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xhtml)
snapshot dated 2025-10-10 and cross-checked against the 2025-10-09
[IPv6 Special-Purpose Address Space](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml);
the positive allocation table is not sufficient by itself. Assigned but
non-global ORCHIDv2 `2001:20::/28` and DET `2001:30::/28`, plus unlisted,
documentation, and discard-only ranges, fail closed. The
plan records the platform-specific socket-option value but does not call the
option. Therefore its vectors prove stale-, special-purpose-, and
self-interface rejection, not that real packets avoid a competing capture
route; that remains a disposable native AMD64/ARM64 gate. The serializable
activation record is deliberately not authorization to mutate the route table.
The native issuer remains closed until it can prove that the record describes
Slipstream's exact serialized transition rather than hiding an unrelated
concurrent route change.

### Remaining safety gates

An exact IP route is still broader than a hostname because CDN destinations
can be shared. A candidate plan is therefore not sufficient authorization for
a route-table mutation. Native work remains ordered as follows:

1. Completed: collect artifact evidence through read-only Windows APIs and
   qualify the official package plus tamper rejection on disposable AMD64 and
   ARM64 Windows without loading the DLL or creating an adapter.
2. Completed as a pure contract: freeze packet-route v1 and specify a
   capture-only v2 boundary. Backend authorization must come from bounded
   per-flow evidence; missing or opaque hostname evidence stays direct.
3. Completed on native AMD64 and ARM64: load only the exact admitted DLL,
   create one unique adapter and minimum session, and prove bounded cleanup
   after both ordinary close and abrupt termination of the exact owner process.
   These gates configure no address or route.
4. Current: keep `windows-packet-egress-v1` pure while adding a trusted
   read-only route collector, an exact owned-transition issuer, and a
   disposable IPv4/IPv6 socket fixture. Prove
   actual outbound loop avoidance under a competing capture route, activation
   safety for existing flows, bounded capture expiry/removal, and explicit
   coexistence with an already-active external VPN on both native
   architectures.
5. Only if that feasibility gate passes, define owned adapter and exact-route
   transactions with crash-safe rollback, then select and bound a userspace
   IPv4/IPv6 and TCP/UDP stack. Prove that direct,
   local-bypass, and geo-exit packet flows retain the shared policy invariants;
   Discord and YouTube must never acquire a Geph edge.
6. Qualify crash, reboot, sleep/wake, update, uninstall, route churn, and
   external DNS/proxy/PAC/VPN coexistence on disposable AMD64 and ARM64 hosts.
7. Compose the adapter into the production service only after every earlier
   gate passes and teardown leaves no adapter, route, process, or durable
   ownership residue.

WinDivert remains unsuitable for the current ARM64 gate and would also require
packet reinjection/NAT ownership. System proxy/PAC would mutate user settings.
Npcap, ETW, and pktmon are observation tools rather than a controlled routing
primitive. None is a production fallback for a failed Wintun qualification.

## Codebase Graph

- Observed on 2026-07-08: the configured `mcp__codebase_memory_mcp` tool failed
  in the active Codex session with `Transport closed`.
- The graph backend itself is healthy. `codebase-memory-mcp cli list_projects`
  works, and manual JSON-RPC over stdio works for `initialize`, `tools/list`,
  and `tools/call list_projects`.
- `/Users/aiwaki/.codex/config.toml` now sets `CBM_LOG_LEVEL=error` for
  `codebase-memory-mcp`.
- `/Users/aiwaki/.local/bin/codebase-memory-mcp` is a wrapper that forces
  `CBM_LOG_LEVEL=error` and executes the original binary at
  `/Users/aiwaki/.local/bin/codebase-memory-mcp.bin`.
- The active Codex session appeared to keep a stale failed MCP transport and did
  not invoke the wrapper. Until a session reloads tools, use
  `codebase-memory-mcp cli` as the graph-backed discovery path.
- Observed again on 2026-07-13: indexing the fresh daemon-recovery worktree
  timed out after 300 seconds, and the following graph search also stalled.
  The CLI `list_projects` path remained healthy. Discovery continued from the
  current `main` graph plus narrow `rtk` source searches. Re-index after the MCP
  process or Codex session is restarted.
- Observed again on 2026-07-18 while indexing the clean Windows-controller
  clone: the MCP transport returned `Transport closed`. The controller audit
  continued from exact `main` source and narrow symbol/string searches; no stale
  graph result was treated as current evidence. A later `list_projects` call in
  the Wintun continuation failed with the same transport error, so that work
  retained the same fallback rather than assuming the graph had recovered.

Indexed routing projects:

- `Users-aiwaki-Documents-Codex-2026-04-30-github-plugin-github-openai-curated-https-slipstream`
- `tmp-slipstream-research-sonic-sonicdpi`
- `tmp-slipstream-research-unblock-unblock-pro`
- `tmp-slipstream-research-sonic-20260708-sonicdpi`
- `tmp-slipstream-research-unblock-20260708-unblock-pro`

Fresh external snapshots checked on 2026-07-08:

- `by-sonic/sonicdpi` at `ebd08f71d33ce8cbeb671742b06054471adbdfd5`
- `by-sonic/unblock-pro` at `a075902efca70392cf7e07f97c85a8b280cb571c`

Fresh external snapshots checked on 2026-07-09:

- `roninreilly/darkware-zapret` at `1d9834a5716d65b6140df24dd64fec350d461bb9`
- `mksglu/context-mode` at `43a2066da943572546ff316ceca79026163be0b1`
- `obra/superpowers` at `d884ae04edebef577e82ff7c4e143debd0bbec99`
- `affaan-m/ECC` at `4130457d674d2180c5af2c5f634f3cae4cbc6c4f`
- `ruvnet/ruflo` at `a444930d88d753e04793f55bd38861e82d9cb062`

## SonicDPI Findings

- The most useful idea is cautious target identity, not a direct strategy copy.
  SonicDPI classifies by TLS SNI, verified QUIC destination, Discord voice
  packet shape, IP-prefix fallback, and sticky flow inheritance.
- SonicDPI explicitly avoids treating every UDP/443 QUIC Initial as YouTube.
  It only upgrades QUIC to YouTube when the destination is verified by prefix
  or DNS evidence. This matches Slipstream's rule: no global UDP/443 handling.
- SonicDPI's default target set covers a broad Discord domain family, including
  updater, status, CDN, auxiliary brand domains, and `discord.media`.
- The engine always observes DNS responses first and uses a DNS cache to
  classify later packets whose SNI is no longer visible. This is a useful model
  for local-bypass health: do not guess UDP/QUIC identity globally, correlate
  it with recent DNS or other host/IP evidence.
- The DNS cache is bounded and time-limited. The useful transferable idea is
  not "own DNS", but "remember verified host-to-IP evidence briefly." The
  current macOS pf/TCP daemon cannot passively observe UDP/53, so this belongs
  either in read-only diagnostics now or in a future packet adapter.
- Slipstream now adds read-only DNS diagnostics to status: active resolver
  detection, `xbox-dns.ru` provider detection, and cached sentinel resolutions
  for Discord/YouTube hosts that flag null, private, or known poison-stub
  answers. This records evidence without changing DNS settings.
- SonicDPI has a lightweight probing model that records wins/losses, ranks
  profiles by a Wilson lower-bound, and gives old entries a small age bonus so
  alternatives get re-tested. Slipstream can borrow this shape for autonomous
  route-health scoring without adding a manual strategy picker to the UI.
- Slipstream now keeps an in-memory local-bypass strategy score per host and
  strategy. Runtime and canary outcomes record wins/losses, cached winners get a
  small bias, stale entries get a small age bonus, and fake-only policies remain
  fake-only.
- 2026-07-09: GitHub API requests were reachable, but Git smart-HTTP transfer
  could hang after the initial refs response while `github.com` and
  `objects.githubusercontent.com` were still classified as `unknown/generic`.
  The safer route is direct-passthrough, plain-only, because these developer
  endpoints do not need local DPI desync or Geph.
- 2026-07-09: Steam Store's original geo-exit canary only proved that Geph could
  open a SOCKS/TLS stream. It now performs a small HTTPS GET for `/` and requires
  a minimum payload so "page shell starts, then stalls" is visible to autonomous
  health instead of requiring manual browser testing.
- 2026-07-10: Browser symptoms where the main page loads but some subresources
  stall exposed that an exact host can be incorrectly learned as geo-exit.
  This remediation was superseded on 2026-07-13: generic hosts no longer learn
  Geph at all, so the failure class cannot recur from a stale auto-Geph entry.
- 2026-07-10: After wake, route canaries can run before Geph/DNS are fully back.
  If `geph_up` arrives while that wake check is still running, the force cooldown
  used to drop the recovery recheck and leave the tray in `needs attention` until
  the next periodic run. Forced recovery triggers now queue a short pending rerun
  and preserve the original reason.
- 2026-07-10: `darkware-zapret` was simultaneously active through root anchor
  `zapret`, nested `zapret-v4`, and `tpws` on `127.0.0.1:988`. Its root anchor
  precedes `com.apple/*`, so PF's first matching `rdr` sent all real HTTPS there
  while Slipstream's internal Discord canaries still reported healthy. Discord
  updater then failed TLS with macOS error `-9806`; stopping only Darkware's
  runtime moved connections to Slipstream `:1080`, completed the update check in
  about six seconds, and reached Gateway `READY`. This is an interceptor
  ownership conflict, not a reason to route Discord through Geph.
- SonicDPI detects likely forged inbound TCP RST packets by learning a target
  flow's baseline server TTL and dropping early RSTs with a large TTL delta.
  This is useful research for packet-level adapters, but it cannot be copied
  into the current macOS pf/TCP transparent-proxy layer.
- SonicDPI has a TCP MSS clamp strategy for Cloudflare-fronted Discord where
  mid-stream classifiers reset update/download flows after the initial TLS
  handshake. It rewrites outbound SYN MSS and carries a throughput cost, so it
  is future packet-adapter research only and must be gated to verified target
  IPs if adopted.
- SonicDPI covers Discord voice UDP ranges `19294-19344` and `50000-50100`.
  That depends on packet-level filtering. It should not be copied into
  Slipstream as a broad pf redirect.
- SonicDPI's QUIC fake Initial and Discord voice fake payloads are randomized.
  This is useful future research only if Slipstream starts touching those
  packet classes directly.
- SonicDPI contains a macOS Network Extension prototype around
  `NEFilterPacketProvider`, with Rust packet logic behind a Swift System
  Extension harness. That confirms the right long-term Apple path for
  per-packet UDP/voice handling. It is not a small change to the current pf/TCP
  daemon.

## Unblock-Pro Findings

- The useful connectivity probe is a real Discord Gateway WebSocket handshake
  against `gateway.discord.gg`. Slipstream already has an equivalent payload
  canary.
- The Discord Gateway WebSocket canary now generates a fresh
  `Sec-WebSocket-Key` for every probe, so it behaves like a real handshake
  rather than replaying a static sample nonce.
- Unblock-Pro avoids false positives by requiring both service shell and
  delivery endpoints: YouTube web plus `redirector.googlevideo.com`; Discord
  API plus CDN; and a real Gateway WebSocket upgrade. This is a good canary
  structure for Slipstream's route health because a homepage or thumbnail can
  work while playback or app login still fails.
- Slipstream now keeps per-check canary health in `canaries.checks` and reduces
  it into the backward-compatible group-level `route_health`. A passing
  `discord_cdn` canary no longer hides a failing `discord_gateway` canary.
- Discord local-bypass health now has separate API, Gateway WebSocket, CDN, and
  updater canaries, matching the endpoint split that Unblock-Pro used to avoid
  false positives.
- YouTube local-bypass health now splits the web shell canary from the
  `googlevideo`/redirector QUIC video-delivery canary.
- Flowseal-style rules include Discord voice UDP ranges and `discord.media`
  alternate TCP ports `2053,2083,2087,2096,8443`. These are useful references,
  but should only be used with host/IP evidence. No global alternate-port
  capture.
- Unblock-Pro tries a remembered last-working strategy first and then a fixed
  Flowseal priority order. Slipstream can use a private route-health cache for
  ordering autonomous checks, but should not expose or require a manual strategy
  picker.
- Unblock-Pro pins a Flowseal release, records a bundle checksum, and tests the
  generated strategy snapshot. That is the right shape for any future
  remote-policy import: signed or checksummed data plus fixtures, not live
  execution of unreviewed scripts.
- Unblock-Pro also ships broad exclusion lists for banks, government sites,
  games, stores, and local/private networks. Treat this as a warning that
  bypass rules need direct-passthrough regression tests; the exact lists should
  not be copied without evidence.
- `safe-copy` and binary-format checks are useful for release/install hygiene:
  retry locked files, skip identical files, and validate Mach-O headers before
  installing local binaries.
- Slipstream now validates that the bundled daemon is an executable Mach-O before
  asking launchd to install it, and reports the validation result in diagnostic
  snapshots.
- Frozen daemon and vendored proxy installs now copy into a temporary path before
  swapping into `/usr/local/slipstream`, and script installs skip identical files
  while replacing changed files atomically.
- GitHub mirror URL fallback could help updater reliability, but only as an
  app-owned download fallback. It must not mutate global proxy, DNS, or VPN
  settings.
- Unblock-Pro's macOS global UDP block writes pf rules for `udp/443`,
  `19294:19344`, and `50000:50100`. Do not copy this. It conflicts with
  Slipstream's invariant that QUIC/UDP must stay open unless a narrow,
  evidence-backed host/IP rule exists.
- Do not copy Unblock-Pro's `/etc/hosts`, system DNS, or system proxy mutation
  behavior into Slipstream.
- Do not copy its static `/etc/hosts` fallback for Discord voice or Telegram:
  stale IPs can create worse failures than the original DPI block, and this
  violates Slipstream's rule that external DNS/hosts state is read-only.
- Neither SonicDPI nor Unblock-Pro uses `xbox-dns.ru` directly in the inspected
  code. If users configure it at the OS/router level, Slipstream treats that
  setting like other external DNS state: report it in diagnostics if relevant,
  but never enable, replace, or restore it automatically. This does not preclude
  Slipstream's separate exact-host DoH fallback, which does not read or modify
  the user's resolver configuration.

## Darkware Zapret Findings

- The pleasant menu is a SwiftUI `MenuBarExtra` with `.menuBarExtraStyle(.window)`,
  a fixed-width material popover, a title row, a large toggle, one status row,
  compact picker rows, and icon-only footer actions with tooltips.
- This is a useful reference for Slipstream's future tray diagnostics: a calm
  compact popover can show "working", "needs attention", and a small details
  action without stretching the native menu line.
- Do not copy the visible engine/strategy picker as the main workflow.
  Slipstream should keep strategy selection autonomous and evidence-driven.
- Darkware's `tpws` path is a transparent TCP proxy. Its `ciadpi` path uses a
  system SOCKS proxy for TCP and UDP. The system SOCKS mutation is not suitable
  for Slipstream because external proxy/PAC/VPN state is user-owned.
- Do not copy the installer sudoers pattern that grants `NOPASSWD` for a service
  control script. Slipstream should keep privilege boundaries tighter and auditable.
- The bruteforce helper is useful as a diagnostic pattern: start a temporary
  local proxy, try candidate strategies with real endpoint requests, then record
  winners. Slipstream can adapt that as a headless re-sweep after local-bypass
  failures, not as a manual picker.

## Agent Tooling Findings

- `context-mode@context-mode` is installed and its doctor passes for Codex hooks,
  MCP server startup, SQLite/FTS5, and plugin registration. It required using the
  bundled Codex Node runtime because the system Node was too old for the plugin.
- `superpowers@openai-curated` is installed and enabled. It is a process-skill
  bundle for planning, debugging, verification, and branch finishing. It should
  remain agent-side tooling, not a Slipstream dependency.
- `affaan-m/ECC` was inspected but not installed. The repo's own Codex plugin
  notes describe the current Codex plugin path as fragile, and the skill bundle
  is too broad for this project without a focused need.
- `ruvnet/ruflo` was inspected but not installed. It brings a large meta-harness,
  swarms, MCP behavior, hooks, and daemon-style features. Useful ideas are ADRs,
  health checks, witness manifests, and tool-description audits; the harness is
  too much global behavior for Slipstream right now.

## Steam Store Findings

- Runtime status on 2026-07-09 showed Slipstream active, pf applied, system proxy
  off, `xbox_dns` detected as external DNS, and existing route-health groups OK.
- Direct endpoint probes showed `store.steampowered.com` returning HTTP 200 but
  stalling while transferring the page body: about 13 KB in 25 seconds. The same
  URL through Slipstream's bundled Geph SOCKS on `127.0.0.1:9954` transferred
  about 1.37 MB in about 2 seconds.
- Steam's own logs showed WebSocket CM attempts timing out before a later
  successful UDP connection. Keep CM/gaming/download paths separate from the
  Store web fix.
- Slipstream now treats the Steam Store web family as `steam_store`/`geo_exit`:
  `steampowered.com`, `steamcommunity.com`, `steamstatic.com`,
  `steamusercontent.com`, and the narrow Steam-owned Akamai hostnames
  `steamcdn-a.akamaihd.net` and `steamcommunity-a.akamaihd.net`.
- Steam Store skips Smart DNS even when `xbox-dns.ru` is active because the
  observed failure was an application-data stall on the direct path, not just
  DNS poisoning. Runtime uses the bundled Geph tunnel for this group.
- Do not route `steamserver.net`, Steam CM, game traffic, or broad Akamai/Fastly
  hostnames through Geph without endpoint-level evidence.

## Unknown-Host Local Recovery

- Generic local stalls never learn `geo_exit`: a foreign tunnel working for a
  host is not evidence that the host rejects Russian IPs.
- An unknown host may receive one exact, local retry through a Slipstream-issued
  Xbox DNS query. This does not inspect or alter the system resolver and does not
  select Geph.
- Legacy `/var/run/slipstream-autogeph.json` entries are discarded on daemon
  start. The compatibility status field remains disabled for one transition
  release so older tray clients can read it safely.
- Google and Spotify families that are known to work natively use explicit
  `direct_first` policy: plain TLS is always first, bounded local desync is the
  only fallback, and Geph is excluded. Discord and YouTube/googlevideo remain
  independent `local_bypass` routes.
- YouTube web-shell probing is warning-only; the hard YouTube health signal is
  the `youtube_video`/googlevideo path because browsers can reach the web shell
  through IPv6/QUIC while daemon-side IPv4/TCP probes are noisy.
- New foreign-exit routes require explicit, reviewed policy evidence. Static
  policy is preferred when a service class is well understood and has multiple
  endpoint families.

## Runtime Local-Bypass Recheck

- Periodic canaries were already able to clear stale local-bypass strategy
  cache and re-sweep candidates, but runtime connection failures could stay
  invisible until the next scheduled canary.
- Slipstream now reports full runtime local-bypass strategy failures into route
  health, clears only the affected local-bypass route group's strategy cache,
  and force-schedules route canaries with the existing cooldown.
- The same failure also schedules a private exact-host re-sweep. It tries only
  the host's allowed local-bypass fake/desync strategies, caches the first
  working strategy, and then clears that host's negative cache. The scheduler
  is deduplicated and does not expose a visited-host history in status.
- Runtime success marks the affected local-bypass group healthy. Discord and
  YouTube/googlevideo remain local-bypass only; this path never promotes them
  to Geph.

## Explicit Route Policy Tables

- Static direct/local-bypass/geo-exit routing now uses `ROUTE_POLICY_TABLE`,
  `GEO_EXIT_POLICY_TABLE`, and `IP_ATTEMPT_LIMIT_BY_ROUTE` instead of embedding
  every group decision directly in `route_policy`.
- This does not change runtime behavior. Discord and YouTube/googlevideo remain
  fake-only local-bypass groups; Telegram stays direct; OpenAI/Anthropic/Steam
  Store stay geo-exit where listed.
- The shape is intentionally close to a future signed policy payload while
  keeping the current source-controlled policy as the only active authority.
- `scripts/make_route_policy_bundle.py` can turn a reviewed manifest or the
  current bundled manifest into a signed JSON bundle and matching public-key map
  for release hosting. It also verifies generated bundles against the key map.
  The daemon verifier accepts legacy bundles without a hash, but any provided
  `sha256` must match the canonical manifest hash.
- The same helper can generate a raw Ed25519 release keypair. Private keys are
  created with `0600` permissions and existing key files are not overwritten.
  Real production private keys must stay outside git.
- Trusted public keys can be embedded in code, bundled as `route-policy-keys.json`
  next to the frozen daemon, or overridden from Slipstream-owned state under
  `/var/db/slipstream`. The repo does not contain real production keys.
- Remote policy fetch can read either a direct signed bundle URL or a stable
  channel index. Channel indexes use `kind: slipstream.route_policy_channel`,
  `schema: 1`, `bundle_url`, and `sha256`; the bundle payload hash is checked
  before signature verification and health gates.

## Daemon-Owned Geph Recovery

- The recovery reducer already produced `restart_owned_geph` after repeated
  post-wake failures across multiple geo-exit hosts, but the action previously
  stopped at a status hint. A running tray was still required to perform any
  live-process restart.
- The Geph launcher now records its numeric user ID together with PID,
  executable, config, and LaunchAgent label. The daemon accepts the claim only
  when that ID also owns the claim file and the current listener still matches
  the recorded process identity.
- Recovery pauses only `com.apple/slipstream`, waits for the aggregate active
  Geph-session count to reach zero, and calls `launchctl kickstart -k` for the
  exact `gui/<uid>/dev.slipstream.geph` target. LaunchAgent `KeepAlive` continues
  to handle ordinary process death.
- A busy tunnel defers the action. A missing or mismatched claim, unknown
  listener, external Geph, or unexpected label produces no signal and no PF,
  DNS, proxy, PAC, or VPN mutation.

## Transfer Backlog

Safe candidates:

- Keep policy tests for the broad Discord family and every Discord host on
  `local_bypass`.
- Add narrow YouTube-family policy coverage for `youtu.be` and `ggpht.com`.
  Broader Google domains such as `googleapis.com` and `googleusercontent.com`
  need observed evidence before they join local bypass.
- Continue adding service-class canaries only when there is evidence that a
  separate endpoint class can fail independently.
- Continue refining read-only DNS diagnostics only from evidence; keep resolver
  settings immutable.
- Keep tuning autonomous strategy scoring from real logs; do not expose a manual
  strategy picker in the tray.
- Consider a compact tray diagnostic popover inspired by Darkware's layout, but
  keep Slipstream's native-menu simplicity and autonomous routing model.
- Keep Steam Store geo-exit narrow; add direct-passthrough diagnostics before
  widening Steam CM, game, or download routing.
- For future packet adapters, evaluate MSS clamp only for verified
  Cloudflare-fronted Discord update/download flows.
- Watch reinstall logs for any remaining locked-file or permission edge cases.
- Add app-owned GitHub download mirror fallback only behind checksum/signature
  validation.
- Define production signing-key storage and release-channel hosting for signed
  route-policy bundles before enabling remote fetch for users.
- Keep external DNS, VPN, PAC, and proxy settings read-only: detect and warn,
  never rewrite.

Unsafe candidates:

- Routing Discord or YouTube through Geph.
- Global QUIC/UDP blocking.
- Blocking `udp/443`, `19294-19344`, or `50000-50100` globally to force a
  fallback path.
- Global alternate-port capture without verified host/IP ownership.
- Mutating `/etc/hosts`.
- Rewriting system DNS, system proxy, PAC, or external VPN configuration.
- Auto-configuring third-party DNS such as `xbox-dns.ru`.
- Auto-configuring system SOCKS proxy to support an engine.
- Granting broad `NOPASSWD` sudoers entries for service control.
- Adding Steam CM/game/download traffic to Geph or local bypass without
  endpoint-level evidence.
- Global MSS clamp or MSS clamp on broad Cloudflare/Google traffic.
- Importing upstream strategy scripts without a pinned, verified, and reviewed
  policy bundle.
