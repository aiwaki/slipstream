# Полный аудит Slipstream — 2026-09-05

## Задание / промпт проверяющему

Проверь весь проект Slipstream, а не только последний симптом Aikido. Сначала
сверь исходники, незавершённую работу, Git/PR/CI и действующие решения. Составь
инвентаризацию всех отслеживаемых файлов и распределение областей проверки.
Для каждой подсистемы проследи входы, доверительные границы, состояние,
ошибки, таймауты, отмену, владение ресурсами и завершение работы. Проверь
согласованность контрактов, тестов, сборки, упаковки и документации.

Ищи причинные дефекты: конкретный достижимый путь, нарушенный инвариант и
воспроизводимое наблюдение. Отделяй подтверждённый дефект от предположения,
исторического результата и непроверяемой здесь платформенной границы.
Исправляй корень подтверждённого дефекта минимальным согласованным изменением,
добавляя регрессионную проверку. Не добавляй статические правила сайтов,
повторные попытки или ослабление доказательств ради зелёного результата.

Особенно проверь: автоматическое восстановление целой страницы и критических
ресурсов; медленное, но рабочее соединение; точность IP/host/connection cache;
DNS, TLS/HTTP framing, QUIC, PF; владение Geph; Quit/Stop/update/rollback;
равенство свежего, staged, bundled и установленного daemon; безопасное
обращение с данными и привилегиями; release proofs, зависимости и CI.

Сохраняй локальные изменения пользователя. Discord, YouTube/googlevideo и
Telegram не переводить в Geph; не менять внешние DNS/proxy/PAC/VPN, внешний
Geph и глобальный UDP/443. Обычный путь остаётся локальным и без браузера.
Восстановление должно быть автоматическим, ограниченным и доказанным.
Не запускать установку, привилегированные сетевые проверки, защищённые
account-backed workflow, soak или публикацию в рамках этого аудита.

Используй известную зелёную базу, если её исходники действительно совпадают.
На исправления запускай минимально достаточные регрессии; расширяй проверки
при общих контрактах, широком влиянии или непригодной базе. Не выдавай
unit-тесты за физическое доказательство Chrome/Safari или Windows.
В этом файле веди журнал: область, файлы/символы, дефект и причина,
исправление, точная команда/результат теста, остаточный риск. В конце укажи
фактическое покрытие и незакрытые границы. Не обещай отсутствие всех ошибок.

## База и сохранность

- Основной checkout: `/Users/aiwaki/Developer/slipstream-macos-baseline-diagnostics`,
  `a22a698e809af5c1892e90ad462512f6719e56e7`, ветка
  `codex/modern-macos-update-notifications`. Его `.playwright-cli/` и `output/`
  не изменяются; два закрытых каталога диагностики не читаются принудительно.
- Live `origin/main`: `2780de4b3f5d77ab3852e46381b997c618bd5080`.
- PR #373 открыт на `513484ac43ae0348df06e61fca5af9d3105eb225`;
  exact-head CI `32867878889` и dependency audit `32867879962` зелёные.
  Эти проверки не относятся к более поздним локальным изменениям.
- Последняя сохранённая локальная ветка `codex/aikido-cdn-recovery`:
  `8cee1ca1ab14e27dca377e44960718867fd3e71a`. Она содержит последующие
  исправления сборки, критических ресурсов и gzip; выбрана базой аудита,
  чтобы не откатить незавершённую работу до старого main/PR.
- Аудит ведётся в постоянном отдельном worktree
  `/Users/aiwaki/Developer/slipstream-codebase-audit-20260905`,
  ветка `codex/codebase-audit-20260905`.
- Исправления и регрессии сохранены отдельным локальным source commit
  **`c060518d52ab888dfd9e92c7472a10dbabe8e555`** (17 файлов).
  Этот отчёт/checkpoint сохраняются следующим documentation commit.
  Push, новый PR, merge и установка в этом проходе не выполнялись.
- Старый `/private/tmp/slipstream-aikido-rootfix.Bekk7h/worktree` существует
  лишь частично: `.git` и отслеживаемые документы отсутствуют. Историческая
  незакоммиченная версия не считается восстановленной и не считается
  совпадающей с этой базой или установленным приложением. Остатки не удалены.
- PR #374 — отдельное открытое обновление Geph; не включается молча в аудит.
- `context-mode` прочитан, но его инструменты отсутствуют в активном списке.
  Используются ограниченный вывод и локальные журналы. Старый memory registry
  сейчас отсутствует; текущие Git/документы приоритетнее прежних сводок.

## Покрытие

| Область | Статус | Результат |
|---|---|---|
| Python daemon, routing, DNS, TLS/HTTP, PF/QUIC, Geph | код, baseline и узкие регрессии проверены | исправления object/IP authority и Stop |
| Tauri tray, lifecycle/Quit, install, updater/rollback, notifications | код и тесты проверены; повторный review Quit чист | lifecycle, Geph ownership, deadline, redaction, login state |
| Rust core, Windows adapter, evaluation crates, JSON contracts | проверено в доступной на macOS области | 4 crate; исправлена terminal queue |
| Browser companion, native helpers, semantic harness | код, JS/Rust/Swift тесты проверены | retention bound и absolute deadline |
| CI/release/build, artifact verification, dependencies | проверено | staging, finite soak evidence, download byte bound |
| Docs, configuration, test inventory, source preservation | проверено; checkpoint обновлён | база сверена, primary не менялся |

Инвентаризация базы: **536 отслеживаемых файлов**: `app-tauri` 87,
`browser-companion` 18, `contracts` 56, `crates` 173, `spike` 66,
`scripts` 77, `docs` 14, `vendor` 23, `.github` 9, `security` 2,
остальные 11 — корневые документы/конфигурация и `.cargo`.
Это риск-ориентированный проход по всем областям плюс доступные контрактные
наборы, **не утверждение о ручном чтении каждой строки каждого файла**.
Сгенерированные bundles, binary payloads, dependency source и старые локальные
логи не приравниваются к исходникам продукта.

Особо прослежены: root/child preflight и доказательство выбранного маршрута;
TCP/QUIC, отмена и кэши; daemon cleanup и launchd ownership; tray lifecycle,
updater transaction и install attestation; BrowserProbe framing/deadlines;
privacy boundary companion; core routing/race/signed-policy, Windows
capture/data-plane/forwarding/IPv6 reassembly; candidate/publisher точные
SHA/run/attempt, подписи, attestations и archive validation; pinned supply
chain и budget/account workflow guards. Граф использован для code discovery;
scripts/config вне fast-index и уже изменённые snippets с устаревшими
смещениями проверены узкими чтениями текущих файлов.

## Подтверждённые дефекты и исправления

### AUD-01 — staging удалял предыдущий daemon до начала замены (исправлено)

- Файлы: `scripts/build_and_stage_daemon.sh`, `scripts/test_build_config.py`.
- Причина: EXIT-trap считал отсутствие временного `stage_dir` признаком уже
  совершённого `mv`. Но каталог также отсутствует при раннем отказе проверки
  нового payload. В таком случае удалялся существующий `target_dir`.
- Воспроизведение: отсутствующий новый payload, неисполняемый daemon и symlink
  вместо нового daemon — все три случая удаляли предыдущие файлы.
- Исправление: удаление нового target разрешено только после начала его
  установки; rollback уже созданного backup сохранён.
- Проверка: новая регрессия сначала дала 3 failures; после исправления она и
  существующий тест fresh/staged/backup/swap проходят (2 tests).

### AUD-02 — бесконечная длительность принималась как доказанный soak (исправлено)

- Файлы: `scripts/release_readiness.py`, `scripts/test_release_readiness.py`.
- Причина: стандартный Python JSON decoder допускает `Infinity`, а валидатор
  проверял лишь `measured >= requested`. Отчёт с `measured=Infinity` получал
  `passed`; это не валидное измерение времени.
- Исправление: измеренная float-длительность должна быть конечной. Минимум
  1800 секунд, выборка, cleanup, матрица и остальные release gates сохранены.
- Проверка: регрессия воспроизвела принятие `+Infinity`; после исправления
  10 readiness tests + 9 nonfinite subtests проходят. Никакой soak не запускался.

### AUD-03 — один healthy объект скрывал другой critical child (исправлено)

- Файлы: `spike/tproxy.py`, `spike/test_tproxy_doh.py`.
- Root/child cache и завершение совместного host-slot переиспользовались как
  доказательство доступности другого transient URL. Незавершённый child мог
  также подавляться отрицательным parent cache.
- Healthy или отрицательный результат одного объекта больше не очищает
  другой объект. Waiter получает inconclusive, пока нет действительно
  committed exact-host route; unresolved child не публикует parent retry cache.
- Только доказанный learned exact-host маршрут может переиспользоваться между
  объектами; URL остаются временными, никаких постоянных URL-cache/host rules.
- Падавшие регрессии воспроизведены до исправления; исходный набор Stop/cache
  44 passed. Это причинный дефект кода, не захваченная причина live Aikido.

### AUD-04 — Quit закрывал tray, оставляя продукт работающим (исправлено)

- `app-tauri/src-tauri/src/lib.rs`, новый `lifecycle.rs`, `spike/tproxy.py`.
- `ID_QUIT => app.exit(0)` не отключал KeepAlive daemon/owned Geph.
- Явный Quit теперь сериализуется с привилегированными install/repair и
  updater admission, инвалидирует старые queued действия, запускает root-owned
  installed daemon `--stop`, затем останавливает owned Geph. Tray выходит только
  после успеха; отмена/ошибка остаётся видимой и допускает повторный Quit.
- `--stop` использует текущую fail-closed PF/процессную очистку, но сохраняет
  установку, настройки, learned state и immutable install attestation.
  Падение tray не превращается в намеренный Stop.
- Pure concurrency tests и mocked cleanup tests не являются физическим
  shutdown/install proof. На пользовательском Mac эта транзакция не запускалась.
- Отсутствие installed binary не проверяется непривилегированным `exists`
  внутри root:0700. Для действительно пустой установки разрешена только
  read-only admin-проверка отсутствия exact paths, launchd label, private PF,
  listeners и owned process paths. Любой остаток/неизвестное состояние — отказ,
  не попытка починки или запуска mutable bundle с root-правами.

### AUD-05 — ошибка launchctl / посланный сигнал считались отсутствием Geph (исправлено)

- `app-tauri/src-tauri/src/lib.rs`.
- Неуспех `launchctl print` больше не превращается в `absent`: принимается
  только точное not-found для app-owned label; неизвестный результат fail-closed.
- `geph_kill_owned` не стирает подтверждённое ownership после одного kill:
  требуется наблюдаемое исчезновение exact PID. Неуспех возвращается наружу.
  Внешние listeners не присваиваются приложению и не завершаются.
- Повторный Quit после исчезновения listener у ещё живого процесса сохраняет
  запись и возвращает ошибку, а не ложный успех. Повреждённая/нечитаемая
  существующая запись также не превращается в отсутствие процесса.

### AUD-06 — companion хранил незавершённые записи без предела (исправлено)

- `browser-companion/chromium/service-worker-core.js`, два test файла,
  `PRIVACY.md`.
- Потерянный terminal event оставлял запись в Map/storage.session после TTL;
  на старом HEAD контроль удержал 130 записей и вернул просроченную запись.
- Очистка только собственного namespace при каждой операции/восстановлении,
  валидация формы/времени и cap 128. При спящем worker очистка происходит при
  следующей операции, а не обещается точный wall-clock alarm.
- Worker/core 19 тестов прошли. Companion опционален, это не product routing fix.

### AUD-07 — Windows EOF/reset терялся при заполненной event queue (исправлено)

- `crates/slipstream-windows-adapter/src/direct_connector/windows.rs`.
- Одно `try_send` terminal event завершало worker с EventQueueFull; reducer
  получал payload, но не BackendClosed/StreamReset.
- Terminal/control событие сохраняется до освобождения bounded очереди;
  shutdown/cancel прерывает ожидание, включая Drop без читающего потребителя.
- Новая регрессия упала на исходном коде, затем 5 connector + 8 контрактных
  тестов и clippy прошли. Проверка на потоках/каналах, не physical Windows.

### AUD-08 — root health и QUIC decision имели слишком широкую IP authority (исправлено)

- `spike/tproxy.py`, `spike/test_tproxy_doh.py`.
- Healthy/challenge root IP подавлял другой IP того же host; host-only inflight
  делал то же для параллельных соединений. IPv4 success мог разрешать unknown
  QUIC для другого IPv4/IPv6.
- Root cache и inflight keyed `(normalized host, canonical destination IP)`;
  QUIC получает фактический destination из flow tuple. Owner epoch
  same-origin child сохраняется; доказанный exact-host Geph policy неизменён.
- Пять новых регрессий сначала падали; 75 затронутых тестов прошли.

### AUD-09 — slow-drip CDP чтение превышало абсолютный срок (исправлено)

- `app-tauri/src-tauri/src/browser_probe.rs`.
- HTTP/WebSocket чтение использовало повторяющийся socket timeout и могло
  получать отдельные байты дольше общего deadline. Частичный header после
  timeout также нельзя заново читать как начало нового кадра.
- Каждое чтение ограничено остатком абсолютного бюджета; частично потреблённый
  frame при обрыве/таймауте fail-closed, без ложного idle poll.
- Loopback slow-drip/partial-header regressions включены в 32 browser tests.
  Это localhost DevTools, не сокращение допустимого времени загрузки сайта.

### AUD-10 — escaped quote раскрывал хвост секрета в диагностике (исправлено)

- `app-tauri/src-tauri/src/diagnostics.rs`, регрессия в app tests.
- Redactor принимал escaped quote внутри token/password за конец значения.
- Закрывающая кавычка теперь учитывает escape, поэтому хвост также скрыт.
  Проверяется только искусственный secret fixture; реальные пароли не читаются.

### AUD-11 — download читал oversized архив полностью до проверки размера (исправлено)

- `scripts/materialize_chromium_headless_shell.py` и его test файл.
- `copyfileobj` не ограничивал сеть/диск pinned размером до EOF. Контроль
  прочитал 4096 bytes при reviewed length 64 и только потом отказал.
- Streaming читает максимум remaining + один sentinel byte; oversized chunk
  не записывается и не запускает бессмысленный повтор. Exact size/hash,
  canonical source, TLS verification и безопасная распаковка сохранены.
- Контроль сначала упал (4096 вместо 65), затем весь file: 8 passed.
  Существующий per-I/O timeout сохранён; абсолютный total download deadline
  не добавлен и не заявляется.

### AUD-12 — Launch at Login показывал успех после ошибки (исправлено)

- `app-tauri/src-tauri/src/lib.rs`.
- Старый обработчик превращал ошибку `is_enabled` в `false`, игнорировал
  результат enable/disable и выставлял желаемую галочку как «real new state».
- Неизвестное исходное состояние больше не разрешает изменение. После записи
  читается и проверяется фактическое состояние; ошибка сообщается пользователю,
  галочка при возможности восстанавливается из наблюдаемого состояния.
- Три mock-регрессии: оба направления, неизвестное исходное состояние/ошибка
  записи, отсутствие подтверждения/неизменённое состояние после записи.
  Реальная Launch-at-Login настройка пользователя не менялась.

## Проверки

- Создан чистый `.audit-venv`, зависимости установлены по hash-locked
  `spike/requirements.txt` с `--only-binary=:all: --require-hashes`.
- Локальный Python 3.13.0 отличается от CI 3.13.14; это не exact-CI qualification.
- `.audit-venv/bin/python -m pytest scripts -q`: **699 passed, 202 subtests**,
  26.99s; включает AUD-01, предшествует AUD-02 и изменениям параллельных агентов.
  Полный вывод: `output/audit-20260905/scripts-baseline.log`.
- AUD-02 после этой базы: `pytest scripts/test_release_readiness.py -q`:
  **10 passed, 9 subtests**. Остальные неизменённые script tests не повторяются.
- `.audit-venv/bin/python -m pytest spike -q`: **1152 passed**, 45.47s,
  `output/audit-20260905/spike-baseline.log`. Включает AUD-03/04, предшествует
  AUD-08. Единственное предупреждение — scapy использует deprecated FFDH
  symbols cryptography; оно не скрывается и не устраняется downgrade.
- После базы `pytest scripts/test_build_config.py scripts/test_release_readiness.py -q`:
  **63 passed, 14 subtests**, 7.29s, `scripts-focused.log`.
- После AUD-08 дополнительная AST-selection тестов, напрямую использующих
  изменённые cache/inflight/entrypoint symbols: **62 passed**, 1.63s.
- `pytest scripts/test_materialize_chromium_headless_shell.py -q`:
  **8 passed**, `materialize-green.log`; красный контроль `materialize-red.log`.
- Cargo baseline с `--locked`: core **41**, Windows adapter **241**,
  stack evaluation **40**, stack-effect evaluation **40**. После AUD-07
  `direct_connector::` **5**, direct_connector_contract + data_plane_contract
  **8**; core/Windows clippy clean.
- `node --test browser-companion/chromium/tests/{service-worker-core,service-worker,detector}.test.mjs`:
  worker/core **19** после исправления + неизменённый detector **10**.
- `swift test --package-path browser-companion/safari`: **7 passed**.
- App Rust: **148 lib + 32 browser tests passed**, `--locked --offline` с
  test-only `TAURI_CONFIG`, отключающим отсутствующие generated bundle resources.
  Production config не изменялся; это не упаковка и не installed app proof.
- После этой app-базы: `--lib redact` **4 passed**;
  `--test updater_installer_mechanics -- --test-threads=1` **3 passed**
  (disposable fixture + loopback, не установка продукта);
  `--lib quit` **5 passed** после обоих crossreview исправлений;
  `--bin slipstream-browser-probe partial_websocket_header_timeout_is_not_an_idle_poll`
  **1 passed** после устранения гонки старта fixture в тесте.
  Общий префикс воспроизведения:
  `env 'TAURI_CONFIG={"bundle":{"externalBin":[],"resources":[]}}' cargo test --locked --offline --manifest-path app-tauri/src-tauri/Cargo.toml`.
  Для исходной app-базы к нему добавлены `--lib --bin slipstream-browser-probe`.
- После окончательного Geph diff root дополнительно запустил `--lib geph`:
  **25 passed**, 5.58s; это affected-module, не повтор полного app baseline.
- AUD-12: `--lib launch_at_login` **3 passed**, 152 filtered out;
  `output/audit-20260905/launch-at-login-tests.log`. Независимый read-only
  review root-дополнения завершился без замечаний.
- `scripts/check_project_state.py`, `scripts/sync_version.py --check` и
  `git diff --check`: clean на промежуточной интеграции; финал фиксируется ниже.
- Новые результаты не переименовываются в физическую или релизную квалификацию.

### Зависимости (OSV, evaluation date 2026-09-05)

- Scanner 2.3.8 скачан через pinned policy и проверен SHA-256
  `a8cd6507b06239f463a7642430cfd2d154882f150f6e30cdc0653e28dfc34216`.
- App SBOM: **362 packages = 361 scanned + 1 integrity-only**;
  5 informational, 0 blocking, 0 accepted exceptions; policy pass.
  Chromium headless shell integrity-only не называется vulnerability scan.
- Canonical Geph 0.3.9 crate проверен reviewed digest/lock; metadata разрешена
  для aarch64 и x86_64 macOS с теми же features, что build workflow.
  Transitive SBOM **484 packages**, 12 advisories: **9 existing accepted
  exceptions**, 3 informational, 0 blocking. Исключения касаются
  aws-sdk-lambda 1.35.0, h2 0.3.27, rsa 0.8.2/0.9.10,
  rustls-webpki 0.101.7, sqlx 0.7.4 и истекают **2026-09-30**.
  Политики/исключения не ослаблялись и сроки не продлевались.
- SBOM/audit JSON и логи находятся в `output/audit-20260905/`.
  Источник SBOM — base commit `8cee1ca…`; manifests/locks в этом аудите
  не менялись. Локальный scanner pass не является GitHub attestation или
  exact-head release gate и не говорит, что зависимостей без риска нет.
- Дополнительно scanner проверил шесть оставшихся явных lockfiles без
  call-analysis и без рекурсивного обхода: четыре `crates/*/Cargo.lock`
  (41/60/27/60 package entries) и `spike/requirements-build.txt`,
  `spike/requirements.txt` (14/13). Во всех шести результатах список
  vulnerabilities пуст. Это 215 записей с возможными повторами пакетов, не
  215 уникальных зависимостей. `remaining-lockfiles-osv.json` и одноимённый log.

## Журнал

- 2026-09-05 14:40 UTC: сверены remote/main, PR #373/#374, локальные ветки;
  создан постоянный worktree и записан этот промпт до проверки подсистем.
- 2026-09-05 15:06 UTC: локальные baselines завершены, подтверждённые исправления
  интегрированы; закончены оба SBOM scan. Идёт финальный narrow и перекрёстный
  lifecycle review. Primary повторно проверен: тот же HEAD и только прежние
  untracked `.playwright-cli/`, `output/`; недоступные каталоги не затрагивались.
- Перекрёстный scripts review: новых дефектов в AUD-01/02/11 не найдено.
- Перекрёстный lifecycle review нашёл две ошибки первоначальной интеграции:
  Quit до установки не имел безопасной ветви отсутствия daemon; повторный
  Quit мог потерять запись ещё живого Geph, который уже закрыл listener.
  Обе устранены; `--lib quit` 5 passed. Повторный независимый review не нашёл
  новых замечаний. Ни одна из проверок не выполняла Quit на пользовательском Mac.
- Последний проход app UI дополнительно выявил ложное подтверждение Launch at
  Login (AUD-12); root исправил обработчик и добавил узкую проверку.
- 2026-09-05 15:22 UTC: source проход завершён, все 12 групп исправлений
  сохранены в `c060518d52ab888dfd9e92c7472a10dbabe8e555`. Финальные scoped
  tests и независимые reviews завершены; `git diff --check`, version sync и
  project-state continuity clean. Открытые платформенные границы перечислены
  ниже, они не скрыты формулировкой «всё работает».

### Воспроизведение выборок daemon (не требование повторять зелёную базу)

Из корня audit worktree, после hash-locked установки `.audit-venv`:

```sh
rtk proxy .audit-venv/bin/python -m pytest -q spike/test_tproxy_doh.py \
  -k 'preflight or bootstrap or quic or coalesced or slow_usable' --tb=short
```

Результат: 75 passed, 575 deselected. Дополнительная структурная выборка
52 test functions → 62 parametrized cases выполнялась следующим Python-кодом
через `rtk proxy .audit-venv/bin/python -c` (не сохраняет/не меняет файлы):

```python
import ast, os
from pathlib import Path
p = Path("spike/test_tproxy_doh.py")
tree = ast.parse(p.read_text())
symbols = {
    "_run_initial_route_preflight", "_run_bootstrap_asset_preflight",
    "_route_preflight_cache", "_route_preflight_inflight",
    "_quic_route_tcp_fallback", "_quic_initial_tcp_fallback_response",
    "_commit_preflight_owned_geph_proof",
}
names = [n.name for n in tree.body
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
         and n.name.startswith("test_")
         and any(isinstance(c, ast.Attribute) and c.attr in symbols
                 for c in ast.walk(n))]
os.execv(".audit-venv/bin/python", [".audit-venv/bin/python", "-m", "pytest", "-q",
          *[str(p) + "::" + n for n in names], "--tb=short"])
```

Для этих agent-проверок и части app/Rust/JS/Swift проверок отдельные raw log
не создавались; команды/результаты сохранены здесь из завершённых tool outputs.
Они не выдаются за подписанные/удалённые artifacts.

## Открытые границы

- Холодное восстановление физического Chrome/Safari не доказано.
- Установленный bundle не привязан к текущей сохранённой базе.
- Незакоммиченный хвост прежнего временного worktree требует отдельной
  проверки возможности восстановления; не заменять его предположениями.
- Legacy source-only install (tproxy.py + venv без frozen slipstreamd),
  partial installation и живой Geph без достаточного renewed ownership proof
  дают явную ошибку Quit. Они не объявляются pristine/остановленными и не
  исправляются небезопасным fallback. Это сохранённый fail-closed предел.
- Native Windows SCM/WFP/Wintun, физические macOS lifecycle/браузеры,
  production bundle/подпись и release gates здесь не выполнялись.
- Малые диагностические `voiceprobe`, `tcpsweep`, `tlsproxy`, `primes`
  инвентаризированы, но не прошли глубокую построчную проверку.

## После аудита: сверка перед bundle — 2026-09-05

Пользователь разрешил следующий этап. Повторная read-only сверка подтвердила
прежние primary HEAD `a22a698e809af5c1892e90ad462512f6719e56e7`, live main
`2780de4b3f5d77ab3852e46381b997c618bd5080` и PR #373
`513484ac43ae0348df06e61fca5af9d3105eb225` с прежними required checks. Эти checks
не являются CI аудита. Tracked source аудита до сверки — `c060518`, checkpoint
commit — `4ba3cd9f7247294d3ea06dd9a6b8e7bc5c7680bb`.

Обнаружен существенный continuity gap: старый graph index хранит metadata
незакоммиченных Quit-resume, TLS-stall и multi-address preflight symbols, которых
нельзя считать восстановленными из saved branch `8cee1ca`. Старый temp source
отсутствует, retained worktree index равен saved base. Оригинальные patch calls
этой задачи найдены в сохранённом transcript; отдельный recovery worktree
должен проверить возможность точного восстановления. Исторические JS/shell
команды не исполняются, учетные данные не переносятся, audit source не заменяется
непроверенной реконструкцией. Bundle/install отложены до сверки этого разрыва.

Сборочные prerequisites готовятся независимо: `npm ci --ignore-scripts` прошёл
(5 packages), materializer проверил pinned Chromium `151.0.7922.77`, архив
`98,976,279` bytes / SHA-256
`44a2ab4206fc5d5d33974adbc3fd2a80966e7a88167914794f524fa29a3d8e8e`, executable
SHA-256 `650f70c6d3e4a902d2ad6d91bb7cc15a08aa0720487b28324563b0f61c219058`.
Geph ingestion следует canonical CI contract для `geph-vendor-0.3.9-r1`, без
обновления до 0.3.10 и без использования локального SBOM как release attestation.
Ingestion завершился успешно: lightweight tag commit
`21fcaab9d35bdfdbdaacd28bf835acf7585318c3`, все восемь assets/API digests/checksums,
source/lock/license, SBOM и historical-policy audit, восемь SLSA и binary SPDX
attestations проверены. Подготовлен universal sidecar (`arm64`, `x86_64`),
`47,012,976` bytes / SHA-256
`39f5ecf8cfe2981061071d0802d79bf4853d2404adc05a27a8abe32ffae5aca4`.
Команды и полные логи — `output/post-audit-bundle-20260905/` (локальные данные,
не release proofs). Неизменённые полные тесты повторно не запускаются.

Установленный app только прочитан, не изменён. Его version `.23` не различает
локальные исправления; frozen daemon SHA-256
`4fbd59f26210ec5151909afe7a2ccfc25fbbba37b3f57fb6b03d2bb6b38cf7e3`, tray
`40130d34ddf55f5d510cd4664c005c9c6a8d639b351cb59882011f0a5bb7a410`.
Tray mtime — `2026-08-31T18:05:10Z`; это locator для истории, не source proof.
Текущий source всё ещё не заявляется равным этой установленной версии.

### Независимая проверка восстановленного Python source

Original successful main/child patch calls воспроизведены по времени в отдельном
durable `/Users/aiwaki/Developer/slipstream-recover-aikido-tail-full-20260905` от
`8cee1ca`. На этом промежуточном этапе Python и build patches применились,
оставшиеся Rust context gaps разбираются отдельно, включая исторический rustfmt.
Не исполнялись исторические JS/shell-команды; применяются только данные патчей.

Для независимого контроля прочитан PyInstaller CArchive установленного daemon
`4fbd59f2…` без его запуска. Pinned/hash-checked PyInstaller `6.21.0` используется
только как локальный archive reader. Восстановленный `spike/tproxy.py`, SHA-256
`011d913e308005aeced1ed75d3f13f0733a332e2f5e04fa4f03bdf64ffe50cb2`, скомпилирован
Python 3.13 без import/exec продуктового кода. Сравнение структуры code objects
исключает paths/line tables и только compiler-generated class `__firstlineno__`,
но сохраняет opcodes, остальные constants, names, flags и exception tables.
**Все 800/800 qualified names, включая модуль целиком, совпали**; missing/extra/
different списки пусты. Контроли инструмента проверили эквивалентность при сдвиге
source locations и обнаружение изменённой константы.

Это сильный контроль полноты Python-recovery, не побайтовое равенство исходных
файлов, не доказательство Rust source и не физическая проверка сайтов. Подробный
JSON: `output/post-audit-bundle-20260905/installed-python-comparison-full.json`;
reusable read-only helper: `compare-installed-python.py` в той же папке.

### Полный recovery baseline и controlled integration

Восстановление сохранено отдельно от исправлений аудита: commit
`ee8ba0e8f78b1070f41b54f75b06cd6e802c557b`, branch
`codex/recover-aikido-tail-full-20260905`. Coverage ledger учитывает 238 уникальных
подтверждённых вызовов (195 main + 43 child), 13 tracked files, все 54 вызова с
Rust-патчами. Восемь локальных поправок восстанавливают только доказанное
форматирование контекста; исторические команды и credentials не исполнялись.
Известных незакрытых recovery gaps нет. Python source остался тем же, что в
независимой проверке 800/800 выше. Это сохранённая история, не новый green test.

Controlled merge выполняется в `codex/codebase-audit-20260905`, сохраняя оба
родителя. Исторические continuous-root TLS, bounded multi-address/request-only
race, exact proof capability/epoch и per-attempt critical-child authority не
заменяются более ранней архитектурой аудита. То же относится к существующему
Quit-resume marker и единственному `DaemonLifecycleCoordinator`: второй
независимый lifecycle gate не накладывается. Недостающие audit fixes переносятся
отдельно, с узкой проверкой соответствующих изменений.

Обнаружен и исправлен дополнительный cold-build defect. Историческая automation
убрала npm pre-step и перенесла freeze в `beforeBundleCommand`, но pinned
`tauri-build 2.6.3` копирует glob resources уже в Cargo `build.rs`. На чистом
checkout отсутствующий `slipstreamd/**/*` останавливает компиляцию раньше этого
hook. В pinned CLI `2.11.3` порядок также однозначен:
[build setup, compile, then bundle](https://github.com/tauri-apps/tauri/blob/tauri-cli-v2.11.3/crates/tauri-cli/src/build.rs),
[beforeBundle inside bundle stage](https://github.com/tauri-apps/tauri/blob/tauri-cli-v2.11.3/crates/tauri-cli/src/bundle.rs).
Freeze/staging перенесён в `beforeBuildCommand`; второго freeze нет. Canonical
`build:local` / `build:release` сохраняют post-bundle identity verifier.
Standalone `tauri bundle` — только repack existing output, не поддерживаемый
fresh-source/release path. Dev hook отдельно и этим изменением не затронут.
Change-scoped `scripts/test_build_config.py`: **53 passed, 5 subtests passed**
за 40.15 s. Лог: `output/post-audit-bundle-20260905/build-config-tests.log`.

Python integration поверх recovery baseline меняет production ровно в двух
местах: `publish_cache=False` для unresolved critical child (включая parent
retry-cache), и argparse rejection для `--stop` вместе с `--install`,
`--uninstall` либо `--recover-network`. Recovered proof binding уже проверяет
canonical host/IP, exact capability и живую identity своего inflight epoch;
аудиторская более слабая замена ему не применяется. Обновлены/добавлены восемь
узких regression functions, включая exact-IP QUIC clearing, competing lifecycle
flags и hardlink witness при повторном stop. **13 passed in 12.35s**, exit 0;
лог `output/post-audit-bundle-20260905/python-recovery-audit-focused.log`.
Production `spike/tproxy.py` после этих двух изменений: SHA-256
`0800b616e3a7fb053c17f7b74ee45120ded4c611ca0ce8c9a7b22d50eb27d225`.
До интеграции он совпадал с installed compiled structure; эти две намеренные
дельты теперь проверены отдельно, не выдаются за прежнее совпадение 800/800.

Rust integration сохраняет recovered coordinator, terminal ownership/generation,
Quit-resume marker и весь более строгий Geph identity/signal/absence chain.
Перенесены root-owned installed `--stop` authority со строгими absence witnesses
для pristine state и verified Launch at Login initial/write/readback. Более
ранний, теперь не подключённый `src/lifecycle.rs` удалён как дублирующая модель;
его история сохраняется в audit parent `c060518`.

Первый scoped Rust pass: `quit` 9, `geph_` 34, `launch_at_login` 3,
`diagnostics_redacts_entire` 1, `queued_admin_action` 1, `terminal_operation` 2 —
всего 50 успешных выполнений. Это тестовая сборка с явно test-only resource
override, не доказательство product bundle. Логи: `rust-integration-*.log` в
той же output-папке. Unchanged full baseline не повторялся.

Независимый review поймал две ошибки ещё до commit/build/install этой интеграции.
Наличие любого каталога не давало права записывать Valid resume marker: root
stop мог отвергнуть wrong-owner/mode или partial install, а marker позже обходил
disabled/absent-label guard при startup. Дополнительно genuinely never-installed
Quit не доходил до root absence witnesses, поскольку отсутствующий label в
успешном `print-disabled` парсился как unknown и отклонялся слишком рано.

Исправление переиспользует существующий schema-3 install-attestation contract,
а не вводит новый privileged probe: enabled runtime перед marker требует
non-symlink root-owned0700 directory, valid bundled executable и
`!daemon_needs_install(bundled)` (exact bundle hash, root-owned bounded JSON,
immutable daemon witness/hardlink и exact LaunchDaemon plist). В root-only child
из user process не заглядываем. Partial/unknown/mismatched enabled installation
не получает marker. Более старый installed daemon против нового bundle здесь
намеренно fail-closed, как у существующего watchdog; mutable privileged fallback
не возвращается. Known-disabled runtime marker не получает. При отсутствии
installed directory label/bundle proof не запрашиваются и marker не пишется;
окончательный stop всё равно требует все root absence witnesses.

Добавлены whole-decision regressions, а не только тесты нового helper. После
этой дельты повторяется только affected `quit` selection. Исторический lib.rs
сам имел около 301 строк rustfmt diff; применён file-only rustfmt с
`skip_children=true`, без форматирования остальных модулей.

Финальная независимая проверка actual delta подтвердила обе коррекции и не нашла
других actionable findings в заданной границе. Финальный `quit` запуск дал
9 успешных behavior cases и один failure старого source-shape assertion, который
запрещал вообще упоминать bundled path. Он стал неверным после разрешённой
read-only attestation validation; исправлен только assertion, не production.
Его отдельный повтор прошёл: все 10 текущих Quit cases покрыты успешными
результатами этих двух запусков. Логи: `rust-integration-quit-final.log` и
`rust-integration-quit-root-authority-final.log`. Остальные 41 scoped checks не
повторялись. Финальные rustfmt check и `git diff --check` — exit 0.
Final lib.rs SHA-256:
`c40613341a7838776ce4cabe7207507174725baffbba9e8c141315967c06d6c6`.
Version sync check и project-state continuity contract также прошли. Дальше —
pin combined source commit и один canonical product build, без test override.
