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

### Canonical local build — 2026-09-05 16:48 UTC

Controlled merge зафиксирован как
`b172617b105b3cab758288ec1bd686b4da94fef5` (parents: audit
`84873f2e89d44acc7813b230691ca47a0c9d760f` и recovery
`ee8ba0e8f78b1070f41b54f75b06cd6e802c557b`). До и после сборки tracked tree
чистый; это точный source SHA артефактов ниже, не последующего docs-only commit.

Из `app-tauri` выполнен один `npm run build:local`, с Python 3.13.0 по точному
пути `/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13` и без
`TAURI_CONFIG`/stage-test overrides. Один `beforeBuildCommand` создал fresh
daemon, атомарно staged его, затем Cargo/Tauri собрали tray, helpers, app и DMG.
Команда завершилась exit 0. Автоматический `verify:bundle:local` дал
`overall=pass`, `build_chain=pass`, coverage `build-chain, artifact`,
`installed.status=not_run`. Повторного freeze или неизменившихся тестовых suites
не было. Python 3.13.0 — локальная сборка; это не release CI с pinned 3.13.14.

Артефакты в `app-tauri/src-tauri/target/release/bundle/`:

| Объект | SHA-256 / результат |
|---|---|
| Fresh = staged = bundled daemon | `3d86a086ec9cd171ea4f67a861e8127d6f1c1dddc27ba8e028a22e19ea913a22` |
| Fresh = staged daemon tree | `9fd3d7bcbe339fd2f6f291c98da98cdbd7e01f87a96cdea861b5d3ff0c87483e` |
| Materialized = bundled daemon tree | `eedda9f4e63a9fffa835a1d74de7b2fa6d30cd01a2bcf4eff88a261ba7771589` |
| `macos/Slipstream.app` tree | `0baa30fc54851f2eab1b250b08d4005fe8e20389a5dc428bc27e0413f5637b16` |
| Tray | `08459feb32ab41400448861c25198676cd5cd561aaa9c7355cfa035a722c5dae` |
| Browser probe | `dda683ded1a1bdc44ad3d4d90f761158f6459e9015b2d34c5c9755863fdf2882` |
| Update watchdog | `89610929189e8753cc697c4790e6ee0ee3b9b4e66b807ac21305eb04ee2fef52` |
| Bundled Geph after Tauri re-signing | `2ddb34a98e9643d2554b1e7e4c09ee4b995eefd89fd7ef5595430348c24ef5d6` |
| Chromium | `650f70c6d3e4a902d2ad6d91bb7cc15a08aa0720487b28324563b0f61c219058` |
| `dmg/Slipstream_0.1.9-preview.23_aarch64.dmg` | `33aa0da4b7b92570f1f38fddd6a4381742ad01e6a0116f5a33f3657575230489` |

DMG: 147,699,648 bytes; отдельный `hdiutil verify` — exit 0, checksum VALID.
Bundle identity `dev.slipstream.tray`, version `0.1.9-preview.23`, signature
valid ad-hoc, Team ID отсутствует. Нотариализации нет; совместимость с
Gatekeeper не заявляется. Local version label не означает опубликованный релиз.

Полный verifier JSON находится последней строкой
`output/post-audit-bundle-20260905/build-local.log`; SHA-256 лога
`bd9f33ee6e895fc6629d2d84c657338a360b3c3261b4ff6cc43b9c8a1b432efc`.
Лог целостности DMG: `output/post-audit-bundle-20260905/dmg-verify.log`.
Исходный primary checkout остался на `a22a698` с прежними untracked diagnostics.
Installed tray и daemon по read-only hashing по-прежнему `40130d34…` и
`4fbd59f2…`; `/Applications/Slipstream.app` не заменён.

Открытая следующая граница — установка и физическая квалификация. После
разрешённой установки точного bundle нужен `npm run verify:local-install`,
затем ordinary Chrome/Safari с проверкой полной страницы и критических ресурсов
(Aikido/Capacitor/Weather/StarrToy), фоновых соединений, медленного, но
прогрессирующего direct path и явных tray Quit/Restart. HTTP 200, один
успешный root, скелетоны Weather и тёплый learned route не являются успехом.
Quit/Restart сохраняют `/var/run/slipstream-autogeph.json`, поэтому сами по себе
не создают cold baseline. Не найден документированный безопасный workstation
reset CLI: отдельный backup/reset/restore требует согласованной транзакции,
либо используется действительно холодная disposable среда. Ничего не удалялось.
`live_site_release_smoke.py` и packaged lifecycle drivers — protected/disposable
CI tools, не готовые команды для primary workstation. Ни установка, ни
сброс learned state, ни физические пробы, ни protected workflow/soak/release
на этом этапе не запускались. Remote CI и audit должны отдельно квалифицировать
новый PR head; прежние green runs не относятся к `b172617`.

### Authorized workstation transaction — preparation, 2026-09-05

User explicitly authorized installation plus temporary learned-route reset,
with private backup and restoration. After the user selected old tray Quit,
old tray PID 77991 and root daemon PID 79095 disappeared; the exact root label
is absent and disabled. This is observed old-version shutdown, not qualification
of the new Quit implementation. The process at
`/Library/Application Support/geph/bin/geph5-client` belongs to the separate
`/Applications/Geph.app/Contents/Resources/geph` parent (started Aug 26), not to
Slipstream's private bundled Geph. No external Geph process/service was changed.

The original app was copied to
`output/workstation-qualification-20260905.B5fQMm/previous-Slipstream.app`;
tray/daemon hashes remain `40130d34…` / `4fbd59f2…`. Incoming app was copied to
`/Applications/.Slipstream.qualification-B5fQMm.app`. Complete verifier output
is `staged-app-verification.json` in the same output directory: overall and
build_chain pass, exact app tree `0baa30fc…`, installed not_run.

The new operational `learning-transaction.sh` has only prepare/reset/restore:
require absent exact tray/root/owned-Geph processes and services, disabled root
label, absent proxy listener and empty private PF rules; snapshot the two exact
learning files with original presence, bytes and metadata; preserve experiment
files instead of deleting them; restore original TTLs unchanged. Runtime backup
also protects tgws-secret against installer rollback and stays root-private.
Independent review found a fixed staging-name retry trap in restore; corrected
to unique staging, with all original copies verified before moving live files.
The reviewed helper passed shell syntax checking. No product code changed.

The one-shot `install-exact-bundle.sh` verifies old/new critical hashes and
signature, prepares the private backup, resets only the two learned files,
preserves the actual old app under `/Applications/.Slipstream.previous-B5fQMm.app`,
places the new app at its final path and invokes that final frozen `--install`
(never the checkout copy), then verifies the root daemon hash. Installer failure
preserves backups and a private log and must be diagnosed without blind retry.
The old attestation/PID/PF ownership are not restored as configuration.

Administrative authorization remains pending. `sudo -n` required authentication;
a PTY Password prompt was not connected to the app terminal panel, so it was
cancelled. Native Terminal automation was unavailable. No root backup, reset,
installation or physical target navigation has occurred yet. The next action
is a user-run exact installer command, followed by installed identity and cold
status checks. Do not export `/private/var/tmp/slipstream-qualification-20260905.B5fQMm`:
it is a private recovery directory, not a diagnostic artifact.

### Authorized installation outcome — 2026-09-05 17:11 UTC

User ran the exact one-shot installer. `npm run verify:local-install` completed
with overall/build_chain/installed pass; installed app tree `0baa30fc...`,
daemon `3d86a086...`, valid schema-3 attestation and fresh active root PID 11973.
Full machine-readable output is the final line of
`output/workstation-qualification-20260905.B5fQMm/installed-verification.log`.
Verifier privileged runtime checks are separately `not_run`; do not imply
independent kernel PF/listener ownership verification from the non-root result.
The immutable install-time dormant/PF-inactive attestation fields are not live
status: current StatusV2 is active. Original backup is present root-private
0700; actual old app remains under `/Applications/.Slipstream.previous-B5fQMm.app`.

New installed tray PID 13022 launched, but Geph is off, owned false, no owned
LaunchAgent. User setting enabled is `1`; old Quit-resume marker remains.
Setup permits resume for a Valid marker and intentionally blocks Geph during
unresolved resume. With exact installation and explicitly enabled label,
request_daemon_install returns false without a new OS authorization request.
No osascript/authorization process was observed. No target
navigation has started, and this is not yet a routing failure or browser pass.
Auto-Geph learned/pending are zero; some unrelated ambient local strategies
exist. Persisted target-key absence alone cannot prove RAM-cold probes.
External Geph remains untouched. Learning restoration remains mandatory after
the authorized qualification transaction. Live main and PR #373 are unchanged;
their old CI does not qualify this new source.

Read-only startup diagnosis isolated a failing predicate in lib.rs:1267:
`listener == Some(status_pid)` is false because listener_pid(1080) returns None.
Fresh status, heartbeat, all PF readiness flags, root PID11973/executable and
enabled label were checked; the marker is not cleared before this full gate.
Non-root lsof exits1 empty; netstat TCP exits0 with empty stdout/stderr. A
bounded loopback-only Node listener on ephemeral59579, PID19582, confirmed
netstat is empty even for a same-user socket while lsof correctly returns19582.
The diagnostic socket was closed immediately; no target or external connection
was made. netstat is the genuine system Mach-O, and its interface output works.
Thus its TCP fallback is unusable in this observed environment; this does not
yet independently prove the root daemon's actual listener state. A root
read-only lsof exact1080 is the next discriminator. sudo -n requires user
authentication. No marker deletion, privilege-policy change, production edit,
rebuild, unchanged suite or browser probe was attempted. Tray stdout/stderr are
/dev/null; bounded process sampling shows a normal event loop, not pending auth.

### Proven resume blocker and narrow correction — 2026-09-05

The user supplied privileged lsof output showing the exact installed root
PID11973 with FD19 IPv6 `[::1]:1080` and FD22 IPv4 `127.0.0.1:1080`, both
LISTEN. This independently distinguishes missing unprivileged visibility from
a missing daemon listener. The tray's checked Enable Geph menu item is only
configuration; Geph remained off because resume could not prove listener PID.

The correction adds `daemon.listener_ownership` to each active root heartbeat:
schema1, current PID, same-generation millisecond sample time and actual
loopback socket endpoints. The producer queries retained server socket FDs
(`getsockname`, stream type, accept/listen state, no reuseport), not configured
addresses or old health results. It drops authority on close/error/shutdown or
non-root/inactive publication. Status publication uses an exclusive temporary
FD, descriptor identity/mode checks and atomic replace.

The daemon-only Rust reader opens the fixed status path nofollow/nonblocking,
reads at most64KiB, checks root owner/nonwritable regular single-link file and
stable descriptor metadata, and requires nonfuture file/heartbeat/sample times
within6s, matching PID, active phase and ready PF. Existing runtime directory
metadata is `/private/var/run` root:daemon0775; only that exact root/GID1/mode
combination is accepted as a writable-parent exception. Other ancestors and
the file itself remain strictly checked. The daemon group may deny access or
rename an existing root-authored inode within the already bounded snapshot
window, but cannot mint a UID0 payload or change its readonly content/mtime.
No second status file/service/cleanup protocol or privilege grant is added.

Only the two resume gates use this witness if system listener lookup is None;
an observed different owner is never overridden. Existing live owned-process,
exact installation/attestation, enabled label, PF and lifecycle-lock checks
remain mandatory. This is bounded fresh root-authored evidence, not a claim of
continuous kernel observation or absolute prevention of every PID reuse race.
Generic Geph ownership, stop/uninstall, routing and learned-state logic are
unchanged. Original private backup and restoration obligation remain intact.

### Resume checkpoint and targeted validation — 2026-09-08

The preserved Rust consumer passed 11 `daemon_listener::tests`; the two-callsite
integration passed 5 `quit_resume` tests (logs in
`output/listener-resume-20260905/rust-witness-tests.log` and
`rust-resume-tests.log`). Those source files are unchanged since that evidence.
The Python listener/status selection passed 21 tests and failed two real-socket
cases, with 693 deselected (`python-tests.log`). The failure is specifically
Darwin `getsockopt(SOL_SOCKET, SO_ACCEPTCONN)` returning ENOPROTOOPT/42 for both
bound and listening sockets; stream type and reuseport probes work. The next
correction must obtain actual kernel LISTEN state using a supported Darwin
query, remain fail-closed on errors, and preserve closed/bound-only negatives.
No unchanged full suite, Rust selection, protected run, soak or reinstall is
needed to investigate that platform-specific predicate.

At 2026-09-08T09:33:56Z main remained `2780de4b3f5d77ab3852e46381b997c618bd5080`;
PR #373 remained open at `513484ac43ae0348df06e61fca5af9d3105eb225`, with exact
CI `32867878889` and dependency audit `32867879962` successful, attempt 1.
Required checks remain green but do not qualify this local correction.
PR #374 remains unrelated. Primary tracked state is unchanged at `a22a698`.

The Darwin correction now queries `IPPROTO_TCP/TCP_CONNECTION_INFO` (0x106),
the installed SDK's 112-byte `tcp_connection_info` prefix, and requires first
byte `tcpi_state == TCPS_LISTEN` (1). Real ephemeral IPv4 and IPv6 sockets
returned state 0 while bound and state 1 while listening. Closed descriptors,
unsupported queries, missing constants, malformed/short replies and all other
TCP states fail closed. Other platforms retain their existing SO_ACCEPTCONN
check. No product listener, network route or target website was touched.

The two prior failures plus 24 helper cases pass (26 tests). The complete
affected producer selection is **47 passed, 693 deselected**, 0.38s; log:
`output/listener-resume-20260905/python-darwin-tests.log`. Command:
`.audit-venv/bin/python -m pytest -q spike/test_tproxy_doh.py` with the bounded
listener/kernel-listener/status-atomic/status-heartbeat/startup-status/
PF-teardown/core-status selection; no whole suite was rerun. Rust source is
unchanged and reuses the 11 + 5 passing results. `git diff --check` is clean.
At 09:35 UTC the installed old daemon still had PID11973 and a fresh active
heartbeat; tray PID13022 and the old 46-byte private resume marker remained,
and internal Geph was off/unowned. External Geph processes were identified
separately and left untouched. This is not installed correction/browser proof.

Independent final source review found no actionable blocker in the Darwin
kernel-state helper, heartbeat regeneration, producer/consumer schema and
timestamps, or the two lifecycle-locked fallback call sites. Visible conflicting
owners still veto readiness; fixed-path root-file authentication, freshness,
PF and exact process/install checks remain. Review and ephemeral socket tests
do not qualify the installed application, ordinary browsers, or full Quit.
