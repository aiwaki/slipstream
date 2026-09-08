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

### Incomplete Chromium staging caught by canonical verifier — 2026-09-08

Listener correction committed as `dd5be8e8d33d33e712ebdec639bbbd873a2a76b6`.
The clean-source `npm run build:local` compiled and produced app/DMG, but
`verify:bundle:local` correctly returned failure because packaged
`Contents/Resources/chromium-headless-shell/chrome-headless-shell` was absent.
Complete log: `output/post-listener-bundle-20260908.ju62L0/build-local.log`,
`BUILD_LOCAL_EXIT=1`. Context-mode's background launcher reported timeout while
the build continued; the process/log were checked instead of dispatching twice.
No incomplete artifact was installed or described as verified.

Both source staging and the bundle contained the same remaining 16 entries.
Production configuration still included Chromium resources and Geph/daemon
were packaged, so the test-only Tauri override/cache hypothesis is unsupported.
The source directory timestamp was Sep-6 02:58 local, with the resource files
dated Sep-5; this does not identify who removed the executable. The existing
hook only rebuilt the daemon and lacked an early Chromium prerequisite check.

The installed app and previous-app backups still contain the runtime. The
installed executable SHA-256 matches both the saved pinned materialization
evidence and manifest exactly:
`650f70c6d3e4a902d2ad6d91bb7cc15a08aa0720487b28324563b0f61c219058`.
`diff -qr` showed that executable was the sole difference between the complete
installed Chromium tree and source staging. Only that verified file was copied
back with metadata preserved. Rehash, full tree comparison and arm64 inspection
passed. No download, installed-app edit or private-backup mutation occurred.
Add a narrow fail-fast build prerequisite check before another canonical build;
the final whole-bundle verifier remains mandatory.

The existing materializer now has a read-only `--verify-only` path. Before
daemon freeze, the build hook requires a non-symlink runtime directory and
regular required files, executable permission, a bounded valid manifest whose
source fields match the pinned contract, and the executable hash recorded by
materialization. This is input-integrity validation, not a new independent
upstream attestation. It does not execute the browser, download, repair or
relax the final verifier. Test fixtures exercise the real guard without a
test-mode bypass, including rejection before the daemon build starts.

Focused command (prefix `rtk proxy`):
`.audit-venv/bin/python -m pytest -q scripts/test_materialize_chromium_headless_shell.py scripts/test_build_config.py -k 'verify_only or app_build_rebuilds_and_hash_checks_the_frozen_daemon or daemon_staging_preserves_previous_payload_before_swap' --tb=short`
passed **5 tests and 28 subtests**, 59 deselected, 2.39s. This result was returned
by the test tool session, not saved to a separate logfile; do not invent one or
rerun merely to create a log. Canonical Python 3.13 `--verify-only` also passed
on the restored real staging tree. `git diff --check` is clean.
Independent final guard review found no actionable blocker and confirmed the
failure occurs before daemon freeze without altering the previous stage.

### Corrected canonical bundle verified — 2026-09-08

Input guard committed as `dde2498bc9107999726d6f9709b7ac96c16a83b5` on top of
listener fix `dd5be8e`. The tracked tree was clean before and after one canonical
`npm run build:local` on this source. Test-only TAURI_CONFIG and stage failpoints
were unset. This is the justified build after restoring the evidenced missing
input, not a blind retry of unchanged failure. `BUILD_LOCAL_EXIT=0` and the
automatic verifier reports `overall=pass`, `build_chain.status=pass`, and
`installed.status=not_run`.

Evidence directory: `output/post-input-guard-bundle-20260908.aCajiw/`.
`build-local.log` contains the complete build/verifier JSON;
`dmg-verify.log` records hdiutil checksum VALID. Artifact identities:

| Artifact | SHA-256 |
|---|---|
| App tree | `b1690537bdc4b4270c0a8c3a02e475efaa24086b1f5b68017221feded5471d6c` |
| Fresh / staged / bundled daemon | `5af9020bbb42e931b4bb0e5a3e4bd04e725f6f45f416683bf9e2356f8cf58a95` |
| Tray executable | `3ef395cabd712d3d7206fb05fe0aa94a54d255a58dfb7f6a2b69b7c4e8bb6a8c` |
| Chromium | `650f70c6d3e4a902d2ad6d91bb7cc15a08aa0720487b28324563b0f61c219058` |
| Geph (bundled signed bytes) | `2ddb34a98e9643d2554b1e7e4c09ee4b995eefd89fd7ef5595430348c24ef5d6` |
| DMG | `f0cc23da8ac04b2a67757509cc3df9f93d023e269d1c7f7d214faf2092cf9d0e` |

App: `app-tauri/src-tauri/target/release/bundle/macos/Slipstream.app`.
DMG: `app-tauri/src-tauri/target/release/bundle/dmg/Slipstream_0.1.9-preview.23_aarch64.dmg`.
Fresh and staged daemon trees also match; the expected Tauri-materialized tree
matches the bundled daemon tree. App signature integrity is valid ad-hoc with
no team identity. No notarization or Gatekeeper compatibility is claimed.

No app replacement, privileged stop/install, marker removal, learning reset,
target browser navigation, external Geph mutation, push/merge, account-backed
workflow or soak occurred. The primary tracked checkout remains unchanged.
Installed `b172617` is still the old runtime. Next is its normal user-driven
Quit, complete owned-runtime absence proof and a new exact-bundle replacement
transaction, preserving the existing original backups and learning restoration
obligation. Site recovery and full Quit/Restart remain physical open gates.

### User Quit observed; fixed replacement staged — 2026-09-08

The user confirmed normal Quit. At 10:06:44 UTC bounded process inspection
found no owned Slipstream root daemon, tray or Geph; both exact launchd labels
were absent (exit 113), the root label was disabled, and status/status.tmp were
absent. The 46-byte UID502/mode600 Quit-resume marker remains unchanged.
Non-root lsof1080 was empty/exit1, which is explicitly not authoritative given
the evidenced listener-visibility defect. `sudo -n true` requires authentication;
root listener/private-PF absence must still be established before replacement.
The separate external Geph.app parent/client processes were not touched.

On audit HEAD `86766d2` (documentation after product source `dde2498`), the
canonical bundle was copied to `/Applications/.Slipstream.incoming-ywqzED.app`.
Complete verifier result is overall/build_chain pass, installed not_run, with
the exact app tree and daemon identities recorded above. Logs:
`output/workstation-replacement-20260908.ywqzED/incoming-verification.json` and
`incoming-verification.log`. The exact isolated Python3.13 tree-digest helper
used by the transaction also returned the expected app tree. No new product
tests or build were run for unchanged source.

New one-shot script:
`output/workstation-replacement-20260908.ywqzED/replace-exact-bundle.sh`.
SHA-256 `57715f811fd0c2f0d59db68be1230d85c062358d1377501bc0f51a9b75f6eb9e`.
`bash -n` passes; independent final read-only review found no concrete blocker.
The script has NOT executed. It requires root/no arguments,
checks exact old/new full app trees and signatures, old root daemon identity,
three stable privileged absence samples, and intact original backup boundaries.
It snapshots current runtime/configuration only into new root0700 private
storage, checks copies of the two learned-state files and metadata, and does
not reset live learning or alter the resume marker. A protected incoming copy
is reverified before final placement. Placement may roll back only before the
installer executes; an installer failure stops for inspection, never replay.
The installer runs from the final app path and must leave the exact new root
daemon hash. No tray/target navigation is launched by the script.

New recovery paths (must not exist before the first attempt):
`/Applications/.Slipstream.before-ywqzED.app` and
`/private/var/tmp/slipstream-replacement-20260908.ywqzED`.
The latter's install.log and runtime snapshot are private and must not be
exported wholesale. Preserve original `.Slipstream.previous-B5fQMm.app` and
root-private `slipstream-qualification-20260905.B5fQMm`; original learning
restoration remains outstanding. Never rerun the old Sep-5 installer/helper.

Live main `2780de4` and PR373 `513484a` remain unchanged; required CI
`32867878889` and audit `32867879962` are green only for that older PR head,
not this local correction. Primary checkout HEAD `a22a698` and its tracked
state are unchanged. Next is user-authenticated execution of the fixed command,
completion inspection, canonical installed proof and actual owned Geph start.
Ordinary Chrome/Safari critical-resource and full Quit/Restart gates stay open.

### Installed listener correction and first ordinary browser observations — 2026-09-08

After the user reported successful execution, canonical
`npm run verify:local-install` passed overall/build_chain/installed. Log:
`output/workstation-replacement-20260908.ywqzED/installed-verification.log`.
Installed app tree is `b1690537bdc4b4270c0a8c3a02e475efaa24086b1f5b68017221feded5471d6c`;
daemon attestation hash and fresh/staged/bundled daemon are
`5af9020bbb42e931b4bb0e5a3e4bd04e725f6f45f416683bf9e2356f8cf58a95`.
Schema3 install attestation is valid; its dormant/PF-false snapshot describes
installation time, not live PF. Unprivileged verification did not independently
rerun installed-root-file hash, listener-owner or kernel-PF checks. Live status
and exact root launchd program/PID agree; fresh StatusV2 is active/PF-ready.

Normal `open /Applications/Slipstream.app` started tray PID41298. At 10:20:47
UTC owned Geph PID41356 and its gui/502 launchd job were running, and StatusV2
reported up/owned=true/port_conflict=false. Root PID39797 now supplies the fresh
actual-descriptor witness for 127.0.0.1:1080 and [::1]:1080. The old Quit-resume
marker disappeared through product code, not a manual deletion. External
Geph.app PID854 and its PID874 client remain untouched and distinct. This
observably resolves the old installed startup boundary; it does not prove
any website recovery, cold cache or full new-bundle Quit behavior.

Ordinary installed Chrome was controlled through native UI, without proxy
flags, browser-profile reset, manual routing rules or page reloads. Capacitor's
homepage was visibly complete in the captured viewport, with real heading,
navigation, stylesheet layout and hero image. First loaded observation was
33s after navigation, interrupted by a Safari capture attempt; do NOT report
33s as actual load latency. This is a warmed/uncontrolled browser observation,
not an exact cold-load benchmark or all-resources network proof.

Aikido's page remained an empty shell/spinner beyond 45s. Its existing console
was opened after failure, without reloading; Chrome showed 162 errors. Visible
examples include `cdn.aikido.dev/assets/DeviceProtectionMacOsMdmInstallModal-Ct2yf_FB.js`,
`DomainChecksPage-J-tCOW6r.js` and `RepositoryOverviewRepoList-CPs80Lzw.js`, all
`net::ERR_CONNECTION_CLOSED`. The initial Network panel cannot retroactively
supply these requests; no reload was used to overwrite the failing attempt.
At 10:24:09 UTC root daemon was active, owned Geph still up/no conflict, two
active sessions and auto-geo-exit learned=1/pending=0. These aggregate values
do not identify which host was learned or explain the CDN decision.

Safari selection returned ScreenCaptureKit error -3811 before any target
navigation. It remains unverified. One Chrome state capture returned the same
tool error after Aikido navigation, but a subsequent read confirmed the exact
Aikido tab; the navigation was not repeated.

The private daemon log is `/var/log/slipstream.log` (root0600, 453361 bytes at
10:26 UTC); `sudo -n true` still requires user authentication. No credentials
were retrieved/replayed and no private runtime backups were opened. Use the
existing Copy Diagnostics admin fallback to obtain a fresh sanitized report;
the standard root-log tail is 80 lines, so absence from that tail is not proof
of an unexecuted preflight. If needed, obtain one scoped historical slice of
this failed attempt rather than repeated target navigations. The exact root
connect/TLS/send/read/classification or child-proof decision remains unknown.

Historical comparison pointers from independent read-only review:
`ROUTING_RESEARCH.md`, 2026-08-25 strict-denial physical validation, records
Chrome/Safari Aikido login on daemon `b66b7d5b...` with an already-learned shared
overlay, not cold discovery. The 2026-08-28 critical-child entry records an
incorrect UI-provenance gate; the 2026-08-31 continuous-root entry records an
earlier TLS-before-HTTP failure. Neither alone identifies today's cause.
No source correction, rebuild, full suite, soak or other site matrix was run.
Browser critical-resource recovery, full Quit/Restart and original learning
restoration remain open. Live main/PR373/required CI and primary checkout have
no relevant delta; prior PR CI still does not qualify local product `dde2498`.

### Fresh Aikido root evidence and missing child decision — 2026-09-08

The user's completed Copy Diagnostics action produced
`/var/folders/ys/sgldb5n55616m0lhykv24f280000gp/T/slipstream-diagnostics.json`
with mtime 10:31:37 UTC, 101037 bytes and mode0600. An exact private copy is
`output/workstation-replacement-20260908.ywqzED/diagnostics-20260908T103137Z.json`.
The 80-line bounded root-log tail includes the existing failed attempt; no
additional sudo read, browser navigation/reload or network probe was needed.

Decisive allowlisted root records (both exact-address/multiple-address-set):

| Time (+0500) | Host | Root outcome | Elapsed bucket | Wire bucket | Assets |
|---|---|---|---|---|---|
| 15:23:34 | app.aikido.dev | usable | ge5s | 4k_to_16k | 3 |
| 15:23:35 | cdn.aikido.dev | usable | 100ms_to_500ms | 4k_to_16k | 3 |

Both records have retryable=0, hard=0, safe_incomplete=0, tls_consensus=0,
wire_measured=1. Therefore these observations reached usable HTTP/root framing;
the old TLS-before-HTTP diagnosis does not describe them. The root record is
prepared after root observation but emitted only after the parent preflight's
finally block. It does not expose the child result. Owned Geph is up/owned,
no conflict; aggregate learned=1/pending=0 does not identify the learned host.

Source trace: `_select_route_preflight_bootstrap_asset` retains only the first
allowed cross-origin candidate, or one same-origin candidate, forgetting the
others. `_bootstrap_asset_preflight_blocking` treats a complete requested
0–65535 range as usable, not as full page/all-module completion. Same-origin
child allowance is still bounded by the parent's healthy budget; cross-origin
child receives its separate documented envelope. Cross-origin child also
requires the existing concurrency/window slot and independently resolved
public exact address. Any of these distinctions can matter; none is proven
to be the branch taken by this failed browser attempt.

The transient `_BootstrapAssetPreflightResult` is discarded. Only successful
owned-Geph learning is persisted; negative result and direct health cache are
not exported. StatusV2 exposes aggregates, not child admission, range outcome,
termination or proof rejection. Existing three-script tests make the selected
first file fail; they do not establish recovery when a selected prefix works
but other modules fail. **Confirmed defect: missing decision observability.
Unresolved: actual negative branch and routing cause of this Aikido attempt.**
A narrow allowlisted child diagnostic is being added without policy changes;
its synthetic tests are not a claim that Aikido is fixed. Preserve the page
and installed version until that source change is reviewed and qualified.

Separate privacy finding: the report also includes archived Geph text with
embedded connection-cookie fields. The current structured/text sensitive-key
lists omit cookie, and the text scanner does not handle escaped JSON keys or
whole collection values. The report must NOT be described as fully sanitized
or exported. Neither report nor actual values are committed/uploaded. The
original and private evidence copy are preserved locally. A separate small
sanitizer correction and synthetic-only tests are in progress; this is not
the Aikido routing cause. Do not read/dump archived Geph logs for this fix.

### Child-decision observability correction — source only, 2026-09-08

Local commit `fb19315` changes only `spike/tproxy.py` and
`spike/test_tproxy_doh.py`. `_run_bootstrap_asset_preflight` now wraps the
unchanged child owner and sends one bounded `route-preflight-child` record
after its cleanup. Internal blocking results carry fixed decision/direct/Geph
categories. Admission refusal, complete sample, incomplete EOF, idle timeout,
comparison/prerequisite refusal, commit rejection/success and cancellation are
distinguishable. While a worker result is unavailable its direct/Geph fields
are `unobserved`, not a false assertion that no probe started.

Only normalized bounded DNS hostnames, same/cross-origin relation and fixed
enum values enter the existing drop-only private diagnostic queue. No URL
target, path/query, address, hash, headers, body, exception text, capability or
exact timing is retained by this record. Formatter/sink failure cannot replace
the ordinary return, original exception or cancellation. Parent/root and child
cache/proof/deadline/concurrency/forgetting semantics are unchanged, including
the original empty-address result of a pre-probe abort. Root independently
reviewed the final production and test diffs; no remaining concrete regression
was identified. No new route, retry or domain rule was added.

Scoped verification from this worktree (tool results; no full suite):

```sh
rtk proxy .audit-venv/bin/python -m pytest -q spike/test_tproxy_doh.py -k 'bootstrap_diagnostic or cancelled_bootstrap_worker' --tb=short
# 41 passed, 739 deselected
rtk proxy .audit-venv/bin/python -m pytest -q spike/test_tproxy_doh.py -k 'bootstrap_diagnostic_formatter_failure or bootstrap_diagnostic_resolver_cancel or ((bootstrap or root_diagnostic or gzip_continuous_root_learns_only_exact_cold_child or full_ranged_root_learns_cold_child_before_exact_payload) and not bootstrap_diagnostic and not cancelled_bootstrap_worker)' --tb=short
# 25 passed, 1 failed, 757 deselected
rtk proxy .audit-venv/bin/python -m pytest -q spike/test_tproxy_doh.py::test_cross_origin_bootstrap_delayed_eof_gets_separate_geph_authority --tb=short
# 1 passed after fixing the pre-existing test spy signature
```

The one failure was an old `mint(host, now_unix_ms=None)` spy that did not
accept/forward the already-existing production `capability=` keyword. Only
its signature/forwarding was repaired; its proof assertions were preserved.
The 25 passing cases included the three later-added formatter/resolver-cancel
cases, so those were not rerun. Total: **67 distinct passing cases**; unchanged
green selections were not repeated. `git diff --check` passed. The module was
imported/executed by these tests; no separate compile/build was necessary.

This fixes the missing diagnostic, not the Aikido page. The installed daemon
is still `dde2498` and cannot emit the new record until a separately verified
bundle is installed. Do not interpret an old report without this record as a
new diagnostic failure, rerun the same old navigation for more evidence, or
claim physical browser/latency/Quit qualification from these synthetic tests.

### AUD-13 — opaque Geph credentials in Copy Diagnostics (fixed in source)

Outcome: **fixed in source** by local commit `a728100`; not rebuilt, installed
or claimed fixed in the user's existing report. Files:
`app-tauri/src-tauri/src/diagnostics.rs` and the import/four Geph-tail call sites
in `app-tauri/src-tauri/src/lib.rs` only.

Boundary: current/archive Geph stdout/stderr -> bounded log tail -> text/JSON
sanitization -> Copy Diagnostics clipboard/file export. Cookie/route-subtree
values must never survive into exported diagnostics; ordinary status, safe
metadata, root decision evidence, missing-log errors and private export-file
permissions must remain intact. The previous key list missed cookies, scalar
scanning could retain collection suffixes, and split-line export lost the
relationship between a multiline key and its value. This is independent of
the routing problem. No real private log/report was used by the implementation
or regression reviewers, and no real values were copied into fixtures/docs.

The `fix-finding` procedure required a fresh boundary investigation and one
fresh bypass/regression review. Root also independently traced both export
sanitization passes and inspected the final diff. The candidate's multiline
bypass was reproduced through the actual log-tail helper before correction
(`output/listener-resume-20260905/rust-cookie-multiline-before.log`). Fix:

- Redact whole structured cookie/route-subtree values; omit recognized opaque
  raw records instead of trying to retain a partially sanitized payload.
- Inspect the entire bounded window before max-lines slicing. If a sensitive
  value cannot be proven complete on its physical line, omit the tail.
- Use a Geph-specific wrapper for all four current/archive tails: after byte
  truncation, the opening key may be outside the 128KiB window, so raw Geph
  lines are omitted. Generic/root decision tails keep their existing bounded
  visibility. Structured Geph lifecycle/state and log availability metadata
  remain available. This loss of uncertain raw Geph detail is intentional.
- Scan identifier tokens once rather than repeatedly rescanning a long
  cookie-containing identifier; do not introduce quadratic scanning.

Ordered verification, from the audit worktree (shell wrappers captured output
in the logs below; these are the underlying Cargo invocations):

```sh
rtk proxy env 'TAURI_CONFIG={"bundle":{"externalBin":[],"resources":[]}}' cargo test --locked --offline --manifest-path app-tauri/src-tauri/Cargo.toml --lib diagnostic -- --test-threads=1
# 16 passed, 180 filtered out; library compiled
rtk proxy env 'TAURI_CONFIG={"bundle":{"externalBin":[],"resources":[]}}' cargo test --locked --offline --manifest-path app-tauri/src-tauri/Cargo.toml --lib redact_sensitive_text_handles_urls_yaml_and_json -- --test-threads=1
# 1 passed, 195 filtered out
rtk proxy rustfmt --check --edition 2021 app-tauri/src-tauri/src/diagnostics.rs
# pass
rtk proxy git diff --check
# pass
```

Final logs:
`output/listener-resume-20260905/rust-cookie-final-diagnostics-tests.log` and
`output/listener-resume-20260905/rust-cookie-final-existing-text-test.log`.
The Tauri resource override is for source-only tests, not bundle verification.
No packaging result is inferred from it. Source compilation and 17 focused
tests cover the actual tail/snapshot boundary, plain/escaped JSON, arrays,
multiline and truncated/keyless continuations, benign prose/metadata,
neighboring complete records, original YAML/URL/JSON redaction and private
export permissions. The synthetic leak no longer reproduces; legitimate
controls remain green. Initial green checks were rerun only after the reviewed
multiline/truncation correction changed their shared sanitizer boundary.
No new concrete bypass/regression remained after reconciliation and root's
final review. This is not a universal guarantee for arbitrary future log
formats or other producers; the Geph export path is the scoped boundary.

The original report/private copy and source logs remain unchanged. They are
still potentially sensitive and must not be uploaded or committed. Next
product step is a canonical bundle of the new source, separate authorized
replacement, then one Aikido observation with the new child-decision record.

### Authorized diagnostic bundle and staging — 2026-09-08

The user explicitly authorized building/installing the diagnostic changes and
one Aikido attempt. Product source changes remain `fb19315` and `a728100`;
the clean build source, including the authorization checkpoint, is
`dc2937bc887d47d4af14b0d3cea703ee13d67a1b`. Remote main `2780de4` and open
PR373/374/362 heads/checks were reconciled without drift. Prior PR CI does not
qualify this local source. The primary checkout was untouched.

One `npm run build:local` ran in `app-tauri`, with
`SLIPSTREAM_PYTHON_313=/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13`
and `TAURI_CONFIG`, `SLIPSTREAM_BUILD_STAGE_TESTING`, and
`SLIPSTREAM_BUILD_STAGE_TEST_FAILPOINT` explicitly unset. The background
context-mode call yielded a timeout response while its child continued; the
build was NOT restarted. Its log subsequently recorded `BUILD_LOCAL_EXIT=0`.
Automatic canonical verification passed overall/build_chain; installed status
was not_run. The 67 Python / 17 Rust passing affected cases were reused;
no unchanged tests, protected workflow or soak ran.

Evidence: `output/aikido-child-diagnostic-20260908.nBz5za/build-local.log`.

| Artifact | SHA-256 |
|---|---|
| App tree | `156680611337a40ac8fffcf5c66bb0d285f7dfa288ae671d71cacd03ea692c85` |
| Fresh / staged / bundled daemon | `7bef1eb8dc5d153ec2d234eb60681845e237e2177d52d90d8b8b8c25fd81456e` |
| Tray | `591d170ce7836da9d30785d6bd95d906f8d3b3daa74b80dce6f0a2a79a69761c` |

The bundled Chromium, Geph, browser worker and update watchdog match the prior
verified bundle values. The app has valid ad-hoc signature integrity and no
Developer ID/notarization claim. App and DMG were produced, but the DMG was not
used or independently checksummed: installation uses the verified app tree.

Copied the built app to the previously absent exact staging path
`/Applications/.Slipstream.incoming-nBz5za.app`. Re-ran the canonical verifier
at this new copy boundary with explicit fresh/staged daemon inputs; it passed
with the same tree/hash and installed=not_run. Evidence:
`output/aikido-child-diagnostic-20260908.nBz5za/incoming-verification.json`.
Tracked source remained clean before this documentation update.

Installed app/runtime remain unchanged. Read-only process identity showed
root daemon39797, tray41298 and owned runtime Geph81799; external Geph854/874
were separately identified and not touched. `sudo -n true` was unavailable.
CUA could list surfaces but two Slipstream selections timed out; a Chrome app
selection failed ScreenCaptureKit -3811 before any action/navigation. No
process was killed, no app Quit/replacement/learning reset occurred, and no
password from chat was reused. Next requires the user's ordinary Quit and
local authorization, a new exact one-shot replacement preserving all prior
backups, then installed verification/owned startup and one Aikido observation.

### Diagnostic replacement completed; awaiting one user navigation — 2026-09-08

After user-confirmed normal Quit, live inspection at 11:49:35Z showed no owned
processes, both launchd services absent (113), root label disabled, and no
status/status.tmp. External Geph854/874 were distinguished and untouched.
These nonroot observations were not substituted for privileged absence checks.

Created and independently reviewed the new one-shot
`output/aikido-child-diagnostic-20260908.nBz5za/replace-exact-bundle.sh`, SHA256
`53986e902973dff9639f12f0ae2f7ebaad6d58057fd7afe41e8411bb574b59ff`.
Its delta from the previous transaction pins the new exact old/new identities,
new paths, requires both older backup generations, and includes TCP1443 and
PF child-anchor absence alongside TCP1080 and PF filter/translation checks.
`bash -n` passed; no broad tests repeated. Main verified this matches the
production stop contract. Existing config/learning remain in place and are
privately snapshotted; no resume marker is removed manually.

Executed once through native `osascript` administrator authorization, without
passing or persisting any password. Execution completed exit0 with:
`Exact dc2937bc bundle installed; root daemon hash matches. Learning was not reset.`
The script creates the new previous app at
`/Applications/.Slipstream.before-nBz5za.app` and root-private recovery state at
`/private/var/tmp/slipstream-replacement-20260908.nBz5za`. Both earlier backup
generations are preserved. Do not replay this or any older transaction.

`npm run verify:local-install` completed exit0 and reports
overall/build_chain/installed pass. Evidence:
`output/aikido-child-diagnostic-20260908.nBz5za/installed-verification.log`.
App tree `156680611337a40ac8fffcf5c66bb0d285f7dfa288ae671d71cacd03ea692c85`
and daemon `7bef1eb8dc5d153ec2d234eb60681845e237e2177d52d90d8b8b8c25fd81456e`
match the build/staged proof. Schema3 attestation/witness are valid and bind
fresh active StatusV2 to exact live launchd PID2946. The attestation's dormant
PF snapshot is historical, not current runtime; StatusV2 reports PF applied/
enabled/rules_loaded. Verifier coverage is installed-unprivileged; its separate
live privileged kernel/listener/hash checks remain not_run. The transaction
proved its own pre-install absence and post-install root daemon hash.

Normal `open -a /Applications/Slipstream.app` started tray3774, then owned
Geph3834. At 11:57:52Z the owned LaunchAgent was running and StatusV2 showed
Geph up/owned=true/port_conflict=false, learned0/pending0. This aggregate does
not identify historical route retention; no manual learning reset occurred.

Chrome CUA selection still failed ScreenCaptureKit -3811 before interaction.
No browser navigation/reload occurred. User must perform the one ordinary
Chrome Aikido navigation and invoke Copy Diagnostics so the newly installed
child-decision record and visual outcome can be inspected. Aikido recovery,
Safari and full browser qualification remain unproven; no build or broad suite
should be repeated to work around this UI limitation.

### User Aikido observation after diagnostic installation — 2026-09-08

User reports opening Safari inadvertently before Chrome; both remain unusable.
The supplied Chrome screenshot shows `app.aikido.dev` with a loading spinner,
not a recovered page. At 12:02:14Z daemon2946 and owned Geph remained active
(up/owned=true/port_conflict=false, learned1/pending0). Aggregate learning is
not exact-host/page proof. The diagnostic file was still the old 10:31:37Z
export, so no new child decision can yet be attributed to this navigation.
Request built-in Copy Diagnostics without another navigation/reload. Preserve
the Safari-then-Chrome order; do not label this a clean isolated Chrome trial.
No source/runtime mutation, test or build was justified by the screenshot alone.

### AUD-14 — critical-child admission starved by retained parent epoch

Status: diagnosed in source and the fresh installed diagnostic record; source
correction and focused verification are recorded below. The installed bundle
still predates this correction. Fresh Copy Diagnostics mtime is
2026-09-08T12:05:26.300Z (generated
at 12:05:22Z), 16670 bytes, owner502/mode0600. Preserved exact private copy:
`output/aikido-child-diagnostic-20260908.nBz5za/diagnostics-20260908T120526Z.json`.
Only bounded root/child decision fields were exported into this audit; no raw
Geph logs, URLs, payloads, cookies or private runtime snapshots were printed.

Captured for parent `app.aikido.dev`, cross-origin child `cdn.aikido.dev`:

| Local time (+0500) | Child decision | Direct / Geph |
|---|---|---|
| 16:59:55 | concurrent_refused | not_started / not_started |
| 16:59:56 | concurrent_refused | not_started / not_started |
| 17:00:21 | window_refused | not_started / not_started |

Each corresponding root is usable with three extracted assets. Therefore
these failures occur before child direct I/O or Geph comparison; they are not
an observed failed Geph payload comparison or the old root TLS-before-HTTP
boundary. User navigation order was Safari then Chrome; logs are not enough
to assign individual entries to either browser or identify every competing
epoch/window consumer. The 80-line truncated tail spans16:59:55–17:04:56 and
contains14 root/3 child records. This is not a complete admission trace.

Current source: `ROUTE_PREFLIGHT_CONCURRENT_MAX=2`, window60s/max8.
`_run_initial_route_preflight` holds its `(host, exact-IP)` Future until its
finally block, including while awaiting `_run_bootstrap_asset_preflight`.
The cross-origin child resolves its independent exact IP, then checks the same
registry length/window and requests another opaque per-object epoch. Under
two concurrent parent owners, a child can therefore be refused even after
its parent's network observation has completed. Repeated root admission also
charges the same eight-entry window; refused child outcomes deliberately do
not mint a healthy/retry cache entry. That safety behavior must remain, but
can expose repeated root cost while the critical child never runs.

The retained epoch is needed for root coalescing and proof lifetime; removing
its map entry early would allow duplicate root work. The private child epoch
is needed to prevent evidence reuse across different critical objects; sharing
the parent's result/Future would conflate authority or resolve waiters early.
The next correction must distinguish worker admission from those lifetimes,
retain exact host/IP/object capability checks and cancellation drain, and
preserve both hard concurrent-worker and actual per-window observation bounds.
An uncharged child/doubled allowance or numeric limit increase is not a fix.

Local blame attributes the existing child capacity/window checks and private
epoch to recovered commit `ee8ba0e8f78b`; `fb19315` added the diagnostic labels,
not that refusal policy. This provenance does not date the original historical
regression beyond the recovered tree. No code fix or new tests were run during
this diagnostic step; one scoped regression should first capture simultaneous
parents/children, window boundary, exact proof isolation and cancellation.
Actual Aikido recovery, Safari qualification, full Quit/Restart and original
learning restoration remain open. No site reload/probe, new rules, runtime
change, full test suite, rebuild/install, workflow or soak ran in this pass.

#### AUD-14 source correction — 2026-09-08

The user authorized implementation after the diagnostic finding. The fix is
generic: no site rule or new denial/timeout authority. Root `(host, exact-IP)`
Futures remain pending for coalesced callers. A separate execution lease is
bound to the exact root epoch and original asyncio task; only after the root
candidate runner drains may that coroutine transfer its slot to its selected
critical child. The child still has a new opaque exact-address epoch and
private proof capability. Lease identity affects scheduling only, never proof
commit or direct/cache authority. Unmapped inflight entries count independently
and conservatively; finalizers remove only their own map entries.

Root admission charges one actual start and reserves one possible cross-child
start. Every admission checks recent actual starts plus live reservations
against the unchanged eight/60s cap; a borrowed child consumes its reservation
and records a new timestamp. Window expiry cannot erase a live reservation,
and cancellation/completion never refunds actual starts. The root releases an
unused reservation as soon as it knows there is no cross-child, or after
owned-worker drain on exit. Numeric concurrency remains two execution jobs;
the existing per-job address racing and direct/Geph budgets are unchanged.
Tradeoff: seven recent starts can refuse a new root because it cannot reserve
its possible child; this conservative reduction in root-only burst admission
is explicit, not a silent allowance increase.

The shared Python test fixture now snapshots/resets/restores lease state.
Focused existing selection passed **74 tests**, 709 deselected, in2.16s:
`rtk proxy .audit-venv/bin/python -m pytest -q spike/test_tproxy_doh.py -k '(route_preflight or bootstrap or cancelled_root or cancelled_coalesced or cancelled_strict_denial) and not install_bootstrap and not tgws_restart' --tb=short`.
Log: `output/aud14-focused-LKpVG3/existing-preflight-tests.log`.
New `spike/test_preflight_admission.py` adds **11 distinct synthetic cases**:
two concurrent roots each reach their independent critical child under cap2;
coalesced waiters remain pending; third execution is refused; live child
reservation survives window pruning without a ninth start; unused reservation
is released while actual root start remains; last unreserved credit can admit
a standalone child but not a new root requiring a child reservation; root and
child cancellation retain lease/epoch until worker drain; foreign-task,
wrong-parent-IP, stale-root, not-ready and already-used leases cannot start a
child probe or mutate counts/epochs/cache.

First command:
`rtk proxy .audit-venv/bin/python -m pytest -q spike/test_preflight_admission.py --tb=short`
reported5PASS/1FAIL in1.19s. The failing root-cancel fixture used an arbitrary
injected callback, which enters the pre-existing unshielded test-only adapter
rather than the production control/drain branch. Only the fixture was changed
to use the production probe identity with synthetic callback/resolver; no
production behavior was broadened to accommodate the injection.
Then only the corrected/changed/new cases ran:
`rtk proxy .audit-venv/bin/python -m pytest -q 'spike/test_preflight_admission.py::test_cancellation_retains_execution_until_worker_drains[root]' spike/test_preflight_admission.py::test_invalid_or_reused_child_lease_cannot_admit_work spike/test_preflight_admission.py::test_root_does_not_start_without_room_for_its_child_reservation --tb=short`
reported7PASS in1.03s. Four unaffected first-run passes were reused; total11
new cases and74 existing affected cases are green. Logs are private:
`output/preflight-admission-tests-20260908.sb88Nb/{pytest,pytest-guards}.log`.
AST parsing and `git diff --check` passed. Independent static review found no
production blocker in lease identity, admission limits, proof isolation or
cancellation cleanup. The previously green unrelated Python/Rust baseline is
reused; this does not replace exact-bundle or browser product qualification.

Live repository reconciliation before the patch: main`2780de4` unchanged;
PR373 OPEN/head`513484a`, required checks PASS; PR374 OPEN moved to`b1bf2a9`
without listed checks and remains excluded; PR362 remains diagnostic-only.
Primary`a22a698` and its pre-existing untracked directories are unchanged.
Installed exact diagnostic source remains`dc2937bc`; source correction is
local to the audit branch. Next is canonical build/equality before a separately
gated installation and fresh ordinary Chrome/Safari evidence. Do not replay
prior replacement transactions or erase learned state/backups.
No live network/browser request, build, installation, service restart, learning
reset, full suite, protected workflow or soak is part of this source correction.

#### AUD-14 exact bundle and replacement preparation — 2026-09-08

Following the user's readiness confirmation, the canonical local build ran
once on clean committed source `10e2cd6186303d89ad6f49905460e24d7afd1366`
and exited0 at13:54:20Z. The canonical automatic verifier returned overall
and build_chain PASS; fresh/staged/bundled daemon SHA-256 all equal
`bcaf262dae85ed82c1bdc7e0b837460f5fa3398b422f546d28ce2f78d6d098c8`.
Complete app tree SHA-256 is
`82b81cd9fc9e5070085db2ea1933d5c765766897ff2364ab208cbd7ad70c6a47`.
The full staged copy `/Applications/.Slipstream.incoming-dHZffB.app` also
passed the canonical verifier. Signature is valid ad-hoc, not notarized.
Evidence directory: `output/aud14-bundle-20260908.dHZffB`; build-run/exit
metadata, private build log, extracted verification JSON, and staged-copy
verification log are retained there. No unchanged tests or soak were rerun.

User performed normal Quit before replacement. At14:02Z, read-only inspection
found no owned process, both root/owned-Geph jobs absent, root label disabled,
and status/status.tmp absent; external Geph854/874 were left untouched.
The newly reviewed script `replace-exact-bundle.sh` in that evidence directory
has SHA-256 `b046c0aca303fdf745de420c68715455dd7b7f4c0afce1c49ab5d2f976db40ba`.
`bash -n` passed and the parent reviewed its full contents and exact delta
against the already-used nBz5za transaction. Changes bind the new identities
and unique dHZffB paths and require preservation of all three prior backup
generations. Stable privileged service/process/1080/1443/PF absence, protected
incoming verification, current private learning snapshot, and fail-closed
installer/rollback boundaries remain unchanged. Execution and browser proof
are still pending; these build checks do not establish Aikido recovery.

#### AUD-14 installation result — 2026-09-08 14:06 UTC

The user completed normal Quit and native macOS authorization. The reviewed
dHZffB transaction ran once and exited0, reporting exact10e2cd6 installed and
the root daemon hash matched. All previous backups plus the new dHZffB
app/runtime/current-learning snapshot remain retained. No password was saved
or replayed; no learning reset or external Geph mutation was requested.
Do not rerun the transaction or any earlier generation.

`rtk proxy npm run verify:local-install` then exited0 with canonical overall,
build_chain and installed PASS. Built/installed app tree82b81cd9... and daemon
bcaf262d... match; schema3 install witness is valid and exact launchd PID86054
matches fresh active StatusV2. The install-time attestation's dormant/PFfalse
is historical install evidence, not current runtime state. Independent
privileged kernel PF/listener checks remain not_run in this unprivileged
verifier; pre-install privileged absence and final root daemon hash were
checked by the successful transaction. Full canonical result is retained at
`output/aud14-bundle-20260908.dHZffB/installed-verification.log` (mode0600).

The app was opened normally from `/Applications/Slipstream.app`: tray86978
and owned Geph launchd87038 run. StatusV2 at14:05:55Z shows daemon86054 active,
local engine ready and Geph up/owned=true/port_conflict=false. No browser
success follows from these checks. The next user action requested is one
ordinary Chrome Aikido navigation and built-in Copy Diagnostics, with no
repeat reload, rule insertion, cache/profile reset or proxy launch flags.
Fresh child admission/proof evidence and ordinary Safari result are pending.
