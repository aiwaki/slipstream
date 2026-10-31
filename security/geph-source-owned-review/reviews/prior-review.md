# Bounded source review — AWS-LC candidate

**Результат: найден один унаследованный P2; разрешения на выпуск нет.** Новых дефектов FFI/RSA-протокольной адаптации в проверенной области не выявлено. Это не доказательство полной безопасности.

Кандидат: `SOURCE.json` SHA-256 `3c2cf6d98b19edf77d20f7105f20ddc509e9e1422dc137720acf7f103de51a6e`. Прочитаны все 10 embedded Rust-файлов и 3 manifest трёх пакетов, auth/bandwidth-вызовы и сохранённые точные тестовые материалы. Сборки, тестовые бинарники, сканер, сеть и реальные аккаунты не запускались.

## Конкретный дефект

`protocol-callsites/after/src/auth.rs:119` вычисляет активную Plus-подписку как `plus_expiry > now`, но строка131 удаляет токены при `plus_expiry > 0`. Для `now=2000`, `plus_expiry=1000`, cached Free условие удаления истинно, хотя уровень не менялся. Обе записи текущей/следующей эпох удаляются на133–134 **до** запроса нового ключа/подписи. Последующая ошибка broker лишает клиента существующего fallback. Условие такое же в before-body: дефект унаследован, не внесён миграцией RSA. Контрпример независимо подтверждён чтением условия и порядка действий; настоящий broker с таким timestamp и пользовательский сбой не воспроизводились. Отдельное исправление готовится только в новом output-кандидате.

## Проверенные свойства

- Два сохранённых upstream `.crate` совпали с provenance SHA; сверены все10 `original_files`. Все20 candidate files и3 descriptor digest совпали. `provenance.json` содержит точные пути, хеши, changed/unchanged-разбиение и копии исходников.
- First-party backend: `lib.rs` SHA `d6473d922426398c931dc1f0e9fb1c2d24ddb628d09bf09616c2bb6a2725994f`, `owned.rs` SHA `1c81e27303f63bbd733c39936a6103e65300b7f60c4906687e814174d46b064a`. Runtime текст совпал с сохранённым async prototype после удаления только `cfg(test)` кода. Проверены13 файлов pinned AWS-LC из локального cache против `.crate`, чей SHA совпадает с Cargo.lock.
- Bn/Ctx/Mont/Rsa имеют единственного RAII-владельца; borrowed n/e живут под Rc. Ошибки не публикуют частичную подпись. Native handles не пересекают await; OwnedPending переносит собственные байты и расходуется целиком. SecretBytes очищает live buffers перед освобождением.
- Основание `BN_mod_exp_mont` секретное, показатель публичный — это прямо разрешено pinned API. Для инверсии применяется blinded API. Импорт/экспорт inverse сохраняет фиксированную ширину; native PSS/hashing используется без собственной реализации. Salt0 emission и auto-salt verification сохраняют проверенный legacy contract. Известный2049-bit legacy blind-encoding bug сознательно не копируется.
- DER ограничен800 байт, SPKI допускает только rsaEncryption+NULL и полное потребление. Pending привязан к математическому ключу, Merkle — к точному response DER; expected epoch/root проверяются до публикации. Mizaru DTO bounds и wire field order сохранены. Broker runtime Rust унаследован без семантических изменений.
- Использованы ранее сохранённые18 primitive/compat,9 независимых corrected compatibility,6 async,6 adapter и11 synthetic actual-callsite tests. Сегодня они не повторялись. Хеши и границы повторного использования — в `backend-bindings.json` и `protocol-review.json`.

## Оставшиеся ограничения

Whole RPC body/JSON allocation по-прежнему происходит до DTO bounds. Не доказано восстановление уведомления после уже отправленного bandwidth INSERT при отмене до notify. Публичная ширина RSA сохраняет legacy2041..4096bits; это не новая политика2048minimum и не проверка всех свойств issuer modulus. Отсутствуют свежие side-channel/sanitizer/fuzz/ABI проверки, доказательство стирания стеков/регистров/всех caller copies и квалификация финального packaged RNG-abort recovery. Default AWS-LC allocator очищает heap; custom allocator hooks требуют отдельного доказательства.

Прежние тесты не равны проверке полного текущего SOURCE/lock/manifest aggregate. Нет новой advisory-оценки, production account/installed E2E или release clearance. SOURCE3c2 не содержит native_sqlite descriptor; итоговая combined inventory остаётся отдельной границей.

Полная семантическая разбивка, точные строки и хеши: `review.json`. Исходный кандидат, scripts, policy и docs не изменены.
