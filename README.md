<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/slipstream-banner-dark.png">
  <img alt="Slipstream — тихий обход цензуры для macOS" src="docs/images/slipstream-banner-light.png" width="100%">
</picture>

**Русский** · [English](README.en.md)

[![platform](https://img.shields.io/badge/платформа-macOS%20(Apple%20Silicon)-000000?logo=apple)](#установка)
[![license](https://img.shields.io/badge/лицензия-MIT-blue.svg)](LICENSE)
[![build-geph](https://github.com/aiwaki/slipstream/actions/workflows/build-geph.yml/badge.svg)](https://github.com/aiwaki/slipstream/actions/workflows/build-geph.yml)
[![build-app](https://github.com/aiwaki/slipstream/actions/workflows/build-app.yml/badge.svg)](https://github.com/aiwaki/slipstream/actions/workflows/build-app.yml)

</div>

---

Провайдеры в России ломают половину интернета: тормозят YouTube, рвут Discord,
подсовывают левый DNS, а до ChatGPT с Claude вообще не достучаться. Slipstream
всё это чинит — тихо, в фоне, прямо на маке. И не гонит весь трафик через
далёкий сервер, как обычный VPN — за границу уходит только то, что иначе не открыть.

Поставил, один раз вбил ключ Geph — дальше оно само разбирается, кому что нужно.
Ни расширений, ни прокси в каждой программе, без лишних кнопок.

> [!NOTE]
> Ранняя версия. Пока только macOS (Apple Silicon), настроено под сети РФ.

## Интерфейс

<p align="center">
  <img src="docs/images/slipstream-menu-composite.png" alt="Меню Slipstream: выбор выхода Geph, прокси для приложений, автозапуск, лог и обновления">
</p>

## Что чинит

| Сервис | Как идёт |
|---|---|
| Discord | чат, серверы и голос через локальный десинк |
| YouTube | локально, без бесконечных подгрузок |
| ChatGPT и Claude | только они уходят через зарубежный выход Geph |
| Telegram Desktop | через встроенный MTProto-over-WebSocket прокси |
| Остальное заблокированное или замедленное | автоматически выбирается локальный обход или туннель |

## Чем отличается от VPN

Обычный VPN гонит через сервер вообще всё — и медленно, и незачем. Slipstream
делит трафик:

| Трафик | Куда идёт | Почему |
|---|---|---|
| Российские сервисы | напрямую | банки, госуслуги и местные сайты не видят заграничный айпи |
| То, что ломает DPI | локально через десинк | айпи остаётся русским, задержка минимальная |
| То, что не пускает русские айпи | через Geph | зарубежный выход нужен только там, где иначе никак |

Быстро, где можно. В обход — только где иначе никак.

## Как устроено

| Слой | Где работает | Что делает |
|---|---|---|
| Десинк | на твоём Mac | режет TLS-хендшейк, кидает короткоживущие пакеты-обманки, использует DoH |
| Geph | локальный клиент + сеть Geph | туннелит только гео-заблокированные сервисы |
| Telegram-прокси | на твоём Mac | даёт Telegram Desktop локальный MTProto-over-WebSocket вход |

<details>
<summary>Схема маршрутизации</summary>

```
                 ┌─────────────────────────── твой Mac ───────────────────────────┐
   любая         │  прозрачный перехват :443 (pf)                                  │
   программа ──► │        │                                                        │
   (браузер,     │        ├─ российский хост? → напрямую, не трогаем               │
   Discord,      │        ├─ ломают по DPI?   → 1) ДЕСИНК (локально, на месте)     │
   Claude…)      │        └─ режут по гео?    → 2) ТУННЕЛЬ GEPH (выход за границей) │
                 │  Telegram Desktop ───────► 3) TG-WS-ПРОКСИ (локальный MTProto)   │
                 └────────────────────────────────────────────────────────────────┘
```

</details>

Три штуки, каждая занимается своим:

1. **Десинк** — локально дурит DPI-фильтр: режет TLS-хендшейк на куски и кидает
   пакеты-обманки с коротким TTL (идея из zapret / byedpi), плюс DoH против
   подмены DNS и отдельная дорожка под голос Discord. Айпи не трогает вообще.
2. **Geph** — это VPN; мы взяли его за цену/качество (открытый, [geph.io](https://geph.io),
   внутри `geph5-client`). Выводит за границу **только** то, что режут по гео.
   Страну выбираешь сам.
3. **tg-ws-proxy** — локальный прокси ([Flowseal](https://github.com/Flowseal/tg-ws-proxy)),
   гонит Telegram по вебсокету мимо блокировки IP дата-центров.

Десинк и Telegram-прокси — целиком у тебя на машине. Geph — готовая сеть, тебе
нужен в ней только аккаунт.

## Установка

1. Скачай `Slipstream.app` из [релизов](https://github.com/aiwaki/slipstream/releases) и кинь в «Программы».
2. Запусти. Один раз спросит пароль — чтобы поставить фоновую службу. Дальше делает всё сам.
3. В меню (иконка в строке меню):
   - **Geph → Account…** — вставь ключ своего аккаунта Geph (бесплатного хватает).
   - **Geph → выбери выход** — город или **Automatic**.
   - **Connect Telegram Proxy** — направит Telegram на встроенный прокси.

Готово — дальше оно само.

> [!TIP]
> Первая сборка пока не нотарифицирована Apple. Если macOS ругается на скачанное
> приложение, открой его через правый клик → **Open**.

## Собрать самому

Нужны Rust, Node, Python 3 и Xcode command-line tools.

```bash
# фоновая служба, которую приложение кладёт внутрь .app
cd spike
./build_daemon.sh
cd ..
rm -rf app-tauri/src-tauri/slipstreamd
cp -R spike/dist/slipstreamd app-tauri/src-tauri/slipstreamd

# приложение в строке меню
cd app-tauri
npm ci
# для чистого локального релиз-билда нужен geph sidecar:
# app-tauri/src-tauri/binaries/geph5-client-aarch64-apple-darwin
npm run tauri build

# фоновая служба (десинк + роутинг) — приложение ставит её само,
# но при разработке можно вручную из корня репозитория:
cd ..
sudo python3 spike/tproxy.py --install
```

Встроенный `geph5-client` собирается из исходников прямо в CI
([`build-geph.yml`](.github/workflows/build-geph.yml)) — всегда свежий, без
протухших бинарников. CI сам кладёт его в `app-tauri/src-tauri/binaries/`.

## Что где

| Путь | Что это |
|------|---------|
| `app-tauri/` | Приложение в строке меню — нативный интерфейс macOS (Tauri + Rust). |
| `spike/tproxy.py` | Служба десинка и раздельного роутинга (Python, root). |
| `vendor/tg-ws-proxy/` | Встроенный Telegram-прокси MTProto-over-WebSocket. |
| `vendor/geph/` | Как собирается и обновляется встроенный `geph5-client`. |
| `docs/` | Заметки по устройству и безопасности. |

## Приватность

- Slipstream — локальное решение: всё крутится у тебя на машине.
- Российские сервисы держим **в стороне** от туннеля — идут напрямую, например банк не видит заграничный айпи.
- Geph — твой аккаунт в открытой сети Geph; за её безопасность отвечают они, подробности — в их доках.

## Благодарности

- **Slipstream** — [MIT](LICENSE).
- **geph5-client** — MPL-2.0, © [Geph](https://geph.io). Встроен как есть, собирается в CI.
- **tg-ws-proxy** — MIT, © [Flowseal](https://github.com/Flowseal/tg-ws-proxy). Встроен как модуль.

<div align="center"><sub>Сделано, чтобы просто работало — само и по-человечески!</sub></div>
