# Slipstream

<div align="center">

**Русский** · [English](README.en.md)

[![preview](https://img.shields.io/badge/preview-macOS%20(Apple%20Silicon)-000000?logo=apple)](#установка)
[![license](https://img.shields.io/badge/лицензия-MIT-blue.svg)](LICENSE)
[![build-geph](https://github.com/aiwaki/slipstream/actions/workflows/build-geph.yml/badge.svg)](https://github.com/aiwaki/slipstream/actions/workflows/build-geph.yml)
[![build-app](https://github.com/aiwaki/slipstream/actions/workflows/build-app.yml/badge.svg)](https://github.com/aiwaki/slipstream/actions/workflows/build-app.yml)

</div>

Slipstream — клиент раздельной маршрутизации для сетей с блокировками,
DPI-фильтрацией и сервисами, требующими зарубежный IP.

Маршруты:

- прямое соединение для российских и локальных сервисов;
- локальный обход DPI без смены внешнего IP;
- туннель Geph для сервисов, которым нужен зарубежный IP;
- встроенный прокси для Telegram Desktop, если прямое подключение не проходит.

Без расширений в браузере и ручной настройки прокси в каждом приложении.

## Компоненты

- **Локальный обход DPI**: разделение TLS-хендшейка, короткоживущие
  decoy-пакеты, DoH против подмены DNS, отдельная обработка голоса Discord.
- **Geph**: зарубежный выход через встроенный `geph5-client`.
- **tg-ws-proxy**: локальный MTProto-over-WebSocket прокси для Telegram Desktop
  ([Flowseal](https://github.com/Flowseal/tg-ws-proxy)).

Десинк и Telegram-прокси работают на вашем устройстве. Для Geph нужен аккаунт в
сети Geph.

## Платформы

| Платформа | Статус |
|---|---|
| macOS Apple Silicon | ранняя сборка |
| Windows | не реализовано |
| Linux | не реализовано |
| iOS | не реализовано |
| Android | не реализовано |

## Установка

1. Скачать `Slipstream.app` из [релизов](https://github.com/aiwaki/slipstream/releases) и перенести в «Программы».
2. Запустить приложение. Пароль macOS потребуется один раз — для установки фоновой службы.
3. В меню (иконка в строке меню):
   - **Geph → Аккаунт…** — вставить ключ аккаунта Geph.
   - **Geph → выбрать выход** — город или **Автоматически**.

Telegram Desktop в России обычно не подключается напрямую — Slipstream сам
предложит включить встроенный Telegram-прокси.

> [!TIP]
> Сборка не нотарифицирована Apple. Если macOS блокирует скачанное
> приложение, его можно открыть через правый клик → **Открыть**.

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

Встроенный `geph5-client` собирается из исходников в CI
([`build-geph.yml`](.github/workflows/build-geph.yml)) и помещается в
`app-tauri/src-tauri/binaries/`.

## Что где

| Путь | Что это |
|------|---------|
| `app-tauri/` | Приложение в строке меню (Tauri + Rust). |
| `spike/tproxy.py` | Служба десинка и раздельного роутинга для macOS (Python, root). |
| `vendor/tg-ws-proxy/` | Встроенный Telegram-прокси MTProto-over-WebSocket. |
| `vendor/geph/` | Сборка встроенного `geph5-client`. |
| `docs/` | Заметки по устройству и безопасности. |

## Приватность

- Клиентская логика Slipstream работает локально на вашем устройстве.
- Российские сервисы не маршрутизируются через Geph.
- Geph — это аккаунт в открытой сети Geph; за её безопасность отвечает Geph,
  подробности есть в их документации.

## Благодарности

- **Slipstream** — [MIT](LICENSE).
- **geph5-client** — MPL-2.0, © [Geph](https://geph.io). Встроен как есть, собирается в CI.
- **tg-ws-proxy** — MIT, © [Flowseal](https://github.com/Flowseal/tg-ws-proxy). Встроен как модуль.
