# Slipstream

<div align="center">

**Русский** · [English](README.en.md)

[![preview](https://img.shields.io/badge/preview-macOS%20Apple%20Silicon-000000?logo=apple)](#установка)
[![ci](https://github.com/aiwaki/slipstream/actions/workflows/ci.yml/badge.svg)](https://github.com/aiwaki/slipstream/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/лицензия-MIT-blue.svg)](LICENSE)

</div>

Slipstream — приложение раздельной маршрутизации для сетей с блокировками и
DPI-фильтрацией. Маршрут выбирается для конкретного сервиса; Slipstream не
включает системный VPN для всего трафика.

## Для пользователя

### Маршруты

| Маршрут | Назначение |
|---|---|
| Прямое соединение | Сервисы, которым обход не требуется. |
| Локальный обход | DPI-блокировки без смены внешнего IP. |
| Зарубежный выход | Только явно проверенные сервисы, блокирующие российские IP; через встроенный Geph. |
| Telegram | Локальный прокси, который предлагается, если прямое подключение недоступно. |

Discord и YouTube используют локальный обход и никогда не направляются через
Geph. Неизвестные хосты не переключаются на зарубежный выход автоматически.
Внешние DNS, proxy, PAC и VPN обнаруживаются, но не изменяются.

### Установка

Доступная сборка: macOS Apple Silicon.

1. В [Releases](https://github.com/aiwaki/slipstream/releases) выбрать последний релиз с названием `Slipstream … (preview)` и загрузить `Slipstream-macos-arm64.zip`.
2. Распаковать приложение и перенести `Slipstream.app` в «Программы».
3. Запустить Slipstream и разрешить установку фоновой службы.

Аккаунт и выход Geph настраиваются в меню только для маршрутов с зарубежным
выходом. Предложение подключить Telegram-прокси появляется автоматически.

> [!NOTE]
> Preview-сборки не нотарифицированы Apple. Если macOS блокирует приложение,
> доступно открытие через контекстное меню **Открыть**.

Порядок поддержки других платформ указан в
[`docs/ROADMAP.md`](docs/ROADMAP.md). Повторяемые симптомы и проверки собраны в
[`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md).

## Для разработчика

Slipstream состоит из tray-приложения на Tauri, фоновой Python-службы,
встроенных sidecar-компонентов и общих JSON-контрактов. Публичного CLI или API
пока нет; проверяемая межплатформенная поверхность находится в `contracts/`.

- [Подготовка и сборка](DEVELOPMENT.md#setup)
- [Безопасные локальные проверки без root](DEVELOPMENT.md#safe-local-checks)
- [Привилегированные проверки только в disposable CI](DEVELOPMENT.md#privileged-qualification)
- [Карта инженерной документации](docs/README.md)
- [Контракты маршрутизации и восстановления](contracts/README.md)
- [Roadmap](docs/ROADMAP.md)

## Приватность и лицензии

Решения о маршрутизации и диагностика выполняются локально. Через сеть Geph
проходит только трафик явно назначенных зарубежных маршрутов; прямой и локальный
маршруты Geph не используют.

- **Slipstream** — [MIT](LICENSE).
- **geph5-client** — MPL-2.0, © [Geph](https://geph.io).
- **tg-ws-proxy** — MIT, © [Flowseal](https://github.com/Flowseal/tg-ws-proxy).

Подробности: [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
