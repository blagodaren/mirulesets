# Разработка и CLI

Для разработки нужен Go 1.26+; рекомендуемый toolchain в `go.mod`, CI, релизные сборки и Docker используют Go 1.26.3. Веб-панель встроена через `go:embed`; сборщик JavaScript и установка пакетов не требуются. Node.js нужен только для проверки синтаксиса и тестов темы.

## Сборка из исходников

```sh
git clone https://github.com/blagodaren/mirulesets.git
cd mirulesets
go build -trimpath -o mirulesets ./cmd/mirulesets
```

Сервер запускается командой `./mirulesets`. По умолчанию он слушает `127.0.0.1:8080` и хранит данные в `data` относительно рабочего каталога. Если пароль не задан через `MI_ADMIN_PASSWORD` или `MI_ADMIN_PASSWORD_FILE`, при первом запуске он создаётся в `data/admin-password`.

Сервер не читает `.env` автоматически: передайте переменные через окружение процесса. Для установки на сервер используйте [инструкцию развёртывания](deployment.md); для изменения версии — [параметры сборки](deployment.md#версия-сборки).

## CLI-конвертер

```sh
./mirulesets convert -input domains.yaml -output domains.mrs -behavior domain -from yaml -to mrs
./mirulesets convert -input domains.mrs -output domains.txt -behavior domain -from mrs -to text
./mirulesets convert -input domains.txt -output classical.yaml -behavior domain -target-behavior classical -to yaml
```

Существующий выходной файл не перезаписывается: выберите новое имя. `auto` определяет формат источника; behavior задаётся явно. [Поддержанные форматы и ограничения](../internal/rules/README.md).

## Проверки

```sh
go test ./...
go vet ./...
node --check web/app.js
node --test web/theme_test.cjs
```

Проверка гонок в Linux требует включённого CGo и C-компилятора:

```sh
CGO_ENABLED=1 go test -race ./...
```

Обычные тесты используют временные каталоги и тестовые HTTP-серверы. Они не подтверждают доступность внешнего домена, выдачу настоящего ACME-сертификата или права конкретного S3-аккаунта. Независимые проверки MRS и SRS запускаются с официальными бинарниками Mihomo и sing-box: [порядок проверки кодеков](../internal/rules/README.md#проверки-совместимости-и-скорости).

CI получает версию командой `version` из собранного бинарника: её источник — `internal/version/version.go`. Это значение передаётся в Docker через аргумент сборки `VERSION` и используется для проверки версии контейнера.

## Структура

| Каталог | Назначение |
| --- | --- |
| `cmd/mirulesets` | Запуск сервера и CLI |
| `internal/service` · `internal/store` | Сборки, публикация и состояние |
| `internal/rules` · `internal/fetcher` | Кодеки, нормализация и загрузка источников |
| `internal/server` · `web` | HTTP API, статические файлы и веб-панель |
| `deploy` · `.github/workflows` | Конфигурации сервера и сборка выпуска |

Интерфейс меняется по [UI Kit](../UI_KIT.md): стили используют переменные `:root`, зависимости и внешние ресурсы для работы панели не требуются.
