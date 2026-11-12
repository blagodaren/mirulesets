# Развёртывание

Руководство по Docker, HTTPS, nginx, Nginx Proxy Manager, Caddy, S3 и systemd находится в [README → Развёртывание](../README.md#развёртывание).

## Prometheus

`GET /metrics` принимает сессию панели, `MI_API_TOKEN` или отдельный `MI_METRICS_TOKEN` в `Authorization: Bearer …`. Для мониторинга используйте `MI_METRICS_TOKEN`: от 32 символов, без переводов строк и отличный от API-токена; доступа к API он не даёт. `/healthz` остаётся публичным. Метрики выдаются в [текстовом формате Prometheus](https://prometheus.io/docs/instrumenting/exposition_formats/).

Пример `prometheus.yml`; файл `/etc/prometheus/secrets/mirulesets-token` должен содержать значение `MI_METRICS_TOKEN`:

```yaml
scrape_configs:
  - job_name: mirulesets
    scheme: https
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/secrets/mirulesets-token
    static_configs:
      - targets: [rules.example.com]
```

Синтаксис авторизации описан в [конфигурации Prometheus](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#http_config).

| Метрика | Значение |
| --- | --- |
| `mirulesets_last_success_timestamp_seconds{ruleset="id"}` | Unix-время последней успешной локальной публикации или проверки без изменений. Ноль до первой сборки. Сбой S3 не отменяет локальную публикацию. |
| `mirulesets_rules{ruleset="id"}` | Число правил в последней опубликованной локальной сборке. |
| `mirulesets_build_errors_total{ruleset="id"}` | Число неудачных попыток сборки, включая частичные ошибки S3. Сбрасывается при перезапуске процесса или удалении набора. |
| `mirulesets_build_duration_seconds{ruleset="id"}` | Длительность последней завершённой попытки, включая неудачную. После перезапуска — длительность сохранённой локальной сборки. |

Последняя успешная публикация и число правил восстанавливаются из `state.json`. Метрики не содержат URL источников, содержимое правил или текст ошибок. Пример условия для оповещения: `increase(mirulesets_build_errors_total[15m]) > 0`.

## Проверка S3 при запуске

При настроенном `MI_S3_BUCKET` сервер проверяет существование и доступность bucket до запуска планировщика и HTTP-сервера. Таймаут — 15 секунд. При недоступном bucket сервер пишет предупреждение без исходного текста ошибки и продолжает запуск; локальная раздача работает, отправка повторяется по существующим правилам. Проверка HEAD может требовать отдельного разрешения на bucket; она не загружает пробный файл и не подтверждает права `PutObject`.

## Версия сборки

CLI `mirulesets version` и `/api/system` используют одну переменную `internal/version.Version`. Версия исходников по умолчанию — `0.1.0-alpha`; для релиза задайте её при сборке:

```sh
go build -ldflags "-X github.com/blagodaren/mirulesets/internal/version.Version=0.1.0-alpha" ./cmd/mirulesets
docker build --build-arg VERSION=0.1.0-alpha -t mirulesets:0.1.0-alpha .
```
