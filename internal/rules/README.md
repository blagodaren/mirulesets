# Кодеки правил

Проверка пакета: `go test ./internal/rules`.

Кодек работает внутри Go-процесса. Бинарник Mihomo требуется только для независимой проверки совместимости. Реализация написана по структуре формата MRS v1; исходники Mihomo не скопированы и не включены в зависимости.

## Форматы

| Behavior | Импорт | Экспорт |
| --- | --- | --- |
| domain | YAML, text, MRS, hosts, Adblock DNS, geosite, sing-box JSON | YAML, text, MRS, sing-box JSON, SRS |
| ipcidr | YAML, text, MRS, geoip, sing-box JSON; отдельные IPv4/IPv6 превращаются в /32 и /128 | YAML, text, MRS, sing-box JSON, SRS |
| classical | YAML, text, hosts, Adblock DNS, geosite, geoip, sing-box JSON | YAML, text, sing-box JSON, SRS |

`Parse(data, "auto", behavior)` определяет формат по содержимому. YAML принимает список строк в `payload` или `rules`; строки в формате text могут содержать комментарии `#` и `//`. Тип behavior указывается явно. YAML-алиасы, несколько документов и смешанные ключи `payload`/`rules` отклоняются.

`Normalize` проверяет каждую строку, приводит домены к нижнему регистру и CIDR к адресу сети, удаляет точные дубликаты с сохранением порядка. Ошибка в любой строке отклоняет весь набор. Поддержаны classical-типы из Mihomo v1.19.34, включая AND/OR/NOT, DSCP, IN-TYPE, REMATCH-NAME и .NET-style регулярные выражения. MATCH, SUB-RULE и верхнеуровневый RULE-SET запрещены самим форматом classical. Наличие GEOIP/GEOSITE и ссылок RULE-SET внутри логических выражений проверяет клиент Mihomo по своей конфигурации и базам.

`Transform` конвертирует domain/ipcidr в classical. Точные домены и суффиксы превращаются в DOMAIN/DOMAIN-SUFFIX; wildcard и suffix-only шаблоны — в точные DOMAIN-REGEX с сохранением значения. Обратное преобразование принимает DOMAIN/DOMAIN-SUFFIX либо IP-CIDR/IP-CIDR6 без флагов. Произвольные регулярные выражения, смешанные типы и флаги `src`/`no-resolve` вызывают ошибку: потеря смысла правила не допускается.

## Новые входные форматы

`ParseSource(data, format, behavior, selector)` добавляет выбор категории DAT; `Parse` остаётся совместимой обёрткой. Идентификаторы форматов: `geosite`, `geoip`, `hosts`, `adblock`, `singbox`. Auto распознаёт JSON с `version`, hosts-записи и заголовок/доменные фильтры Adblock. DAT требует явного формата.

1. **geosite.dat / geoip.dat:** protobuf-схема [V2Fly](https://github.com/v2fly/v2ray-core/blob/master/app/router/routercommon/common.proto). `selector` обязателен: `google`, `cn,us` или `*` для всех категорий. Отсутствующая категория вызывает ошибку. Атрибуты geosite не фильтруются: берётся вся выбранная категория. Exact/suffix домены доступны как domain, keyword/regex требуют classical; `inverse_match` geoip отклоняется.
2. **hosts:** извлекаются точные имена и алиасы из `IP domain [aliases…]`; адрес назначения не становится DNS-перенаправлением. Комментарии после `#` поддерживаются.
3. **Adblock DNS:** `||example.com^` → `+.example.com`, голый домен → точное имя. Комментарии и заголовки поддерживаются. Исключения `@@`, ресурсные опции, пути URL и косметические фильтры отклоняются целиком: позитивный набор не может выразить их без изменения смысла. Сопоставление соответствует [DNS-синтаксису AdGuard](https://adguard-dns.io/kb/general/dns-filtering-syntax/).
4. **sing-box JSON:** принимается version 1–5 с `rules`. Поддержаны адресные поля, source CIDR, network, destination/source ports и ranges, process_name/path, logical and/or/invert. Сочетания полей сохраняют OR/AND-группы из [Headless Rule](https://sing-box.sagernet.org/configuration/rule-set/headless-rule/). Неизвестные/повторные поля и неподдержанные условия вызывают ошибку. Regex должен быть RE2-совместимым; явные флаги регистра сохраняются.

## Экспорт sing-box

Выходные идентификаторы — `singbox` (файл `.json`) и `srs` (файл `.srs`). Используется version 2, совместимая с sing-box **1.10+**. Domain exact/suffix/wildcard, IPv4/IPv6, а также перечисленное выше подмножество classical экспортируются. Mihomo-only GEOIP/GEOSITE, ASN, флаги `src`/`no-resolve` и прочие неподдержанные условия отклоняются с пояснением. Пустой JSON/SRS допустим. Импорт бинарного SRS не включён: сначала выполните `sing-box rule-set decompile`.

SRS реализован независимо, без зависимости от proxy engine: `SRS` + байт версии, затем zlib; количество правил и длины строк — uvarint. Домены используют LOUDS с маркерами корня/поддоменов, CIDR — объединённые IP-диапазоны. Структура сверена с [binary.go](https://github.com/SagerNet/sing-box/blob/v1.14.1/common/srs/binary.go) и [ip_set.go](https://github.com/SagerNet/sing-box/blob/v1.14.1/common/srs/ip_set.go). JSON описан в [официальной документации](https://sing-box.sagernet.org/configuration/rule-set/source-format/).

```sh
mirulesets convert -input geosite.dat -from geosite -selector google -behavior classical -to singbox -output google.json
mirulesets convert -input geoip.dat -from geoip -selector cn,us -behavior ipcidr -to srs -output countries.srs
mirulesets convert -input hosts.txt -from hosts -behavior domain -to srs -output hosts.srs
```

Независимая проверка официальным **sing-box 1.14.1**:

```powershell
$env:SINGBOX_BIN = (Resolve-Path '.tools/singbox/sing-box-1.14.1-windows-amd64/sing-box.exe').Path
go test ./internal/rules -run TestSingBoxCompatibility -count=1 -v
go test ./internal/rules -run '^$' -fuzz '^FuzzExtendedFormats$' -fuzztime 15s -parallel 2
```

Тест сравнивает декомпиляцию нашего SRS с результатом независимой компиляции JSON официальным бинарником: domain, ipcidr, classical и пустой набор; Unicode, wildcard, IPv6, логика и порты. Проверка выполнена 12 ноября 2026. Короткий fuzz новых импортов: 87 086 входов без падений за 15 секунд.

## Ограничения

1. Вход и распакованный MRS: 64 MiB; до 1 000 000 правил.
2. Домен: до 1024 байт; классическое правило: до 16 KiB; вложенность логики: до 32 уровней.
3. Доменное дерево: до 8 000 000 узлов; zstd-окно: до 16 MiB.
4. Пустые YAML/text допустимы. Пустой MRS отклоняется, как и в официальном конвертере.

Длины проверяются до выделения памяти. MRS с неправильной структурой дерева, несогласованными битовыми картами, некорректным UTF-8, неверным behavior и лишними байтами отклоняется.

## Структура MRS v1

Весь файл сжат zstd. В распакованном потоке числа имеют порядок big-endian.

| Поле | Представление |
| --- | --- |
| Сигнатура | 4 байта: `M`, `R`, `S`, `1` |
| Behavior | 1 байт: domain = 0, ipcidr = 1 |
| Количество правил | int64 |
| Дополнительные данные | int64 длина, затем указанное число байтов |
| Набор | версия 1 и данные domain/ipcidr |

Domain хранит дерево перевёрнутых доменных строк в LOUDS: bitmap терминальных узлов, bitmap структуры, байтовые метки. Каждое поле имеет int64 длину; bitmap состоит из uint64. Нулевой бит структуры обозначает ребро, единичный — конец узла; порядок узлов — обход в ширину. Суффиксные записи используют внутренний маркер `+`; `+.example.com` содержит точную запись и запись только для поддоменов.

IPCIDR хранит int64 количество диапазонов; у каждого диапазона два адреса по 16 байт. IPv4 записывается как IPv4-mapped IPv6. При экспорте перекрывающиеся и смежные диапазоны объединяются через `netipx.IPSetBuilder`.

Описание проверено по [mrs_converter.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.34/rules/provider/mrs_converter.go), [mrs_reader.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.34/rules/provider/mrs_reader.go), [domain_set_bin.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.34/component/trie/domain_set_bin.go), [ipcidr_set_bin.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.34/component/cidr/ipcidr_set_bin.go). Матрица форматов опубликована в [документации Mihomo](https://wiki.metacubex.one/en/config/rule-providers/).

## Проверки совместимости и скорости

Обычные unit-тесты не скачивают файлы и не обращаются в сеть. Для независимых проверок укажите официальный бинарник Mihomo **v1.19.34** и каталог с исходными `google.mrs` / `telegram.mrs`:

```powershell
$env:MIHOMO_BIN = (Resolve-Path '.tools/mihomo-v1.19.34/mihomo-windows-amd64-v1.exe').Path
$env:MIHOMO_FIXTURES = (Resolve-Path '.tools/fixtures').Path
go test ./internal/rules -count=1 -v
```

Проверяется чтение нашего MRS официальным конвертером, чтение MRS из официальных YAML/text-конверсий, domain exact/suffix/wildcard, Unicode и IPv4/IPv6. Дополнительно проверены [Google geosite](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google.mrs) — 1052 правила / 8973 байта — и [Telegram geoip](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/telegram.mrs) — 12 правил / 145 байт. Повторная сборка имеет те же размеры и тот же вывод официального конвертера. Эти URL изменяются; использованные SHA-256:

```text
google.mrs   ad92420fecc12694f11af2ed86ddc5d233ec1350b1ae15e8d24959fda23bc200
telegram.mrs d121af95b9aeca3d8c29b2112d5e6685b2a6716383df8ae31b5fbb3408c527b3
```

Два fuzz-теста проверяют сжатый поток и распакованную структуру отдельно:

```text
go test ./internal/rules -run '^$' -fuzz FuzzMRSDecoder -fuzztime 15s -parallel 2
go test ./internal/rules -run '^$' -fuzz FuzzMRSPayload -fuzztime 15s -parallel 2
go test ./internal/rules -run '^$' -bench BenchmarkDomainMRS100K -benchtime=3x -benchmem
```

Локальный результат 12 ноября 2026, Windows amd64, Go 1.26.3, Ryzen 7 9800X3D: 100 000 доменов → MRS за **70,3 мс** в среднем за три повторения; суммарно выделено 127,8 MB за операцию. Это микробенчмарк кодека, а не оценка пропускной способности сервера. Fuzz: 1 294 993 сжатых входа и 336 109 вариантов структуры без падений за два запуска по 15 секунд.
