# Демонстрационные программы шифрования

Программы предназначены только для проверки прототипа обнаружения на заранее
подготовленной изолированной копии тестового набора. Файлы изменяются
непосредственно в указанном каталоге: программа ничего не копирует и не создаёт
отдельный выходной каталог.

Доступны пять режимов:

- `intermittent_encryption.py` — 32 КиБ через каждые 64 КиБ, начиная со смещения 64 КиБ;
- `header-only_encryption.py` — первые 16 КиБ, либо 64 КиБ для файлов больше 20 МиБ;
- `adaptive_encryption.py` — полное преобразование файлов до 10 МиБ, иначе hybrid;
- `hybrid_encryption.py` — заголовок и прерывистые блоки; имя получает суффикс `.hacked`;
- `full_encryption.py` — полное AES-128-GCM-преобразование содержимого.

Как и в `augmentation/targeted_encryption.py`, nonce и authentication tag не
сохраняются. Преобразованные файлы не предназначены для обратного
расшифрования.

## Защитные меры

Перед запуском в корне тестового каталога должен находиться файл
`.ransomware-demo-allow` с единственной строкой:

```text
ALLOW_IN_PLACE_DEMO=YES
```

Создание маркера в PowerShell:

```powershell
Set-Content -Path C:\datasets\napierone-test\.ransomware-demo-allow `
  -Value "ALLOW_IN_PLACE_DEMO=YES" `
  -Encoding utf8
```

Маркер следует создать до запуска мониторинга целевого каталога.

Дополнительно:

- обязательны флаги `--in-place` и `--confirm`;
- `--dry-run` выполняет проверки без изменения файлов и не требует `--confirm`;
- корень диска, домашний и системные каталоги запрещены;
- символические ссылки, junction и другие reparse points не обходятся;
- защитный маркер не включается в число найденных файлов и не изменяется;
- `--files_count` должен быть неотрицательным и не превышать число найденных файлов.

## Прямой запуск отдельной программы

Команды выполняются из корня репозитория:

```powershell
.\.venv\Scripts\python.exe software\demo\full_encryption.py `
  C:\datasets\napierone-test `
  --in-place `
  --files_count 100 `
  --dry-run
```

После проверки:

```powershell
.\.venv\Scripts\python.exe software\demo\full_encryption.py `
  C:\datasets\napierone-test `
  --in-place `
  --files_count 100 `
  --confirm
```

Аналогично запускаются:

```text
software\demo\intermittent_encryption.py
software\demo\header-only_encryption.py
software\demo\adaptive_encryption.py
software\demo\hybrid_encryption.py
```

## Общий CLI

Алгоритм можно выбрать первым позиционным аргументом:

```powershell
.\.venv\Scripts\python.exe software\demo\encryption_demo.py `
  hybrid `
  C:\datasets\napierone-test `
  --in-place `
  --files_count 100 `
  --confirm
```

Допустимые значения алгоритма: `adaptive`, `full`, `header-only`, `hybrid`,
`intermittent`.

Целевой каталог следует добавить в `monitor.directories` конфигурации системы
обнаружения до запуска демонстрационной программы.
