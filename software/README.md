# Ransomware detection runtime prototype

Windows-прототип связывает файловые события ETW с процессами и обрабатывает
их конвейером:

`ETW/ReadDirectoryChangesW → filter → stabilize → extract → vectorize → classify → score → log`.

Прототип является пассивным. Для уровней `high` и `critical` он сохраняет
запрошенные действия `suspend` и `terminate`, но фактически всегда выполняет
только `log`. В коде отсутствуют вызовы остановки или завершения процессов.

Провайдер `Microsoft-Windows-Kernel-File` запускается с
`monitor.system_logger_mode: true`. Этот режим обязателен для получения
файловых ETW-событий с PID. Запуск ETW обычно требует административных прав.

Высокочастотные системные события `NameCreate`, `NameDelete`, `Create` и
`Write` разбираются напрямую из Kernel-File payload без медленного TDH-разбора.
`Create` используется только для корреляции `FileObject → путь`; изменение
существующего файла публикуется как `modified` по событию `Write`.

Нативный `ReadDirectoryChangesW` можно использовать как отдельный источник
событий без PID:

```yaml
monitor:
  etw_enabled: false
  directory_fallback_enabled: true
```

В этом режиме ETW-сессия не запускается, административные права для файлового
мониторинга обычно не требуются, а события получают
`process_id: null` и `process_key: unknown:directory-watcher`.

Одновременный режим `etw_enabled: true` и
`directory_fallback_enabled: true` поддерживается, но может создавать
дубликаты событий с разными ключами процесса.

## Требования

- Windows x64;
- Python 3.11;
- административные права могут потребоваться для ETW-сессии;
- доверенный ML-bundle в формате `joblib`;
- зависимости из `software/requirements.txt`.

Текущее виртуальное окружение репозитория может ссылаться на уже удалённый
интерпретатор. Его следует пересоздать:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r software\requirements.txt
```

## Конфигурация

Скопируйте `software/example_config.yaml`, укажите наблюдаемые каталоги,
путь к SQLite и путь к bundle. Относительные пути вычисляются относительно
файла конфигурации.

Параметр `logging.path` задаёт каталог журналов, а не конкретный файл:

```yaml
logging:
  path: C:\runtime\logs
  level: INFO
  max_bytes: 5242880
  backup_count: 3
```

Для каждого запуска создаётся отдельный файл с timestamp запуска:

```text
ransomware-detection_2026-06-20_03-39-51_603000.log
```

При превышении `max_bytes` части текущего запуска сохраняются как
`ransomware-detection_<timestamp>_part-1.log` и далее. Обработчики журналов
принудительно сбрасываются и закрываются при завершении программы.

Проверка:

```powershell
python -m software validate-config --config software\example_config.yaml
python -m software validate-bundle --config software\example_config.yaml
```

## Контракт ML-bundle

Bundle является словарём, сохранённым через `joblib.dump()`. Он обязан
содержать:

```python
{
    "model": fitted_lgbm_classifier,
    "feature_list": [...],
    "dtype_map": {"feature": "bool|int|float"},
    "fill_values": {"feature": value},
    "scaler": fitted_standard_scaler,
    "scaler_columns": [...],
    "label_map": {
        "benign": 0,
        "benign-encrypted": 1,
        "ransomware-encrypted": 2,
    },
    "model_version": "string",
    "feature_schema_hash": "sha256",
}
```

Команда `validate-config` выводит ожидаемый `feature_schema_hash`. Порядок
`feature_list`, типы, колонки scaler, классы модели и hash проверяются до
запуска.

Загружайте только доверенные joblib-файлы: формат pickle/joblib способен
выполнять код при десериализации.

## Запуск

Live ETW:

```powershell
python -m software run --config path\to\runtime.yaml
```

Остановка — `Ctrl+C`.

Replay для проверки без ETW:

```powershell
python -m software replay `
  --config path\to\runtime.yaml `
  --events path\to\events.json
```

Replay принимает JSON-массив или JSONL. Минимальное событие:

```json
{
  "event_type": "modified",
  "timestamp": "2026-06-18T10:00:00+00:00",
  "file_path": "C:/test/sample.pdf",
  "process_id": 1234,
  "process_name": "sample.exe",
  "process_start_time": "2026-06-18T09:59:00+00:00"
}
```

## Хранилище

SQLite работает в WAL-режиме:

- `file_events` обновляется после каждого этапа обработки;
- `processes` хранит текущий профиль процесса в 30-секундном окне;
- признаки и вектор сохраняются как JSON внутри записи события.

## Тесты

Тесты используют стандартный `unittest`:

```powershell
python -m unittest discover -s software\tests -v
```

ETW smoke-тест отключён по умолчанию. Для его запуска на Windows:

```powershell
$env:RUN_ETW_TESTS = "1"
python -m unittest software.tests.test_etw_windows -v
```

## Read-only Streamlit UI

Локальный интерфейс просмотра таблиц `processes` и `file_events` запускается
отдельно от runtime-конвейера:

```powershell
.\.venv\Scripts\python.exe -m streamlit run `
  software\interface\app.py `
  --server.address 127.0.0.1 `
  -- `
  --config software\configuration.yaml
```

SQLite открывается только для чтения. Подробная инструкция находится в
`software/interface/README.md`.
