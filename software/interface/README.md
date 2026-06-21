# Read-only Streamlit UI

Интерфейс предназначен только для просмотра таблиц `processes` и
`file_events`. SQLite открывается через URI `mode=ro` с
`PRAGMA query_only=ON`; операции изменения данных отсутствуют.

## Установка

```powershell
.\.venv\Scripts\python.exe -m pip install -r software\requirements.txt
```

## Запуск по конфигурации

Команда выполняется из корня репозитория:

```powershell
.\.venv\Scripts\python.exe -m streamlit run `
  software\interface\app.py `
  --server.address 127.0.0.1 `
  -- `
  --config software\configuration.yaml
```

UI прочитает путь к базе из `storage.path`.

## Запуск с явным путём к SQLite

Параметр `--database` имеет приоритет над конфигурацией:

```powershell
.\.venv\Scripts\python.exe -m streamlit run `
  software\interface\app.py `
  --server.address 127.0.0.1 `
  -- `
  --config software\configuration.yaml `
  --database C:\runtime\antivirus_db.sqlite3
```

Приложение доступно только локально по адресу, который напечатает Streamlit,
обычно `http://127.0.0.1:8501`.

## Возможности

- список и полная карточка профиля процесса;
- связанные с процессом файловые события;
- общий список и полная карточка файлового события;
- фильтрация, сортировка и пагинация;
- форматированный просмотр `features_json` и `feature_vector_json`;
- ручное обновление и необязательное автообновление каждые пять секунд.

Автообновление приостанавливается, когда открыта подробная карточка, чтобы
выбранная запись не смещалась.

