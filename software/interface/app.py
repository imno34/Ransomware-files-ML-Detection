from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pandas as pd
import streamlit as st

from software.interface.formatting import display_value, parse_json_payload
from software.interface.repository import (
    DatabaseSchemaError,
    EventFilters,
    InterfaceDatabaseError,
    PageResult,
    ProcessFilters,
    ReadOnlyRepository,
)
from software.interface.settings import (
    InterfaceConfigurationError,
    parse_interface_options,
)


PROCESS_SORT_LABELS = {
    "Уровень подозрения": "score_desc",
    "Последняя активность": "last_seen_desc",
    "Имя процесса": "name_asc",
    "Число ransomware-событий": "ransomware_desc",
}

EVENT_SORT_LABELS = {
    "Сначала новые": "timestamp_desc",
    "Вероятность ransomware": "ransomware_desc",
    "Приоритет": "priority_desc",
    "Путь к файлу": "path_asc",
}

PROCESS_COLUMN_LABELS = {
    "process_id": "PID",
    "process_name": "Процесс",
    "last_seen": "Последняя активность",
    "events_in_window": "Событий в окне",
    "ransomware_encrypted_count": "Ransomware",
    "max_ransomware_probability": "Макс. вероятность",
    "suspicion_score": "Score",
    "threat_level": "Угроза",
    "profile_status": "Статус",
}

EVENT_COLUMN_LABELS = {
    "timestamp": "Время",
    "event_type": "Тип",
    "file_path": "Файл",
    "process_name": "Процесс",
    "process_id": "PID",
    "event_priority": "Приоритет",
    "predicted_class": "Класс",
    "ransomware_encrypted_probability": "P(ransomware)",
    "extraction_status": "Признаки",
    "vectorization_status": "Вектор",
    "response_status": "Реакция",
}

EVENT_DETAIL_GROUPS = (
    (
        "Событие и файл",
        (
            "event_id",
            "event_type",
            "timestamp",
            "file_path",
            "file_extension",
            "file_size",
        ),
    ),
    (
        "Процесс",
        (
            "thread_id",
            "process_id",
            "process_name",
            "process_path",
            "process_start_time",
            "process_key",
            "process_profile_ref",
        ),
    ),
    (
        "Фильтрация",
        (
            "filter_decision",
            "filter_reason",
            "event_priority",
        ),
    ),
    (
        "Стабилизация",
        (
            "stabilization_status",
            "stable_file_size",
            "stabilization_attempts",
            "stable_mtime",
            "stabilization_error",
        ),
    ),
    (
        "Извлечение и векторизация",
        (
            "extraction_status",
            "features_ref",
            "extraction_error",
            "vectorization_status",
            "feature_vector_ref",
            "vectorization_error",
        ),
    ),
    (
        "Классификация",
        (
            "predicted_class",
            "benign_probability",
            "benign_encrypted_probability",
            "ransomware_encrypted_probability",
            "classifier_version",
            "classification_timestamp",
            "classification_error",
        ),
    ),
    (
        "Реакция",
        (
            "response_action",
            "requested_action",
            "executed_action",
            "response_status",
            "response_timestamp",
            "response_error",
        ),
    ),
)


def main(argv: Sequence[str] | None = None) -> None:
    st.set_page_config(
        page_title="Результаты антивируса",
        page_icon="🛡️",
        layout="wide",
    )
    st.title("Результаты работы антивируса")
    st.caption("Локальный интерфейс просмотра SQLite — только чтение.")

    try:
        options = parse_interface_options(argv)
        repository = ReadOnlyRepository(options.database_path)
        repository.validate_schema()
    except (
        InterfaceConfigurationError,
        InterfaceDatabaseError,
        DatabaseSchemaError,
    ) as exc:
        st.error(str(exc))
        st.info(
            "Проверьте `storage.path` в конфигурации либо передайте "
            "`--database` после разделителя `--` в команде Streamlit."
        )
        st.stop()
        return

    _reset_selection_if_database_changed(str(repository.path))
    _apply_pending_navigation()

    with st.sidebar:
        st.header("Навигация")
        view = st.radio(
            "Раздел",
            ("Процессы", "Файловые события"),
            key="interface_view",
        )
        st.divider()
        st.caption("База данных")
        st.code(str(repository.path), language=None)
        auto_refresh = st.toggle(
            "Автообновление каждые 5 секунд",
            value=False,
            key="auto_refresh",
        )
        if st.button("Обновить данные", use_container_width=True):
            st.rerun()

    try:
        summary = repository.summary()
    except InterfaceDatabaseError as exc:
        st.error(str(exc))
        st.stop()
        return

    _render_summary(summary)
    details_open = bool(
        st.session_state.get("selected_process_key")
        if view == "Процессы"
        else st.session_state.get("selected_event_id")
    )
    if auto_refresh and details_open:
        st.caption(
            "Автообновление приостановлено, пока открыта подробная карточка."
        )

    run_every = "5s" if auto_refresh and not details_open else None

    @st.fragment(run_every=run_every)
    def render_active_view() -> None:
        try:
            if view == "Процессы":
                _render_processes(repository)
            else:
                _render_events(repository)
        except InterfaceDatabaseError as exc:
            st.error(str(exc))

    render_active_view()


def _render_summary(summary: Mapping[str, int]) -> None:
    columns = st.columns(4)
    columns[0].metric("Процессы", summary["processes"])
    columns[1].metric("Файловые события", summary["events"])
    columns[2].metric("Критические процессы", summary["critical_processes"])
    columns[3].metric("Ransomware-события", summary["ransomware_events"])


def _render_processes(repository: ReadOnlyRepository) -> None:
    st.header("Процессы")
    filter_columns = st.columns((2.2, 1.4, 1.4, 1.4, 0.8))
    search = filter_columns[0].text_input(
        "Поиск",
        placeholder="Имя, PID или process_key",
        key="process_search",
    )
    threat_levels = filter_columns[1].multiselect(
        "Уровень угрозы",
        repository.distinct_values("processes", "threat_level"),
        key="process_threat_levels",
    )
    statuses = filter_columns[2].multiselect(
        "Статус профиля",
        repository.distinct_values("processes", "profile_status"),
        key="process_profile_statuses",
    )
    sort_label = filter_columns[3].selectbox(
        "Сортировка",
        tuple(PROCESS_SORT_LABELS),
        key="process_sort_label",
    )
    page_size = filter_columns[4].selectbox(
        "Строк",
        (25, 50, 100),
        index=1,
        key="process_page_size",
    )

    filters = ProcessFilters(
        search=search,
        threat_levels=tuple(threat_levels),
        profile_statuses=tuple(statuses),
    )
    signature = (search, tuple(threat_levels), tuple(statuses), sort_label, page_size)
    page = _prepare_page("process_page", "process_filters_signature", signature)
    result = repository.list_processes(
        filters,
        sort=PROCESS_SORT_LABELS[sort_label],
        page=page,
        page_size=page_size,
    )
    _synchronize_page("process_page", result)

    st.caption(f"Найдено процессов: {result.total}")
    display_rows = [
        {label: row.get(column) for column, label in PROCESS_COLUMN_LABELS.items()}
        for row in result.items
    ]
    selection = st.dataframe(
        pd.DataFrame(display_rows),
        hide_index=True,
        use_container_width=True,
        on_select="rerun",
        selection_mode="single-row",
        key=_table_key("process_table", signature, result.page),
    )
    selected_key = _selected_identifier(
        selection,
        result.items,
        "process_key",
    )
    if selected_key and selected_key != st.session_state.get(
        "selected_process_key"
    ):
        st.session_state["selected_process_key"] = selected_key
        st.session_state.pop("selected_process_event_id", None)
        st.rerun()

    _render_page_controls(result, "process_page")

    process_key = st.session_state.get("selected_process_key")
    if not process_key:
        st.info("Выберите строку процесса, чтобы открыть его профиль.")
        return

    profile = repository.get_process(process_key)
    if profile is None:
        st.warning("Выбранный профиль больше не существует.")
        if st.button("Закрыть карточку процесса"):
            st.session_state.pop("selected_process_key", None)
            st.rerun()
        return

    st.divider()
    title_columns = st.columns((5, 1))
    title_columns[0].subheader(
        f"{profile.get('process_name', 'unknown')} — профиль процесса"
    )
    if title_columns[1].button(
        "Закрыть",
        key="close_process_detail",
        use_container_width=True,
    ):
        st.session_state.pop("selected_process_key", None)
        st.session_state.pop("selected_process_event_id", None)
        st.rerun()

    _render_process_detail(profile)
    _render_process_events(repository, process_key)


def _render_process_detail(profile: Mapping[str, Any]) -> None:
    metrics = st.columns(4)
    metrics[0].metric("Уровень угрозы", profile.get("threat_level", "—"))
    metrics[1].metric("Suspicion score", profile.get("suspicion_score", 0))
    metrics[2].metric(
        "Ransomware-события",
        profile.get("ransomware_encrypted_count", 0),
    )
    metrics[3].metric(
        "Макс. вероятность",
        _probability(profile.get("max_ransomware_probability")),
    )

    with st.expander("Все поля процесса", expanded=True):
        _render_key_value_table(profile)


def _render_process_events(
    repository: ReadOnlyRepository,
    process_key: str,
) -> None:
    st.subheader("Связанные файловые события")
    controls = st.columns((1.5, 0.8))
    sort_label = controls[0].selectbox(
        "Сортировка событий",
        tuple(EVENT_SORT_LABELS),
        key="process_event_sort_label",
    )
    page_size = controls[1].selectbox(
        "Строк",
        (25, 50, 100),
        index=1,
        key="process_event_page_size",
    )
    signature = (process_key, sort_label, page_size)
    page = _prepare_page(
        "process_event_page",
        "process_event_filters_signature",
        signature,
    )
    result = repository.list_process_events(
        process_key,
        sort=EVENT_SORT_LABELS[sort_label],
        page=page,
        page_size=page_size,
    )
    _synchronize_page("process_event_page", result)

    st.caption(f"Связанных событий: {result.total}")
    selection = _event_table(
        result,
        key=_table_key("process_event_table", signature, result.page),
    )
    selected_event = _selected_identifier(
        selection,
        result.items,
        "event_id",
    )
    if selected_event and selected_event != st.session_state.get(
        "selected_process_event_id"
    ):
        st.session_state["selected_process_event_id"] = selected_event
        st.rerun()
    _render_page_controls(result, "process_event_page")

    event_id = st.session_state.get("selected_process_event_id")
    if not event_id:
        return
    event = repository.get_event(event_id)
    if event is None:
        st.warning("Выбранное событие больше не существует.")
        return

    _render_event_detail(event, title="Подробности связанного события")
    if st.button(
        "Открыть в разделе «Файловые события»",
        key="open_event_page",
    ):
        st.session_state["selected_event_id"] = event_id
        st.session_state["pending_interface_view"] = "Файловые события"
        st.rerun()


def _render_events(repository: ReadOnlyRepository) -> None:
    st.header("Файловые события")
    first_row = st.columns((2.2, 1.2, 1.5))
    search = first_row[0].text_input(
        "Поиск",
        placeholder="Путь, процесс, process_key или event_id",
        key="event_search",
    )
    event_types = first_row[1].multiselect(
        "Тип события",
        repository.distinct_values("file_events", "event_type"),
        key="event_types",
    )
    predicted_classes = first_row[2].multiselect(
        "Предсказанный класс",
        repository.distinct_values("file_events", "predicted_class"),
        key="event_predicted_classes",
    )

    second_row = st.columns((1.4, 1.4, 1.4, 0.8))
    extraction_statuses = second_row[0].multiselect(
        "Извлечение",
        repository.distinct_values("file_events", "extraction_status"),
        key="event_extraction_statuses",
    )
    vectorization_statuses = second_row[1].multiselect(
        "Векторизация",
        repository.distinct_values("file_events", "vectorization_status"),
        key="event_vectorization_statuses",
    )
    sort_label = second_row[2].selectbox(
        "Сортировка",
        tuple(EVENT_SORT_LABELS),
        key="event_sort_label",
    )
    page_size = second_row[3].selectbox(
        "Строк",
        (25, 50, 100),
        index=1,
        key="event_page_size",
    )

    filters = EventFilters(
        search=search,
        event_types=tuple(event_types),
        predicted_classes=tuple(predicted_classes),
        extraction_statuses=tuple(extraction_statuses),
        vectorization_statuses=tuple(vectorization_statuses),
    )
    signature = (
        search,
        tuple(event_types),
        tuple(predicted_classes),
        tuple(extraction_statuses),
        tuple(vectorization_statuses),
        sort_label,
        page_size,
    )
    page = _prepare_page("event_page", "event_filters_signature", signature)
    result = repository.list_events(
        filters,
        sort=EVENT_SORT_LABELS[sort_label],
        page=page,
        page_size=page_size,
    )
    _synchronize_page("event_page", result)

    st.caption(f"Найдено событий: {result.total}")
    selection = _event_table(
        result,
        key=_table_key("event_table", signature, result.page),
    )
    selected_event = _selected_identifier(
        selection,
        result.items,
        "event_id",
    )
    if selected_event and selected_event != st.session_state.get(
        "selected_event_id"
    ):
        st.session_state["selected_event_id"] = selected_event
        st.rerun()
    _render_page_controls(result, "event_page")

    event_id = st.session_state.get("selected_event_id")
    if not event_id:
        st.info("Выберите строку, чтобы открыть полные данные события.")
        return

    event = repository.get_event(event_id)
    if event is None:
        st.warning("Выбранное событие больше не существует.")
        if st.button("Закрыть карточку события"):
            st.session_state.pop("selected_event_id", None)
            st.rerun()
        return

    st.divider()
    title_columns = st.columns((5, 1))
    title_columns[0].subheader("Полные данные файлового события")
    if title_columns[1].button(
        "Закрыть",
        key="close_event_detail",
        use_container_width=True,
    ):
        st.session_state.pop("selected_event_id", None)
        st.rerun()

    _render_event_detail(event)
    process_key = event.get("process_key")
    if process_key and repository.get_process(str(process_key)) is not None:
        if st.button("Открыть профиль процесса", key="open_process_page"):
            st.session_state["selected_process_key"] = str(process_key)
            st.session_state["pending_interface_view"] = "Процессы"
            st.rerun()
    elif process_key:
        st.caption(
            "Для process_key этого события актуальный профиль отсутствует."
        )


def _event_table(
    result: PageResult[dict[str, Any]],
    *,
    key: str,
):
    display_rows = [
        {label: row.get(column) for column, label in EVENT_COLUMN_LABELS.items()}
        for row in result.items
    ]
    return st.dataframe(
        pd.DataFrame(display_rows),
        hide_index=True,
        use_container_width=True,
        on_select="rerun",
        selection_mode="single-row",
        key=key,
    )


def _render_event_detail(
    event: Mapping[str, Any],
    *,
    title: str | None = None,
) -> None:
    if title:
        st.subheader(title)

    probability_columns = st.columns(4)
    probability_columns[0].metric(
        "Класс",
        event.get("predicted_class") or "—",
    )
    probability_columns[1].metric(
        "P(benign)",
        _probability(event.get("benign_probability")),
    )
    probability_columns[2].metric(
        "P(benign-encrypted)",
        _probability(event.get("benign_encrypted_probability")),
    )
    probability_columns[3].metric(
        "P(ransomware)",
        _probability(event.get("ransomware_encrypted_probability")),
    )

    displayed_fields: set[str] = {"features_json", "feature_vector_json"}
    for group_title, fields in EVENT_DETAIL_GROUPS:
        displayed_fields.update(fields)
        values = {field: event.get(field) for field in fields}
        with st.expander(group_title, expanded=group_title in {"Событие и файл", "Классификация"}):
            _render_key_value_table(values)

    remaining = {
        key: value
        for key, value in event.items()
        if key not in displayed_fields
    }
    if remaining:
        with st.expander("Прочие поля"):
            _render_key_value_table(remaining)

    _render_json_payload(
        "Извлечённые признаки",
        event.get("features_json"),
    )
    _render_json_payload(
        "Вектор признаков",
        event.get("feature_vector_json"),
    )


def _render_json_payload(title: str, raw_value: Any) -> None:
    with st.expander(title):
        valid, payload = parse_json_payload(raw_value)
        if payload is None:
            st.caption("Данные отсутствуют.")
        elif valid:
            st.json(payload, expanded=False)
        else:
            st.warning("Поле содержит некорректный JSON; показано исходное значение.")
            st.code(str(payload), language=None)


def _render_key_value_table(values: Mapping[str, Any]) -> None:
    rows = [
        {"Поле": key, "Значение": display_value(value)}
        for key, value in values.items()
    ]
    st.dataframe(
        pd.DataFrame(rows),
        hide_index=True,
        use_container_width=True,
    )


def _selected_identifier(
    selection: Any,
    rows: Sequence[Mapping[str, Any]],
    identifier: str,
) -> str | None:
    selected_rows = getattr(getattr(selection, "selection", None), "rows", ())
    if not selected_rows:
        return None
    index = int(selected_rows[0])
    if index < 0 or index >= len(rows):
        return None
    value = rows[index].get(identifier)
    return str(value) if value is not None else None


def _prepare_page(page_key: str, signature_key: str, signature: Any) -> int:
    if st.session_state.get(signature_key) != signature:
        st.session_state[signature_key] = signature
        st.session_state[page_key] = 1
    return int(st.session_state.get(page_key, 1))


def _synchronize_page(page_key: str, result: PageResult[Any]) -> None:
    current = int(st.session_state.get(page_key, 1))
    if current != result.page:
        st.session_state[page_key] = result.page


def _render_page_controls(
    result: PageResult[Any],
    page_key: str,
) -> None:
    columns = st.columns((1, 2, 1))
    if columns[0].button(
        "← Предыдущая",
        disabled=result.page <= 1,
        key=f"{page_key}_previous",
        use_container_width=True,
    ):
        st.session_state[page_key] = result.page - 1
        st.rerun()
    columns[1].caption(
        f"Страница {result.page} из {result.total_pages}"
    )
    if columns[2].button(
        "Следующая →",
        disabled=result.page >= result.total_pages,
        key=f"{page_key}_next",
        use_container_width=True,
    ):
        st.session_state[page_key] = result.page + 1
        st.rerun()


def _probability(value: Any) -> str:
    if value is None:
        return "—"
    try:
        return f"{float(value):.2%}"
    except (TypeError, ValueError):
        return str(value)


def _table_key(prefix: str, signature: Any, page: int) -> str:
    return f"{prefix}_{page}_{abs(hash(repr(signature)))}"


def _reset_selection_if_database_changed(database: str) -> None:
    previous = st.session_state.get("interface_database")
    if previous == database:
        return
    st.session_state["interface_database"] = database
    for key in (
        "selected_process_key",
        "selected_process_event_id",
        "selected_event_id",
    ):
        st.session_state.pop(key, None)


def _apply_pending_navigation() -> None:
    pending = st.session_state.pop("pending_interface_view", None)
    if pending in {"Процессы", "Файловые события"}:
        st.session_state["interface_view"] = pending


if __name__ == "__main__":
    main()
