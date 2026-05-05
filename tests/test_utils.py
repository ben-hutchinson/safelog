from pathlib import Path

from safelog.utils import non_empty_lines, normalize_log_message, read_text_file


def test_read_text_file_reads_utf8_text(tmp_path: Path) -> None:
    path = tmp_path / "sample.log"
    path.write_text("hello\n", encoding="utf-8")

    assert read_text_file(path) == "hello\n"


def test_non_empty_lines_filters_blank_lines() -> None:
    assert non_empty_lines("\nINFO ready\n  \nERROR failed\n") == [
        "INFO ready",
        "ERROR failed",
    ]


def test_normalize_log_message_removes_iso_timestamp_prefix() -> None:
    assert (
        normalize_log_message("2026-05-05T10:00:01Z ERROR timeout") == "ERROR timeout"
    )


def test_normalize_log_message_leaves_unmatched_lines_unchanged() -> None:
    assert normalize_log_message("ERROR timeout") == "ERROR timeout"
