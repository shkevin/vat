from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType

from app.services import aikido_export


def test_flatten_rows_and_columns_helpers():
    assert aikido_export._flatten_for_excel(None) == ""
    assert aikido_export._flatten_for_excel("x") == "x"
    assert aikido_export._flatten_for_excel({"a": 1}).startswith("{")
    long_list = ["x"] * 50000
    assert len(aikido_export._flatten_for_excel(long_list)) <= 32767

    rows = aikido_export._rows_from_dicts(
        [{"a": 1, "b": {"x": 1}}, "skip", {"a": 2}], exclude_keys={"b"}
    )
    assert rows == [{"a": 1}, {"a": 2}]
    assert aikido_export._ensure_columns([]) == []
    cols = aikido_export._ensure_columns([{"a": 1}, {"b": 2}], column_order=["a", "b"])
    assert cols == [{"a": 1, "b": ""}, {"a": "", "b": 2}]


def test_export_aikido_skip_and_errors(monkeypatch, tmp_path):
    assert aikido_export.export_aikido_sync_to_excel({}, output_dir=None) is None

    class _BadPath:
        def __init__(self, *_args, **_kwargs):
            pass

        def mkdir(self, *args, **kwargs):
            raise OSError("nope")

    real_path = aikido_export.Path
    monkeypatch.setattr(aikido_export, "Path", _BadPath)
    assert aikido_export.export_aikido_sync_to_excel({}, output_dir=str(tmp_path / "bad")) is None
    monkeypatch.setattr(aikido_export, "Path", real_path)

    monkeypatch.setitem(sys.modules, "pandas", None)
    out = aikido_export.export_aikido_sync_to_excel(
        {"issues": [], "fetchedAt": "now"}, output_dir=tmp_path
    )
    assert out is None


def test_export_aikido_success_and_exception_paths(monkeypatch, tmp_path):
    writes = []

    class _FakeDF:
        def __init__(self, data):
            self._data = data

        def to_excel(self, writer, sheet_name=None, index=False):
            writes.append((sheet_name, index, self._data))

    class _Writer:
        def __init__(self, path, engine=None):
            self.path = str(path)
            self.engine = engine

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    fake_pd = ModuleType("pandas")
    fake_pd.DataFrame = _FakeDF
    fake_pd.ExcelWriter = _Writer
    monkeypatch.setitem(sys.modules, "pandas", fake_pd)

    data = {
        "fetchedAt": "2026-01-01T00:00:00Z",
        "issues": [{"id": "i1", "nested": {"x": 1}}],
        "issueGroups": [{"id": "g1"}],
        "repos": [{"id": "r1"}],
        "containers": [{"id": "c1"}],
        "vms": [{"id": "v1"}],
        "issueCounts": {"open": 1},
    }
    out = aikido_export.export_aikido_sync_to_excel(
        data, raw_issues=[{"id": "raw1"}], output_dir=tmp_path
    )
    assert out is not None
    assert out.endswith(".xlsx")
    written_sheets = {name for (name, _idx, _data) in writes}
    assert {
        "Summary",
        "IssueCounts",
        "Issues",
        "IssueGroups",
        "RawIssues",
        "Repos",
        "Containers",
        "VMs",
    }.issubset(written_sheets)

    class _BadWriter(_Writer):
        def __enter__(self):
            raise RuntimeError("boom")

    fake_pd2 = ModuleType("pandas")
    fake_pd2.DataFrame = _FakeDF
    fake_pd2.ExcelWriter = _BadWriter
    monkeypatch.setitem(sys.modules, "pandas", fake_pd2)
    out2 = aikido_export.export_aikido_sync_to_excel(data, output_dir=tmp_path)
    assert out2 is None
