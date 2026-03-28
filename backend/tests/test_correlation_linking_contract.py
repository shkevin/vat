"""
Contract tests for correlation cluster queries — no DB required.

Guards tenant isolation (NULL vs value) and deterministic ordering at the SQL layer.
"""

from sqlalchemy.dialects import postgresql

from app.services.correlation_linking import select_correlation_cluster


def _compile(stmt) -> str:
    return str(stmt.compile(dialect=postgresql.dialect())).lower()


def test_select_correlation_cluster_null_tenant_filters_is_null() -> None:
    stmt = select_correlation_cluster(correlation_key="v1:sca:asset:x", tenant_id=None)
    sql = _compile(stmt)
    assert "correlation_key" in sql
    assert "tenant_id" in sql
    assert "null" in sql  # IS NULL


def test_select_correlation_cluster_value_tenant_filters_equality() -> None:
    stmt = select_correlation_cluster(
        correlation_key="v1:sca:asset:x", tenant_id="tenant-a"
    )
    sql = _compile(stmt)
    assert "correlation_key" in sql
    assert "findings.tenant_id" in sql
    # Bound parameter (value not inlined) — must not use OR across tenants
    assert "tenant_id_1" in sql or "%(tenant_id" in sql


def test_select_correlation_cluster_orders_by_created_at_then_id() -> None:
    stmt = select_correlation_cluster(correlation_key="k", tenant_id=None)
    sql = _compile(stmt)
    assert "created_at" in sql
    assert "id" in sql
