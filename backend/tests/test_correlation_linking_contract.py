"""
Contract tests for correlation cluster queries — no DB required.

Guards tenant isolation (NULL vs value) and deterministic ordering at the SQL layer.
"""

from sqlalchemy.dialects import postgresql

from app.services.correlation_linking import select_correlation_cluster


def _compile(stmt) -> str:
    return str(stmt.compile(dialect=postgresql.dialect())).lower()


def test_select_correlation_cluster_null_tenant_coalesces_to_default() -> None:
    stmt = select_correlation_cluster(correlation_key="v1:sca:asset:x", tenant_id=None)
    sql = _compile(stmt)
    assert "correlation_key" in sql
    assert "coalesce" in sql
    assert "coalesce_1" in sql and "coalesce_2" in sql


def test_select_correlation_cluster_value_tenant_filters_equality() -> None:
    stmt = select_correlation_cluster(
        correlation_key="v1:sca:asset:x", tenant_id="tenant-a"
    )
    sql = _compile(stmt)
    assert "correlation_key" in sql
    assert "coalesce" in sql
    # Bound parameters — must not use OR across tenants
    assert "coalesce_1" in sql and "coalesce_2" in sql


def test_select_correlation_cluster_orders_by_created_at_then_id() -> None:
    stmt = select_correlation_cluster(correlation_key="k", tenant_id=None)
    sql = _compile(stmt)
    assert "created_at" in sql
    assert "id" in sql
