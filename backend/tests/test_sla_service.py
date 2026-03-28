from app.services.sla import SLA_DAYS


def test_sla_days_contains_expected_policy_points():
    assert SLA_DAYS[("Secret", "Critical")] == 1
    assert SLA_DAYS[("SCA", "High")] == 14
    assert SLA_DAYS[("IaC", "Low")] == 30
    assert SLA_DAYS[("SAST", "Medium")] == 60
    assert SLA_DAYS[("License", "Informational")] == 180
    assert len(SLA_DAYS) == 25
