from app.engines.risk_engine import calculate_risk, calculate_comprehensive_risk

class MockFinding:
    def __init__(self, category, severity, confidence="high"):
        self.category = category
        self.severity = severity
        self.confidence = confidence

def test_empty_findings_clean_score():
    result = calculate_comprehensive_risk([])
    assert result["overall_risk_score"] == 0.0
    assert result["health_score"] == 100.0
    assert result["health_label"] == "Excellent"

def test_critical_security_escalates_risk():
    findings = [
        MockFinding("security", "critical", "high")
    ]
    result = calculate_comprehensive_risk(findings)
    assert result["overall_risk_score"] >= 65.0
    assert result["health_score"] <= 35.0
    assert result["health_label"] in ("Needs Improvement", "Poor")

def test_backward_compatibility_helper():
    assert calculate_risk([]) == 0.0
    f_high = [MockFinding("security", "high")]
    f_low = [MockFinding("security", "low")]
    assert calculate_risk(f_high) > calculate_risk(f_low)
