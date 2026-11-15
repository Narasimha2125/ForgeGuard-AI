SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
    "info": 0.2
}

CONFIDENCE_MULTIPLIERS = {
    "high": 1.0,
    "medium": 0.8,
    "low": 0.5
}

def calculate_category_risk(findings, category_name: str, max_scale: float = 50.0) -> float:
    cat_findings = [f for f in findings if (getattr(f, "category", "") or "").lower() == category_name.lower()]
    if not cat_findings:
        return 0.0
    raw_points = 0.0
    for f in cat_findings:
        sev = getattr(f, "severity", "low").lower()
        conf = getattr(f, "confidence", "medium").lower()
        w = SEVERITY_WEIGHTS.get(sev, 1.0)
        c = CONFIDENCE_MULTIPLIERS.get(conf, 0.8)
        raw_points += (w * c)
    # Bounded logarithmic-linear scaling from 0 to 100
    risk = min(100.0, (raw_points / max_scale) * 100.0)
    return round(risk, 1)


def calculate_comprehensive_risk(findings):
    if not findings:
        return {
            "overall_risk_score": 0.0,
            "security_risk": 0.0,
            "quality_risk": 0.0,
            "dependency_risk": 0.0,
            "risk_level": "Low",
            "health_score": 100.0,
            "health_label": "Excellent",
            "security_score": 100.0,
            "quality_score": 100.0,
            "dependency_score": 100.0,
            "maintainability_score": 100.0,
            "explanation": "No active quality, security, or dependency findings detected. Repository is clean."
        }

    sec_risk = calculate_category_risk(findings, "security", max_scale=40.0)
    qual_risk = calculate_category_risk(findings, "code_quality", max_scale=60.0)
    dep_risk = calculate_category_risk(findings, "dependency", max_scale=30.0)

    # Weighted Overall Risk Score: Security (45%), Dependency (30%), Code Quality (25%)
    overall_risk = (sec_risk * 0.45) + (dep_risk * 0.30) + (qual_risk * 0.25)
    
    # Critical issue escalation: if any critical finding exists, overall risk is at least 65
    has_critical = any(getattr(f, "severity", "").lower() == "critical" for f in findings)
    if has_critical and overall_risk < 65.0:
        overall_risk = 65.0

    overall_risk = round(min(100.0, max(0.0, overall_risk)), 1)

    if overall_risk >= 75.0:
        risk_level = "Critical"
    elif overall_risk >= 50.0:
        risk_level = "High"
    elif overall_risk >= 25.0:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Corresponding Health Scores (0 to 100, where 100 is best)
    health_score = round(max(0.0, 100.0 - overall_risk), 1)
    security_score = round(max(0.0, 100.0 - sec_risk), 1)
    quality_score = round(max(0.0, 100.0 - qual_risk), 1)
    dependency_score = round(max(0.0, 100.0 - dep_risk), 1)
    maintainability_score = round(max(0.0, 100.0 - (qual_risk * 0.8)), 1)

    if health_score >= 90.0:
        health_label = "Excellent"
    elif health_score >= 70.0:
        health_label = "Good"
    elif health_score >= 50.0:
        health_label = "Needs Improvement"
    else:
        health_label = "Poor"

    explanation = (
        f"Score calculated from {len(findings)} findings. "
        f"Security risk: {sec_risk}% (weight 45%), "
        f"Dependency risk: {dep_risk}% (weight 30%), "
        f"Code quality risk: {qual_risk}% (weight 25%). "
        f"Project health rated '{health_label}' with composite score {health_score}/100."
    )

    return {
        "overall_risk_score": overall_risk,
        "security_risk": sec_risk,
        "quality_risk": qual_risk,
        "dependency_risk": dep_risk,
        "risk_level": risk_level,
        "health_score": health_score,
        "health_label": health_label,
        "security_score": security_score,
        "quality_score": quality_score,
        "dependency_score": dependency_score,
        "maintainability_score": maintainability_score,
        "explanation": explanation
    }


def calculate_risk(findings):
    """Backward compatibility with starter helper."""
    res = calculate_comprehensive_risk(findings)
    return res["overall_risk_score"]
