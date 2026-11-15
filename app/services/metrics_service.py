def summarize_findings(findings):
    return {severity: sum(1 for f in findings if f.severity == severity)
            for severity in ("critical", "high", "medium", "low")}
