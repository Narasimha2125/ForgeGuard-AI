def finding_features(findings):
    severities = ("critical", "high", "medium", "low")
    return {f"count_{level}": sum(1 for item in findings if item.severity == level)
            for level in severities}
