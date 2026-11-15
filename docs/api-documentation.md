# ForgeGuard AI — REST API Specification

ForgeGuard AI exposes structured endpoints for programmatic integration with CI/CD runners, dashboard components, and third-party tools.

## Authentication
Session cookie authenticated via `/login` and `/register`. All protected endpoints enforce active user context and verify resource ownership.

---

### Scans & Telemetry

#### 1. `POST /scans/start`
Starts a multi-stage background scan.
- **Payload**:
  - `project_id` (int, required)
  - `categories` (array of string: `quality`, `security`, `dependency`, `architecture`)
- **Response**: Redirect to `/scans/<scan_id>`

#### 2. `GET /scans/<scan_id>/progress`
Live JSON polling endpoint for scan execution console.
- **Response**:
```json
{
  "id": 14,
  "status": "running",
  "current_stage": "Security & Secret Analysis",
  "current_stage_number": 7,
  "progress_percent": 63,
  "files_scanned": 128,
  "files_skipped": 14,
  "findings_count": 8,
  "critical_count": 1,
  "high_count": 2,
  "health_score": 76.5,
  "health_label": "Good",
  "elapsed_seconds": 12.4,
  "stages": [
    {"number": 1, "name": "Repository Validation", "status": "completed", "message": "Repository verified."},
    {"number": 7, "name": "Security & Secret Analysis", "status": "running", "message": "Scanning for credentials..."}
  ]
}
```

#### 3. `POST /scans/<scan_id>/cancel`
Cancels a running scan.

#### 4. `POST /scans/<scan_id>/retry`
Creates a new scan clone and restarts execution.

---

### Findings Management

#### 5. `GET /findings/<finding_id>`
Retrieves complete finding metadata, code snippet, explanation, and automated diff.
- **Response**:
```json
{
  "id": 42,
  "rule_id": "SEC-AWS-KEY-001",
  "category": "security",
  "severity": "critical",
  "confidence": "high",
  "file_path": "config/aws.py",
  "line_number": 12,
  "code_snippet": "-> 12 | AWS_SECRET_ACCESS_KEY = \"AKIAIOSFODNN7EXAMPLE\"",
  "title": "Hardcoded AWS Access Key Detected",
  "description": "Detected secret pattern: AKIA************MPLE",
  "technical_explanation": "An active AWS IAM Access Key ID was detected in source code...",
  "why_it_matters": "Compromised AWS keys allow unauthorized access to cloud infrastructure...",
  "recommendation": "Revoke the key immediately in AWS IAM console...",
  "suggested_fix": "os.getenv('AWS_ACCESS_KEY_ID')",
  "proposed_diff": "- AWS_KEY = \"AKIAEXAMPLEKEY123456\"\n+ import os\n+ AWS_KEY = os.environ.get(\"AWS_ACCESS_KEY_ID\")",
  "status": "open"
}
```

#### 6. `POST /findings/<finding_id>/status`
Updates finding lifecycle status.
- **Form Data**:
  - `status`: `open` | `in_progress` | `resolved` | `accepted_risk` | `false_positive` | `ignored`
  - `notes`: text reason or explanation

---

### Reports & Notifications

#### 7. `POST /reports/generate`
Generates a downloadable compliance report.
- **Form Data**:
  - `scan_id`: integer
  - `format`: `pdf` | `csv` | `json`

#### 8. `GET /api/notifications/unread-count`
Real-time topbar polling endpoint.
- **Response**:
```json
{
  "count": 2,
  "recent": [
    {
      "id": 8,
      "title": "Critical Security Alert: backend-api",
      "message": "Critical issue 'Hardcoded AWS Access Key' discovered...",
      "severity": "danger",
      "time": "11:42",
      "link": "/findings?scan_id=4&severity=critical"
    }
  ]
}
```

---

### Integrations

#### 9. `POST /api/webhooks/github`
Webhook listener for automated Git push events. Returns HTTP 200 acknowledging receipt.
