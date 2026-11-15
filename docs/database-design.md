# ForgeGuard AI — Normalized Database Architecture

ForgeGuard AI uses SQLAlchemy ORM with support for MySQL Community Edition and local SQLite development fallback. All 15 relational tables adhere to third normal form (3NF) with primary keys, indexes, foreign key constraints, and cascade delete rules.

## Relational Entity Schema

### 1. `users`
- `id` (INT, PK, Auto-Increment)
- `name` (VARCHAR(100), NOT NULL)
- `email` (VARCHAR(160), UNIQUE, INDEX, NOT NULL)
- `password_hash` (VARCHAR(255), NOT NULL)
- `role` (VARCHAR(20), DEFAULT 'developer')
- `avatar_url` (VARCHAR(255), NULL)
- `created_at`, `updated_at` (DATETIME)

### 2. `user_settings`
- `id` (INT, PK)
- `user_id` (INT, FK -> users.id, UNIQUE, INDEX)
- `theme` (VARCHAR(20), DEFAULT 'dark')
- `scan_timeout_seconds` (INT, DEFAULT 300)
- `default_excluded_dirs` (TEXT)
- `max_file_size_mb` (INT, DEFAULT 50)
- `notify_on_scan_complete` (BOOLEAN)
- `notify_on_critical_findings` (BOOLEAN)
- `notify_on_security_alerts` (BOOLEAN)
- `github_access_token` (VARCHAR(255), NULL)

### 3. `projects`
- `id` (INT, PK)
- `user_id` (INT, FK -> users.id, INDEX)
- `name` (VARCHAR(120), NOT NULL)
- `description` (TEXT)
- `language` (VARCHAR(60))
- `source_path` (VARCHAR(500))
- `archive_filename` (VARCHAR(255))
- `total_size_bytes` (BIGINT)
- `file_count` (INT)
- `excluded_dirs` (TEXT)
- `created_at`, `updated_at` (DATETIME)

### 4. `project_files`
- `id` (INT, PK)
- `project_id` (INT, FK -> projects.id, INDEX)
- `file_path` (VARCHAR(500), NOT NULL)
- `relative_path` (VARCHAR(500), NOT NULL)
- `file_name` (VARCHAR(255), NOT NULL)
- `extension` (VARCHAR(50))
- `file_size_bytes` (BIGINT)
- `line_count` (INT)
- `language` (VARCHAR(50))
- `is_analyzed` (BOOLEAN)

### 5. `scans`
- `id` (INT, PK)
- `project_id` (INT, FK -> projects.id, INDEX)
- `status` (VARCHAR(30)) — pending, running, completed, failed, cancelled
- `current_stage` (VARCHAR(100))
- `current_stage_number` (INT)
- `progress_percent` (INT)
- `files_scanned` (INT)
- `files_skipped` (INT)
- `findings_count` (INT)
- `critical_count`, `high_count`, `medium_count`, `low_count`, `info_count` (INT)
- `risk_score` (FLOAT)
- `health_score` (FLOAT)
- `health_label` (VARCHAR(30)) — Excellent, Good, Needs Improvement, Poor
- `security_score`, `quality_score`, `dependency_score`, `maintainability_score` (FLOAT)
- `error_message` (TEXT)
- `started_at`, `completed_at`, `created_at` (DATETIME)

### 6. `scan_stages`
- `id` (INT, PK)
- `scan_id` (INT, FK -> scans.id, INDEX)
- `stage_number` (INT) — 1 to 11
- `stage_name` (VARCHAR(100))
- `status` (VARCHAR(30))
- `message` (VARCHAR(255))
- `started_at`, `completed_at` (DATETIME)

### 7. `findings`
- `id` (INT, PK)
- `project_id` (INT, FK -> projects.id, INDEX)
- `scan_id` (INT, FK -> scans.id, INDEX)
- `rule_id` (VARCHAR(100), INDEX)
- `category` (VARCHAR(50), INDEX) — security, code_quality, dependency, architecture
- `severity` (VARCHAR(20), INDEX) — critical, high, medium, low, info
- `confidence` (VARCHAR(20)) — high, medium, low
- `file_path` (VARCHAR(500), INDEX)
- `line_number` (INT)
- `column_number` (INT)
- `code_snippet` (TEXT)
- `title` (VARCHAR(255))
- `description`, `technical_explanation`, `why_it_matters`, `recommendation`, `suggested_fix` (TEXT)
- `detection_tool` (VARCHAR(100))
- `fingerprint` (VARCHAR(64), INDEX)
- `status` (VARCHAR(30), INDEX) — open, in_progress, resolved, accepted_risk, false_positive, ignored
- `resolution_notes` (TEXT)
- `created_at`, `updated_at` (DATETIME)

### 8. `project_metrics`
- `id` (INT, PK)
- `scan_id` (INT, FK -> scans.id, INDEX)
- `metric_category` (VARCHAR(50))
- `metric_name` (VARCHAR(100), INDEX)
- `metric_value` (FLOAT)

### 9. `risk_assessments`
- `id` (INT, PK)
- `scan_id` (INT, FK -> scans.id, UNIQUE, INDEX)
- `overall_risk_score`, `security_risk`, `quality_risk`, `dependency_risk` (FLOAT)
- `risk_level` (VARCHAR(30))
- `explanation` (TEXT)

### 10. `recommendations`
- `id` (INT, PK)
- `finding_id` (INT, FK -> findings.id, INDEX)
- `priority` (VARCHAR(20))
- `title` (VARCHAR(255))
- `plain_explanation`, `technical_explanation`, `proposed_diff`, `doc_links` (TEXT)

### 11. `notifications`
- `id` (INT, PK)
- `user_id` (INT, FK -> users.id, INDEX)
- `title` (VARCHAR(200))
- `message` (TEXT)
- `notification_type` (VARCHAR(50))
- `severity` (VARCHAR(20))
- `link_url` (VARCHAR(300))
- `is_read` (BOOLEAN, INDEX)

### 12. `reports`
- `id` (INT, PK)
- `scan_id` (INT, FK -> scans.id, INDEX)
- `project_id` (INT, FK -> projects.id, INDEX)
- `user_id` (INT, FK -> users.id, INDEX)
- `report_format` (VARCHAR(10)) — pdf, csv, json
- `file_name` (VARCHAR(255))
- `file_path` (VARCHAR(500))
- `file_size_bytes` (BIGINT)

### 13. `integrations`
- `id` (INT, PK)
- `user_id` (INT, FK -> users.id, INDEX)
- `provider` (VARCHAR(50)) — github
- `account_name` (VARCHAR(100))
- `access_token` (VARCHAR(255))
- `is_active` (BOOLEAN)

### 14. `scan_comparisons`
- `id` (INT, PK)
- `user_id` (INT, FK -> users.id, INDEX)
- `project_id` (INT, FK -> projects.id, INDEX)
- `base_scan_id` (INT, FK -> scans.id)
- `target_scan_id` (INT, FK -> scans.id)
- `new_findings_count`, `resolved_findings_count`, `persistent_findings_count` (INT)
- `health_score_diff`, `risk_diff` (FLOAT)

### 15. `audit_logs`
- `id` (INT, PK)
- `user_id` (INT, FK -> users.id, INDEX)
- `action` (VARCHAR(100), INDEX)
- `resource_type` (VARCHAR(50))
- `resource_id` (VARCHAR(100))
- `details` (TEXT)
- `ip_address` (VARCHAR(45))
