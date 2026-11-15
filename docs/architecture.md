# ForgeGuard AI — Comprehensive System Architecture

## Overview
ForgeGuard AI is an intelligent software repository analysis, static code inspection, and security intelligence platform designed for software engineering teams. It processes raw source repositories, extracts file trees, detects languages, and executes multi-engine inspections without ever executing untrusted user code.

```
┌────────────────────────────────────────────────────────────────────────┐
│                          PRESENTATION LAYER                            │
│  Dark SaaS UI · Jinja2 · Bootstrap 5 · Chart.js · Responsive Telemetry │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
┌────────────────────────────────────▼───────────────────────────────────┐
│                       FLASK APPLICATION & REST APIS                    │
│  14 Modular Blueprints · Flask-Login · Session Auth · Role Isolation   │
└──────────────────┬─────────────────┬─────────────────┬─────────────────┘
                   │                 │                 │
┌──────────────────▼──────┐ ┌────────▼────────┐ ┌──────▼─────────────────┐
│  REPOSITORY SERVICE     │ │ SCANNER WORKER  │ │  INTEGRATIONS SERVICE  │
│  - Streamed ZIP ingest  │ │ - 11 Pipeline   │ │  - GitHub REST API     │
│  - Traversal defense    │ │   Stages        │ │  - PAT Token Store     │
│  - Zip Bomb safeguards  │ │ - Async threads │ │  - Automated Webhook   │
│  - AST File Indexer     │ │ - Live polling  │ │  - One-click import    │
└─────────────────────────┘ └────────┬────────┘ └────────────────────────┘
                                     │
┌────────────────────────────────────▼───────────────────────────────────┐
│                          ANALYSIS ENGINES LAYER                        │
├─────────────────────────┬──────────────────────┬───────────────────────┤
│ CODE QUALITY ENGINE     │ SECURITY ENGINE      │ DEPENDENCY ENGINE     │
│ - Python AST Parser     │ - Regex Secret Scan  │ - 12 Manifest Parsers │
│ - Radon Complexity (CC) │ - Token Redaction    │ - OSV.dev REST API    │
│ - Radon Maintainability │ - SQL Injection CWE  │ - Offline CVE Catalog │
│ - Long functions/args   │ - Command Injection  │ - Version semver diff │
│ - Silent exceptions     │ - Insecure Pickle    │ - Fix recommendation  │
│ - JS / TS Code Smells   │ - Broken Crypto      │                       │
└─────────────────────────┴──────────┬───────────┴───────────────────────┘
                                     │
┌────────────────────────────────────▼───────────────────────────────────┐
│                    RISK & RECOMMENDATION ENGINE                        │
│ - Weighted Risk Scoring (Security 45%, SCA 30%, Quality 25%)           │
│ - Health Score Inversion (0-100) & Qualitative Labels                  │
│ - Deterministic AI Fix Recommendations & Proposed Diffs                │
│ - Multi-format Exporters (ReportLab PDF, CSV, JSON)                    │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
┌────────────────────────────────────▼───────────────────────────────────┐
│                        DATA PERSISTENCE LAYER                          │
│  MySQL 8+ (Production) / SQLite (Development Fallback)                 │
│  15 Normalized Relational Models · Flask-Migrate / Alembic DDL         │
└────────────────────────────────────────────────────────────────────────┘
```

## Security & Trust Boundaries
1. **Zero Execution Policy**: Uploaded source code is parsed exclusively as abstract syntax trees (AST) or token streams. Code is never executed, imported, or run in the web container.
2. **ZIP File Validation**: 
   - Directory traversal (`..` path segments or absolute paths) rejected immediately.
   - Decompression ratio limits (>100:1) defend against archive bombs.
   - Configurable quotas via environment variables (`MAX_UPLOAD_SIZE_MB`, `MAX_TOTAL_EXTRACTION_MB`, `MAX_ARCHIVE_FILES`).
   - Strict destination confinement verifies that extracted files strictly resolve within the target project sandbox.
3. **Secret Redaction**: Detected passwords, API keys, AWS credentials, and tokens are automatically masked (e.g. `AKIA************CDEF`) in database records, UI previews, and generated reports.
4. **User Isolation**: Every database query is scoped to `current_user.id` to guarantee tenant isolation.
