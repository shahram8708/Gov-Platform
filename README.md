# InfraGuard: Civic Infrastructure Transparency & Grievance Platform

A Flask-powered civic transparency platform that lets citizens report infrastructure issues with AI-verified evidence, discover public projects via grounded AI search, generate RTI-ready PDF reports, and surface corruption risk signals for administrators.

## Table of Contents
- Project Overview
- Key Features
- System Architecture & Stack
- Technical Deep Dive
- Installation & Setup
- Usage Guide
- Configuration & Environment
- UI Screens & Flows
- Security & Privacy
- Performance Notes
- Limitations & Known Issues
- Future Enhancements
- Business Value
- Contribution Guidelines
- License
- Conclusion

## Project Overview
- **What it does:** Collects citizen complaints with AI vision analysis, runs grounded AI project discovery, generates RTI/legal-ready PDFs, and highlights corruption risks and alerts.
- **Platform type:** Web application (Flask + SQLAlchemy) with templated front-end and AI integrations.
- **Purpose & goal:** Increase transparency, speed up grievance redressal, and provide audit-ready evidence trails for public infrastructure.
- **Real-world applications:** Civic complaint portals, public works monitoring, contractor oversight, RTI generation, department dashboards.
- **Target users:** Citizens, government officers, contractors, admins/compliance teams.
- **Industry relevance:** GovTech, civic-tech, public works, audit/compliance.
- **Vision & scope:** End-to-end pipeline from AI-assisted discovery → complaint intake → follow-ups → analytics/alerts → RTI-grade exports.

## Key Features
**Core**
- AI-assisted complaint intake with Gemini Vision: auto-detects issue type, severity, authenticity, and generates structured markdown summaries (complaints.py, ai_vision.py, ai_markdown_formatter.py).
- AI-backed project discovery with Google Search grounding (Gemini) and Perplexity fallback; validates schema and persists projects, contractors, departments, tenders, anchors integrity hashes (project_discovery.py, ai_project_discovery.py, blockchain_ready.py).
- Public transparency portal listing projects and complaints with anonymization controls (__init__.py, complaints.py, project_discovery.py).

**Major**
- RTI/legal-ready PDF generation with checksums, timelines, communications log, AI findings, and source links (rti_service.py, pdf_generator.py).
- Smart alerts + corruption intelligence (deterministic rules) with deduping and severity targeting (alert_engine.py, corruption_intelligence.py).
- Follow-up agent for unattended complaints (scheduled CLI `followup-run`) with escalating emails (app.py, follow_up_agent.py).
- Transparency dashboards with cached analytics (city, contractor, department) and grounded AI section fetch for missing project data (transparency.py, analytics_agent.py, ai_section_fetcher.py).

**Minor / Backend**
- Email audit trail and retry, attachment integrity checks, citizen confirmations, authority notifications (email_service.py).
- Offline-first complaint sync with base64 uploads (complaints.py, offline_sync.py).
- Role-based dashboards (citizen/officer/contractor/admin) and RBAC decorators (__init__.py, decorators.py if present).
- Image EXIF capture, hashing, duplicate detection, authenticity heuristics (image_utils.py, complaints.py).

**Admin/User**
- Auto-provisioned roles and default admin bootstrap (app.py, config.py).
- Email-based entity linking for access scoping (contractor/department/officer) (identity_linker.py).
- Multilingual support via JSON bundles (en, hi) with per-user locale cookies (i18n.py, translations folder).

## System Architecture & Stack
- **Architecture:** Flask app factory with blueprints for auth, complaints, projects, transparency; SQLAlchemy ORM; WTForms; server-side rendered templates; AI provider integrations; background CLI for follow-ups.
- **Backend:** Python, Flask, SQLAlchemy, Flask-Migrate, Flask-Login, Flask-WTF. Database: PostgreSQL or SQLite fallback (config.py).
- **Frontend:** Jinja2 templates under templates, CSS/JS in static (dashboard, discovery, complaints, RTI views).
- **AI/ML:** Google Gemini (vision + text with search grounding), optional Perplexity Sonar Pro (ai_project_discovery.py, ai_section_fetcher.py, ai_vision.py).
- **PDF/Reporting:** reportlab-based generator for RTI/legal exports (pdf_generator.py).
- **Caching:** In-memory home cache and analytics snapshots persisted in DB (__init__.py, analytics_agent.py).
- **Alerts & Integrity:** Smart alerts + corruption flags, blockchain-ready hashing/anchors (alert_engine.py, corruption_intelligence.py, blockchain_ready.py).
- **Data flow:** Request → blueprint → forms/validators → business logic → DB via SQLAlchemy → optional AI calls → email/alerts → template render/JSON API → response headers hardened (app.py, security.py).

## Technical Deep Dive
- **Important modules & logic**
  - App factory sets config, ensures DB existence, registers blueprints, loads user, injects alerts & i18n, security headers, creates tables, seeds roles/admin (app.py).
  - Models define roles/users, projects, contractors/departments, complaints, images/support, RTI, analytics snapshots, blockchain anchors, corruption flags, alerts with constraints/indexes (__init__.py).
  - Complaint flow: upload image → validate & hash → Gemini Vision analysis → authenticity assessment → preview → submission persists complaint + image + status history + alerts/emails → follow-ups & support images share pipeline (complaints.py).
  - Project discovery: Gemini/Perplexity prompt, strict JSON validation, schema normalization, hash & anchor, persist related entities, render markdown & map data (project_discovery.py, ai_project_discovery.py).
  - Section fetch: targeted Gemini prompt for missing fields with sources; updates records selectively; logs markdown & sources (ai_section_fetcher.py).
  - RTI: hydrate project/complaint graph, build payload, generate PDF twice to embed checksum, log audit, store snapshot (rti_service.py).
  - Analytics: aggregates severity-weighted metrics, resolution times, repeats, city overview; caches snapshots; runs corruption intelligence and auto-alerts (analytics_agent.py).
  - Security: CSP, HSTS, referrer/permissions headers, input sanitization, password policy, safe redirects, light rate tracking (security.py).
  - Emails: SMTP TLS/SSL, attachment integrity (hash + size + MIME allowlist), audit logging, retries, citizen confirmation, follow-ups (email_service.py).
- **Engineering practices:** strict schema validation, DB constraints, hashing for integrity, duplicated detection, defensive error handling, role-based access guards, cache-control for public data, audit logs across actions.

## Installation & Setup
- **Requirements:** Python 3.10+ recommended; PostgreSQL (or SQLite fallback); SMTP credentials for email; Google Gemini API key; optional Perplexity API key.
- **Clone & env**
  ```bash
  python -m venv .venv
  .\.venv\Scripts\activate
  pip install -r requirements.txt
  ```
- **Environment (examples)**
  ```bash
  set FLASK_ENV=production
  set SECRET_KEY=change-me
  set DATABASE_URL=postgresql+psycopg2://user:pass@host/db
  set GEMINI_API_KEY=your-key
  set MAIL_SERVER=smtp.example.com
  set MAIL_PORT=587
  set MAIL_USERNAME=user
  set MAIL_PASSWORD=pass
  set MAIL_USE_TLS=true
  ```
  See Configuration section for full list.
- **Run server**
  ```bash
  python app.py
  ```
  App listens on `0.0.0.0:5000` by default.
- **Database**
  - Auto-creates tables on first run.
  - Default admin seeded from `DEFAULT_ADMIN_EMAIL` / `DEFAULT_ADMIN_PASSWORD`.
- **Follow-up scheduler**
  ```bash
  flask followup-run
  ```
  (use cron/Task Scheduler).

## Usage Guide
- **Register/Login:** Create account, choose role (Citizen/Officer/Contractor). Verify email via link.
- **Dashboard:** Redirected by role to relevant dashboard pages.
- **Project Discovery:** Enter location or GPS + project types; AI fetches projects, persists, shows map + markdown; view history and detail pages; request AI section fetch to fill missing fields.
- **File a Complaint:** Choose project → upload image → AI analysis preview → confirm → submission triggers alerts/emails; view detail timeline, resend emails, add support remarks/images.
- **Offline Sync:** POST batch of offline complaints to `/complaints/offline-sync` once online.
- **Transparency Dashboard:** Public analytics with filters (severity/date/contractor/department).
- **RTI:** Generate RTI for project/complaint; view/preview/download PDF; email notification sent.
- **Alerts:** Authenticated `/api/alerts` provides role-scoped smart alerts.

## Configuration & Environment
Key variables (defaults in config.py):
- Security/session: `SECRET_KEY`, `PREFERRED_URL_SCHEME`, `WTF_CSRF_ENABLED`, cookie secure/samesite flags.
- Database: `DATABASE_URL`, `SQLITE_URL`, `POSTGRES_DB_ADMIN`, pool options.
- Email: `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_USE_TLS`, `MAIL_USE_SSL`, `MAIL_MONITOR_ADDRESS`, `MAIL_HIGHER_AUTHORITY`, `MAIL_DEFAULT_SENDER` (used in email_service).
- AI: `GEMINI_API_KEY`, `GEMINI_VISION_MODEL`, `PERPLEXITY_API_KEY` or `PERPLEXITY_API_KEYS`, `PERPLEXITY_API_URL`.
- Admin bootstrap: `DEFAULT_ADMIN_EMAIL`, `DEFAULT_ADMIN_PASSWORD`.
- Upload/storage: `COMPLAINT_UPLOAD_FOLDER`, `PROJECT_SNAPSHOT_DIR`, `RTI_REPORT_DIR`, `MAX_IMAGE_UPLOAD_BYTES`, `MAX_REQUEST_BYTES`, `TIMELAPSE_MAX_IMAGES`.
- Follow-ups: `FOLLOW_UP_FIRST_AFTER_DAYS`, `FOLLOW_UP_INTERVAL_DAYS`, `FOLLOW_UP_MAX_REMINDERS`.
- Analytics/cache: `ANALYTICS_CACHE_MINUTES`, `PUBLIC_HOME_CACHE_SECONDS`.
- Corruption rules: `REPEAT_COMPLAINTS_PER_CONTRACTOR`, `COST_OVERRUN_THRESHOLD_PCT`, `DELAY_THRESHOLD_DAYS`, `REPEAT_COMPLAINTS_PER_LOCATION`, `UNRESOLVED_COMPLAINT_THRESHOLD`, `RISK_SCORE_ALERT_THRESHOLD`, `ALERT_DEDUP_HOURS`.
- Locale: `SUPPORTED_LANGUAGES`.
- Offline: `OFFLINE_MAX_BATCH`.

## UI Screens & Flows
- Public home: grouped projects, recent complaints, activity feed (public-safe, cached).
- Role dashboards: citizen/officer/contractor/admin views under dashboard.
- Project discovery & detail: map data, status history, links, snapshots, AI markdown.
- Complaints: list/detail, timeline, email logs, support submissions, image viewers.
- Transparency dashboard: analytics charts/metrics per city/contractor/department.
- RTI: list, preview, download pages.
- Auth: register/login/resend verification templates.

## Security & Privacy
- CSP, HSTS (when HTTPS), X-Frame-Options, referrer and permissions policies applied post-response (security.py).
- CSRF protection via Flask-WTF; session/httpOnly cookies; long-lived remember cookies tuned for gov use.
- Input sanitization on args/form; safe redirect checks.
- Password policy: length ≥12, mixed case, digit, symbol.
- Attachment integrity: hash + size + MIME checks; attachment path whitelisting.
- Access control: role + entity-link checks for project/complaint visibility; public endpoints restrict to anonymized/public data.
- Audit trails: extensive logging of actions, emails, RTI events, AI prompts/responses (stdout + rotating file).
- Duplicate image detection and moderation events for abuse handling.
- Note: AI keys and SMTP credentials must be kept secret; configure HTTPS in production.

## Performance Notes
- DB connection pooling configurable; indexes on frequent filters (status, severity, ids).
- Caching: home page in-memory TTL; analytics snapshots persisted; AI section fetch rate-limited.
- Image upload size limits; email attachment size check.
- Potential latency from AI calls (Gemini/Perplexity) and SMTP; consider background job queues for scale.

## Limitations & Known Issues
- No explicit frontend build pipeline; primarily server-rendered templates.
- In-memory rate limiting (`track_attempt`) is per-process and non-persistent.
- Caching uses process memory; not shared across workers.
- AI dependencies require external connectivity and keys; failures surface as warnings.
- No explicit license file present.
- Perplexity model path marked “coming soon” in UI validation.

## Future Enhancements
- Add Redis-backed rate limiting and shared caching.
- Background task queue for emails/AI to improve latency.
- OAuth/SAML SSO for government users.
- Richer geospatial maps and timeline visualizations.
- Extend corruption intelligence with ML and cross-dataset joins.
- Add automated tests (unit/integration) and CI pipeline.
- Harden file scanning with AV/malware checks.

## Business Value
- Reduces grievance turnaround with authenticated, evidence-backed complaints.
- Increases transparency via public dashboards and RTI-ready exports.
- Provides oversight with corruption risk signals and smart alerts.
- Lowers operational overhead with AI-powered data completion and follow-ups.

## Contribution Guidelines
- Fork/branch workflow; submit PRs with clear descriptions.
- Run formatting/linting aligned with Flask/PEP8 conventions.
- Include migrations for DB schema changes.
- Add/update tests when modifying logic (where applicable).
- Avoid committing secrets; use environment variables.

## License
- No license file detected; treat as “all rights reserved” until a license is added.

## Conclusion
InfraGuard delivers an end-to-end, AI-assisted transparency stack: grounded project discovery, authentic complaint intake, smart follow-ups, corruption intelligence, and RTI-grade evidence generation—all secured with audit-friendly practices and ready for real-world civic deployment.