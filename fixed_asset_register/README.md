# AssetTrack Pro
**Smart asset lifecycle and depreciation management**

## Overview
AssetTrack Pro is a professional enterprise finance application for managing fixed assets, monitoring depreciation, tracking transfers and disposals, controlling user access, and maintaining a complete audit trail.

The application is built with Flask, SQLite, SQLAlchemy, Jinja2, Bootstrap 5, and Chart.js.

## Core Modules
- Authentication and role-based access control
- User management
- Fixed asset management (enterprise form with quantity, supplier, invoice, and lifecycle fields)
- Multi-level approval workflow (draft, submitted, under review, approved, rejected)
- Straight-line depreciation engine + scenario analysis
- Asset transfer and disposal approval workflows
- Maintenance history tracking
- Physical verification and discrepancy tracking
- Document attachment management (upload, download, delete)
- Dashboard analytics and KPI monitoring
- Advanced reporting and CSV exports
- Expanded audit logging

## Features
- Secure login/logout with session authentication
- Password hashing with Werkzeug
- First-login forced password change
- Role-based access for `admin` and `viewer`
- Admin-only user management
- Full fixed asset CRUD workflow
- Approval-controlled registration, transfer, and disposal execution
- Straight-line depreciation calculations on each asset record
- Transfer and disposal history per asset
- Maintenance history per asset with next service date
- Physical verification records with discrepancy detection
- Document attachment library per asset
- Search, filters, and sorting on the asset register
- Dashboard summaries, compliance KPIs, and Chart.js analytics
- CSV export for operational and advanced reporting views
- Audit logging for authentication, asset lifecycle, approvals, maintenance, verification, and documents

## Technology Stack
- Python 3
- Flask
- Flask-SQLAlchemy
- Flask-WTF
- SQLite
- SQLAlchemy ORM
- Jinja2 templates
- HTML5 / CSS3
- Bootstrap 5
- Chart.js

## Project Structure
```text
AssetTrack Pro Application/
│
├── app.py
├── models.py
├── seed_data.py
├── requirements.txt
├── README.md
├── static/
│   └── css/
│       └── style.css
└── templates/
    ├── base.html
    ├── login.html
    ├── change_password.html
    ├── dashboard.html
    ├── asset_list.html
    ├── asset_form.html
    ├── asset_detail.html
    ├── approvals_list.html
    ├── approval_review.html
    ├── approval_report.html
    ├── reports_hub.html
    ├── depreciation_scenario.html
    ├── verification_form.html
    ├── verification_report.html
    ├── maintenance_form.html
    ├── maintenance_list.html
    ├── maintenance_report.html
    ├── document_upload_form.html
    ├── document_list.html
    ├── document_report.html
    ├── depreciation_report.html
    ├── department_report.html
    ├── disposed_report.html
    ├── end_of_life_report.html
    ├── transfer_form.html
    ├── disposal_form.html
    ├── audit_logs.html
    ├── user_list.html
    ├── user_form.html
    ├── user_detail.html
    └── reset_password.html
```

## Installation
1. Open the project in VS Code.
2. Create and activate a virtual environment.

macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows:
```bash
python -m venv .venv
.venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Run the Application
From the application directory (the folder containing `app.py`):
```bash
python app.py
```

Open the application in a browser:
- `http://127.0.0.1:5000`

## Default Login Credentials
### Admin User
- Username: `admin`
- Password: `Admin123!`
- Must change password on first login: Yes

### Viewer User
- Username: `viewer`
- Password: `Viewer123!`
- Must change password on first login: Yes

## Depreciation Formula
The system uses straight-line depreciation:

```text
annual_depreciation = (purchase_cost - salvage_value) / useful_life
```

Business rules applied:
- `years_used = current year - purchase year` with a minimum of `0`
- accumulated depreciation cannot exceed `purchase_cost - salvage_value`
- net book value cannot fall below salvage value

## Reporting Module
Available report routes:
- `/report/depreciation`
- `/report/depreciation/scenario`
- `/report/departments`
- `/report/disposed`
- `/report/end-of-life`
- `/report/verifications`
- `/report/maintenance`
- `/report/approvals`
- `/report/documents`

## Export Features
Available CSV export routes:
- `/export/assets`
- `/export/depreciation`
- `/export/disposed`
- `/export/departments`
- `/export/verifications`
- `/export/maintenance`
- `/export/approvals`
- `/export/documents`

Each export returns a downloadable CSV file.

## Notes
- Database tables are initialized automatically on first run.
- Sample users are seeded automatically if no users exist.
- Sample fixed assets are seeded automatically if the asset register is empty.
- Legacy unused tables from earlier versions are removed automatically during initialization.

## Enterprise Workflow Notes
- New asset registration, transfer, and disposal use approval requests; final changes apply only after approval.
- Document uploads are stored under `uploads/<asset_id>/` with controlled file extensions.
- Verification records automatically flag discrepancies when actual state differs from expected state.
