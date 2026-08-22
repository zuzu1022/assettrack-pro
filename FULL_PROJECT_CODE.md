# AssetTrack Pro - Full Project Code

## 1. Complete folder structure
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
    ├── depreciation_report.html
    ├── depreciation_scenario.html
    ├── department_report.html
    ├── disposed_report.html
    ├── end_of_life_report.html
    ├── verification_form.html
    ├── verification_report.html
    ├── maintenance_form.html
    ├── maintenance_list.html
    ├── maintenance_report.html
    ├── document_list.html
    ├── document_upload_form.html
    ├── document_report.html
    ├── transfer_form.html
    ├── disposal_form.html
    ├── audit_logs.html
    ├── user_list.html
    ├── user_form.html
    ├── user_detail.html
    └── reset_password.html
```

## 2. Full code for app.py
```python
import csv
import io
import json
import os
import re
import uuid
from datetime import date, datetime
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from models import (
    ApprovalRequest,
    Asset,
    AssetDisposal,
    AssetDocument,
    AssetMaintenance,
    AssetTransfer,
    AssetVerification,
    AuditLog,
    User,
    db,
    init_db,
)
from seed_data import seed_sample_data


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///assets.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "university-fixed-asset-secret-key"
app.config["WTF_CSRF_ENABLED"] = True
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

csrf = CSRFProtect(app)
init_db(app)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

USER_ROLES = ["admin", "viewer"]
STATUS_OPTIONS = ["Active", "Under Maintenance", "Disposed"]
FORM_STATUS_OPTIONS = ["Active", "Under Maintenance"]
ASSET_CONDITION_OPTIONS = ["New", "Good", "Fair", "Poor"]
APPROVAL_STATUS_OPTIONS = ["draft", "submitted", "under_review", "approved", "rejected"]
APPROVAL_DECISION_OPTIONS = ["under_review", "approved", "rejected"]
TRANSFER_PENDING_STATUSES = {"draft", "submitted"}
VERIFICATION_STATUS_OPTIONS = ["verified", "discrepancy_found", "missing"]
DOCUMENT_TYPE_OPTIONS = [
    "invoice",
    "warranty",
    "service_report",
    "disposal_form",
    "transfer_form",
    "asset_image",
    "other",
]
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "doc", "docx"}
DEFAULT_CATEGORY_OPTIONS = [
    "Furniture",
    "Industrial Equipment",
    "IT Equipment",
    "Office Equipment",
    "Power Equipment",
    "Vehicles",
]
DEFAULT_DEPARTMENT_OPTIONS = [
    "Administration",
    "Facilities",
    "Finance",
    "Human Resources",
    "Information Technology",
    "Maintenance",
    "Manufacturing",
    "Operations",
]
DEPARTMENT_CODE_MAP = {
    "Administration": "ADM",
    "Facilities": "FAC",
    "Finance": "FIN",
    "Human Resources": "HR",
    "Information Technology": "IT",
    "Maintenance": "MNT",
    "Manufacturing": "MFG",
    "Operations": "OPS",
}
CATEGORY_CODE_MAP = {
    "Furniture": "FUR",
    "Industrial Equipment": "MCH",
    "IT Equipment": "ITM",
    "Office Equipment": "OFF",
    "Power Equipment": "GEN",
    "Vehicles": "VEH",
}


with app.app_context():
    seed_sample_data()


@app.before_request
def load_current_user():
    g.current_user = None
    user_id = session.get("user_id")
    if not user_id:
        return

    user = db.session.get(User, user_id)
    if user and user.is_active:
        g.current_user = user
    else:
        session.clear()
        return

    if (
        g.current_user
        and g.current_user.must_change_password
        and request.endpoint
        and request.endpoint not in {"change_password", "logout", "login", "static"}
    ):
        flash("Please change your password before continuing.", "warning")
        return redirect(url_for("change_password"))


@app.context_processor
def inject_current_user():
    return {"current_user": g.get("current_user")}


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not g.current_user:
            flash("Please log in to continue.", "danger")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not g.current_user:
            flash("Please log in to continue.", "danger")
            return redirect(url_for("login", next=request.path))
        if g.current_user.role != "admin":
            log_audit(
                "authorization failure",
                details=f"Blocked admin-only access to {request.path} for user {g.current_user.username}.",
            )
            db.session.commit()
            flash("Access denied. Admin privileges are required.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapped_view


@app.template_filter("bhd")
def bhd_format(value):
    try:
        return "BD {:,.3f}".format(float(value))
    except (ValueError, TypeError):
        return "BD 0.000"


def strip_html(value):
    return re.sub(r"<[^>]*>", "", (value or "")).strip()


def is_valid_email(email):
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email or ""))


def hash_password(password):
    return generate_password_hash(password, method="pbkdf2:sha256")


def build_code_segment(value, fallback="GEN", mapping=None):
    if mapping and value in mapping:
        return mapping[value]

    tokens = re.findall(r"[A-Za-z0-9]+", (value or "").upper())
    if not tokens:
        return fallback
    if len(tokens) >= 2:
        return "".join(token[0] for token in tokens[:3])[:3]
    return tokens[0][:3]


def parse_optional_date(value):
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return "invalid"


def json_safe(value):
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    return value


def normalize_approval_status(status):
    normalized = (status or "").strip().lower()
    if normalized in TRANSFER_PENDING_STATUSES:
        return "pending"
    if normalized in {"under_review", "approved", "rejected", "pending"}:
        return normalized
    return "pending"


def approval_status_label(status):
    normalized = normalize_approval_status(status)
    labels = {
        "pending": "Pending",
        "under_review": "Under Review",
        "approved": "Approved",
        "rejected": "Rejected",
    }
    return labels.get(normalized, "Pending")


def parse_approval_payload(approval):
    try:
        return json.loads(approval.request_payload or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}


def build_transfer_workflow_view(approval):
    if not approval:
        return None

    payload = parse_approval_payload(approval)
    normalized_status = normalize_approval_status(approval.status)
    transfer_date = parse_optional_date(payload.get("transfer_date"))

    return {
        "id": approval.id,
        "status": normalized_status,
        "status_label": approval_status_label(approval.status),
        "submitted_by": approval.submitted_by,
        "submission_date": approval.submission_date,
        "reviewed_by": approval.reviewed_by,
        "approved_by": approval.approved_by,
        "approval_date": approval.approval_date,
        "rejection_reason": approval.rejection_reason,
        "target_department": payload.get("new_department"),
        "transfer_date": transfer_date if transfer_date != "invalid" else None,
        "reason": payload.get("reason"),
    }


def get_form_options():
    categories = sorted(
        set(
            DEFAULT_CATEGORY_OPTIONS
            + [row[0] for row in db.session.query(Asset.category).distinct().all() if row[0]]
        )
    )
    departments = sorted(
        set(
            DEFAULT_DEPARTMENT_OPTIONS
            + [row[0] for row in db.session.query(Asset.department).distinct().all() if row[0]]
        )
    )
    return categories, departments


def generate_asset_code(category, department, asset=None):
    if not category or not department:
        return ""

    dept_code = build_code_segment(department, fallback="DEP", mapping=DEPARTMENT_CODE_MAP)
    category_code = build_code_segment(category, fallback="CAT", mapping=CATEGORY_CODE_MAP)
    base_code = f"{dept_code}-{category_code}"
    highest_sequence = 0

    for existing in Asset.query.order_by(Asset.asset_code.asc()).all():
        if asset and existing.id == asset.id:
            continue
        suffix = existing.asset_code.rsplit("-", 1)[-1]
        if suffix.isdigit():
            highest_sequence = max(highest_sequence, int(suffix))

    return f"{base_code}-{highest_sequence + 1:03d}"


def preview_asset_code(category, department):
    if not category or not department:
        return ""
    dept_code = build_code_segment(department, fallback="DEP", mapping=DEPARTMENT_CODE_MAP)
    category_code = build_code_segment(category, fallback="CAT", mapping=CATEGORY_CODE_MAP)
    return f"{dept_code}-{category_code}-###"


def generate_invoice_number(reference_date=None, asset=None):
    target = reference_date or datetime.utcnow()
    period_code = target.strftime("%Y%m")
    prefix = f"INV-{period_code}-"
    highest_sequence = 0

    for existing in Asset.query.order_by(Asset.id.asc()).all():
        if asset and existing.id == asset.id:
            continue
        invoice_number = (existing.invoice_number or "").strip().upper()
        if not invoice_number.startswith(prefix):
            continue
        suffix = invoice_number.replace(prefix, "", 1)
        if suffix.isdigit():
            highest_sequence = max(highest_sequence, int(suffix))

    return f"{prefix}{highest_sequence + 1:04d}"


def preview_invoice_number():
    return generate_invoice_number()


def allowed_file(filename):
    if "." not in filename:
        return False
    extension = filename.rsplit(".", 1)[1].lower()
    return extension in ALLOWED_EXTENSIONS


def absolute_document_path(stored_path):
    if os.path.isabs(stored_path):
        return stored_path
    return os.path.join(app.root_path, stored_path)


def log_audit(action, asset=None, details="", user=None):
    actor = user or g.get("current_user")
    username = actor.username if actor else "system"
    user_id = actor.id if actor else None
    asset_id = asset.id if asset else None
    asset_name = asset.asset_name if asset else None

    db.session.add(
        AuditLog(
            user_id=user_id,
            username=username,
            action=action,
            asset_id=asset_id,
            asset_name=asset_name,
            details=details,
        )
    )


def export_csv(filename, headers, rows):
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(headers)
    writer.writerows(rows)
    response = make_response(stream.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response


def is_valid_role(role):
    return role in USER_ROLES


def is_unique_username(username, current_user_id=None):
    query = User.query.filter(func.lower(User.username) == username.lower())
    if current_user_id is not None:
        query = query.filter(User.id != current_user_id)
    return query.first() is None


def is_unique_email(email, current_user_id=None):
    query = User.query.filter(func.lower(User.email) == email.lower())
    if current_user_id is not None:
        query = query.filter(User.id != current_user_id)
    return query.first() is None


def active_admin_count():
    return User.query.filter_by(role="admin", is_active=True).count()


def build_asset_query(args, base_query=None):
    search = args.get("search", "").strip()
    category = args.get("category", "").strip()
    department = args.get("department", "").strip()
    status = args.get("status", "").strip()
    supplier = args.get("supplier", "").strip()
    condition = args.get("condition", "").strip()
    start_date = args.get("start_date", "").strip()
    end_date = args.get("end_date", "").strip()
    min_cost = args.get("min_cost", "").strip()
    max_cost = args.get("max_cost", "").strip()
    sort_by = args.get("sort_by", "asset_name").strip()
    sort_dir = args.get("sort_dir", "asc").strip().lower()

    query = base_query or Asset.query
    if search:
        query = query.filter(
            or_(
                Asset.asset_name.ilike(f"%{search}%"),
                Asset.asset_code.ilike(f"%{search}%"),
                Asset.serial_number.ilike(f"%{search}%"),
                Asset.location.ilike(f"%{search}%"),
                Asset.invoice_number.ilike(f"%{search}%"),
            )
        )
    if category:
        query = query.filter(Asset.category == category)
    if department:
        query = query.filter(Asset.department == department)
    if status:
        query = query.filter(Asset.status == status)
    if supplier:
        query = query.filter(Asset.supplier.ilike(f"%{supplier}%"))
    if condition:
        query = query.filter(Asset.asset_condition == condition)

    parsed_start = parse_optional_date(start_date)
    parsed_end = parse_optional_date(end_date)
    if parsed_start and parsed_start != "invalid":
        query = query.filter(Asset.purchase_date >= parsed_start)
    if parsed_end and parsed_end != "invalid":
        query = query.filter(Asset.purchase_date <= parsed_end)

    try:
        if min_cost != "":
            query = query.filter(Asset.purchase_cost >= float(min_cost))
    except ValueError:
        pass
    try:
        if max_cost != "":
            query = query.filter(Asset.purchase_cost <= float(max_cost))
    except ValueError:
        pass

    sort_map = {
        "asset_name": Asset.asset_name,
        "purchase_date": Asset.purchase_date,
        "purchase_cost": Asset.purchase_cost,
        "department": Asset.department,
        "status": Asset.status,
    }
    sort_column = sort_map.get(sort_by, Asset.asset_name)
    if sort_dir == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    return query, {
        "search": search,
        "category": category,
        "department": department,
        "status": status,
        "supplier": supplier,
        "condition": condition,
        "start_date": start_date,
        "end_date": end_date,
        "min_cost": min_cost,
        "max_cost": max_cost,
        "sort_by": sort_by,
        "sort_dir": sort_dir,
    }


def get_asset_form_data(asset=None):
    data = {
        "asset_name": strip_html(request.form.get("asset_name")),
        "asset_code": strip_html(request.form.get("asset_code")),
        "category": strip_html(request.form.get("category")),
        "department": strip_html(request.form.get("department")),
        "purchase_date": request.form.get("purchase_date", "").strip(),
        "quantity": request.form.get("quantity", "").strip(),
        "purchase_cost": request.form.get("purchase_cost", "").strip(),
        "salvage_value": request.form.get("salvage_value", "").strip(),
        "useful_life": request.form.get("useful_life", "").strip(),
        "status": request.form.get("status", "Active").strip(),
        "supplier": strip_html(request.form.get("supplier")),
        "serial_number": strip_html(request.form.get("serial_number")),
        "location": strip_html(request.form.get("location")),
        "warranty_expiry": request.form.get("warranty_expiry", "").strip(),
        "asset_condition": strip_html(request.form.get("asset_condition", "Good")),
    }

    if data["salvage_value"] == "":
        data["salvage_value"] = "0"
    if data["quantity"] == "":
        data["quantity"] = "1"

    errors = []
    if not data["asset_name"]:
        errors.append("Asset name cannot be empty.")
    if not data["category"]:
        errors.append("Category cannot be empty.")
    if not data["department"]:
        errors.append("Department cannot be empty.")
    if data["status"] not in FORM_STATUS_OPTIONS:
        errors.append("Invalid asset status selected.")
    if data["asset_condition"] not in ASSET_CONDITION_OPTIONS:
        errors.append("Invalid asset condition selected.")

    purchase_date_obj = parse_optional_date(data["purchase_date"])
    if purchase_date_obj is None:
        errors.append("Purchase date is required.")
    elif purchase_date_obj == "invalid":
        purchase_date_obj = None
        errors.append("Purchase date must be valid.")

    warranty_expiry_obj = parse_optional_date(data["warranty_expiry"])
    if warranty_expiry_obj == "invalid":
        warranty_expiry_obj = None
        errors.append("Warranty expiry must be a valid date.")

    try:
        quantity_value = int(data["quantity"])
        if quantity_value <= 0:
            errors.append("Quantity must be greater than 0.")
    except ValueError:
        quantity_value = None
        errors.append("Quantity must be a valid integer.")

    try:
        purchase_cost_value = float(data["purchase_cost"])
        if purchase_cost_value < 0:
            errors.append("Purchase cost must be greater than or equal to 0.")
    except ValueError:
        purchase_cost_value = None
        errors.append("Purchase cost must be a valid number.")

    try:
        salvage_value_value = float(data["salvage_value"])
        if salvage_value_value < 0:
            errors.append("Salvage value must be greater than or equal to 0.")
    except ValueError:
        salvage_value_value = None
        errors.append("Salvage value must be a valid number.")

    try:
        useful_life_value = int(data["useful_life"])
        if useful_life_value <= 0:
            errors.append("Useful life must be greater than 0.")
    except ValueError:
        useful_life_value = None
        errors.append("Useful life must be a valid integer.")

    if (
        purchase_cost_value is not None
        and salvage_value_value is not None
        and salvage_value_value > purchase_cost_value
    ):
        errors.append("Salvage value cannot be greater than purchase cost.")

    generated_code = data["asset_code"] or (asset.asset_code if asset else None)
    if asset is None:
        generated_code = generate_asset_code(data["category"], data["department"])

    invoice_number = asset.invoice_number if asset and asset.invoice_number else None
    if not invoice_number:
        invoice_number = generate_invoice_number(asset=asset)

    if not generated_code:
        errors.append("Asset code will be generated after category and department are provided.")
    else:
        existing = Asset.query.filter_by(asset_code=generated_code).first()
        if existing and (asset is None or existing.id != asset.id):
            errors.append("Generated asset code must be unique. Please adjust the asset details and try again.")

    return {
        "asset_name": data["asset_name"],
        "asset_code": generated_code,
        "category": data["category"],
        "department": data["department"],
        "purchase_date": purchase_date_obj,
        "quantity": quantity_value,
        "purchase_cost": purchase_cost_value,
        "salvage_value": salvage_value_value,
        "useful_life": useful_life_value,
        "status": data["status"],
        "supplier": data["supplier"] or None,
        "invoice_number": invoice_number,
        "serial_number": data["serial_number"] or None,
        "location": data["location"] or None,
        "warranty_expiry": warranty_expiry_obj,
        "asset_condition": data["asset_condition"],
    }, errors


def get_transfer_form_data(asset):
    new_department = strip_html(request.form.get("new_department"))
    transfer_date = parse_optional_date(request.form.get("transfer_date", ""))
    reason = strip_html(request.form.get("reason"))
    comments = strip_html(request.form.get("comments"))
    errors = []

    if not new_department:
        errors.append("New department is required.")
    elif new_department == asset.department:
        errors.append("New department must be different from the current department.")
    if transfer_date is None:
        errors.append("Transfer date is required.")
    elif transfer_date == "invalid":
        transfer_date = None
        errors.append("Transfer date must be valid.")
    elif transfer_date < asset.purchase_date:
        errors.append("Transfer date cannot be earlier than purchase date.")
    if not reason:
        errors.append("Transfer reason is required.")

    return {
        "new_department": new_department,
        "transfer_date": transfer_date,
        "reason": reason,
        "comments": comments,
    }, errors


def get_disposal_form_data(asset):
    disposal_date = parse_optional_date(request.form.get("disposal_date", ""))
    disposal_reason = strip_html(request.form.get("disposal_reason"))
    disposal_notes = strip_html(request.form.get("disposal_notes"))
    disposal_value_raw = request.form.get("disposal_value", "").strip()
    comments = strip_html(request.form.get("comments"))
    errors = []

    if disposal_date is None:
        errors.append("Disposal date is required.")
    elif disposal_date == "invalid":
        disposal_date = None
        errors.append("Disposal date must be valid.")
    elif disposal_date < asset.purchase_date:
        errors.append("Disposal date cannot be earlier than purchase date.")
    if not disposal_reason:
        errors.append("Disposal reason is required.")

    try:
        disposal_value = float(disposal_value_raw or 0)
        if disposal_value < 0:
            errors.append("Disposal value must be greater than or equal to 0.")
    except ValueError:
        disposal_value = 0
        errors.append("Disposal value must be a valid number.")

    return {
        "disposal_date": disposal_date,
        "disposal_reason": disposal_reason,
        "disposal_value": disposal_value,
        "disposal_notes": disposal_notes or None,
        "comments": comments,
    }, errors


def get_maintenance_form_data(asset):
    maintenance_date = parse_optional_date(request.form.get("maintenance_date", ""))
    maintenance_type = strip_html(request.form.get("maintenance_type"))
    service_provider = strip_html(request.form.get("service_provider"))
    maintenance_cost_raw = request.form.get("maintenance_cost", "").strip()
    next_maintenance_date = parse_optional_date(request.form.get("next_maintenance_date", ""))
    notes = strip_html(request.form.get("notes"))
    errors = []

    if maintenance_date is None:
        errors.append("Maintenance date is required.")
    elif maintenance_date == "invalid":
        maintenance_date = None
        errors.append("Maintenance date must be valid.")

    if not maintenance_type:
        errors.append("Maintenance type is required.")
    if not service_provider:
        errors.append("Service provider is required.")

    try:
        maintenance_cost = float(maintenance_cost_raw or 0)
        if maintenance_cost < 0:
            errors.append("Maintenance cost must be greater than or equal to 0.")
    except ValueError:
        maintenance_cost = 0
        errors.append("Maintenance cost must be a valid number.")

    if next_maintenance_date == "invalid":
        next_maintenance_date = None
        errors.append("Next maintenance date must be valid.")

    if maintenance_date and maintenance_date != "invalid" and next_maintenance_date:
        if next_maintenance_date < maintenance_date:
            errors.append("Next maintenance date cannot be earlier than maintenance date.")

    return {
        "asset_id": asset.id,
        "maintenance_date": maintenance_date,
        "maintenance_type": maintenance_type,
        "service_provider": service_provider,
        "maintenance_cost": maintenance_cost,
        "next_maintenance_date": next_maintenance_date,
        "notes": notes or None,
        "created_by": g.current_user.username,
    }, errors


def get_verification_form_data(asset):
    verification_date = parse_optional_date(request.form.get("verification_date", ""))
    expected_location = strip_html(request.form.get("expected_location")) or (asset.location or asset.department or "")
    actual_location = strip_html(request.form.get("actual_location"))
    expected_condition = strip_html(request.form.get("expected_condition")) or (asset.asset_condition or "")
    actual_condition = strip_html(request.form.get("actual_condition"))
    discrepancy_notes = strip_html(request.form.get("discrepancy_notes"))
    errors = []

    if verification_date is None:
        errors.append("Verification date is required.")
    elif verification_date == "invalid":
        verification_date = None
        errors.append("Verification date must be valid.")

    if not actual_location:
        verification_status = "missing"
    elif actual_location != expected_location or actual_condition != expected_condition:
        verification_status = "discrepancy_found"
    else:
        verification_status = "verified"

    if verification_status != "verified" and not discrepancy_notes:
        discrepancy_notes = "Auto-flagged discrepancy during physical verification."

    return {
        "asset_id": asset.id,
        "verification_date": verification_date,
        "verified_by": g.current_user.username,
        "expected_location": expected_location,
        "actual_location": actual_location,
        "expected_condition": expected_condition,
        "actual_condition": actual_condition,
        "verification_status": verification_status,
        "discrepancy_notes": discrepancy_notes or None,
    }, errors


def create_approval_request(request_type, payload, status="submitted", asset=None, comments=None):
    if status not in APPROVAL_STATUS_OPTIONS:
        status = "submitted"

    request_record = ApprovalRequest(
        request_type=request_type,
        asset_id=asset.id if asset else payload.get("asset_id"),
        submitted_by=g.current_user.username,
        status=status,
        request_payload=json.dumps(json_safe(payload)),
        comments=comments or None,
        submission_date=datetime.utcnow(),
    )
    db.session.add(request_record)
    return request_record


def apply_approval_request(approval):
    payload = json.loads(approval.request_payload or "{}")

    if approval.request_type == "asset_registration":
        purchase_date = parse_optional_date(payload.get("purchase_date"))
        warranty_expiry = parse_optional_date(payload.get("warranty_expiry"))
        asset = Asset(
            asset_name=payload.get("asset_name"),
            asset_code=payload.get("asset_code"),
            category=payload.get("category"),
            department=payload.get("department"),
            purchase_date=purchase_date,
            quantity=int(payload.get("quantity", 1)),
            purchase_cost=float(payload.get("purchase_cost", 0)),
            salvage_value=float(payload.get("salvage_value", 0)),
            useful_life=int(payload.get("useful_life", 1)),
            status=payload.get("status", "Active"),
            supplier=payload.get("supplier"),
            invoice_number=payload.get("invoice_number"),
            serial_number=payload.get("serial_number"),
            location=payload.get("location"),
            warranty_expiry=warranty_expiry if warranty_expiry != "invalid" else None,
            asset_condition=payload.get("asset_condition", "Good"),
        )

        duplicate_code = Asset.query.filter_by(asset_code=asset.asset_code).first()
        if duplicate_code:
            asset.asset_code = generate_asset_code(asset.category, asset.department)

        duplicate_invoice = Asset.query.filter_by(invoice_number=asset.invoice_number).first()
        if duplicate_invoice:
            asset.invoice_number = generate_invoice_number()

        db.session.add(asset)
        db.session.flush()
        approval.asset_id = asset.id
        log_audit(
            "approval execution",
            asset=asset,
            details=f"Approved asset registration request #{approval.id} and created asset {asset.asset_code}.",
        )
        return

    asset = Asset.query.get(approval.asset_id)
    if not asset:
        raise ValueError("Related asset does not exist.")

    if approval.request_type == "asset_transfer":
        if asset.is_disposed:
            raise ValueError("Disposed assets cannot be transferred.")

        old_department = asset.department
        transfer_date = parse_optional_date(payload.get("transfer_date"))
        db.session.add(
            AssetTransfer(
                asset_id=asset.id,
                old_department=old_department,
                new_department=payload.get("new_department"),
                transfer_date=transfer_date,
                reason=payload.get("reason") or "Approved transfer workflow",
                transferred_by=approval.approved_by or g.current_user.username,
            )
        )
        asset.department = payload.get("new_department")
        log_audit(
            "approval execution",
            asset=asset,
            details=f"Approved transfer request #{approval.id}. {old_department} -> {asset.department}.",
        )
        return

    if approval.request_type == "asset_disposal":
        if asset.is_disposed:
            raise ValueError("Asset is already disposed.")

        disposal_date = parse_optional_date(payload.get("disposal_date"))
        disposal_reason = payload.get("disposal_reason")
        disposal_value = float(payload.get("disposal_value", 0))
        disposal_notes = payload.get("disposal_notes")

        db.session.add(
            AssetDisposal(
                asset_id=asset.id,
                disposal_date=disposal_date,
                disposal_reason=disposal_reason,
                disposal_value=disposal_value,
                disposal_notes=disposal_notes,
                disposed_by=approval.approved_by or g.current_user.username,
            )
        )
        asset.status = "Disposed"
        asset.disposal_date = disposal_date
        asset.disposal_reason = disposal_reason
        asset.disposal_value = disposal_value
        asset.disposal_notes = disposal_notes
        log_audit(
            "approval execution",
            asset=asset,
            details=f"Approved disposal request #{approval.id} for asset {asset.asset_code}.",
        )
        return

    raise ValueError("Unknown approval request type.")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.current_user:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = strip_html(request.form.get("username"))
        password = request.form.get("password", "")

        if not username or not password:
            log_audit("login failure", details="Login failed due to missing username or password.")
            db.session.commit()
            flash("Username and password are required.", "danger")
            return render_template("login.html")

        user = User.query.filter(func.lower(User.username) == username.lower()).first()
        if not user or not user.check_password(password):
            log_audit("login failure", details=f"Invalid credentials attempt for username {username or 'unknown'}.")
            db.session.commit()
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

        if not user.is_active:
            log_audit("login failure", details=f"Inactive account login attempt for username {user.username}.", user=user)
            db.session.commit()
            flash("Your account is inactive. Contact an administrator.", "danger")
            return render_template("login.html")

        session["user_id"] = user.id
        user.last_login = datetime.utcnow()
        log_audit("user login", details=f"User {user.username} logged in.", user=user)
        db.session.commit()

        if user.must_change_password:
            flash("Please change your password before continuing.", "warning")
            return redirect(url_for("change_password"))

        next_url = request.args.get("next", "")
        if next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    log_audit("user logout", details=f"User {g.current_user.username} logged out.")
    db.session.commit()
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        errors = []

        if not new_password:
            errors.append("New password is required.")
        elif len(new_password) < 8:
            errors.append("Password must be at least 8 characters.")
        if new_password != confirm_password:
            errors.append("Password confirmation does not match.")

        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("change_password.html")

        g.current_user.password_hash = hash_password(new_password)
        g.current_user.must_change_password = False
        log_audit("password change", details=f"Password changed for user {g.current_user.username}.")
        db.session.commit()
        flash("Password changed successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")


@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    assets = Asset.query.order_by(Asset.asset_name.asc()).all()
    active_assets_count = Asset.query.filter_by(status="Active").count()
    under_maintenance_assets_count = Asset.query.filter_by(status="Under Maintenance").count()
    disposed_assets_count = Asset.query.filter_by(status="Disposed").count()
    nearing_end_assets = [asset for asset in assets if asset.nearing_end_of_life]

    category_summary = (
        db.session.query(
            Asset.category,
            func.count(Asset.id).label("asset_count"),
            func.sum(Asset.purchase_cost).label("total_cost"),
        )
        .group_by(Asset.category)
        .order_by(Asset.category.asc())
        .all()
    )

    department_summary_raw = (
        db.session.query(
            Asset.department,
            func.count(Asset.id).label("asset_count"),
            func.sum(Asset.purchase_cost).label("total_cost"),
        )
        .group_by(Asset.department)
        .order_by(Asset.department.asc())
        .all()
    )

    department_summary_map = {
        row.department: {
            "department": row.department,
            "asset_count": row.asset_count,
            "total_cost": row.total_cost or 0,
        }
        for row in department_summary_raw
    }
    all_departments = sorted(set(DEFAULT_DEPARTMENT_OPTIONS + [row.department for row in department_summary_raw]))
    department_summary = [
        department_summary_map.get(department, {"department": department, "asset_count": 0, "total_cost": 0})
        for department in all_departments
    ]

    department_depreciation = {}
    for asset in assets:
        department_depreciation[asset.department] = department_depreciation.get(asset.department, 0) + asset.accumulated_depreciation

    pending_approval_count = ApprovalRequest.query.filter(ApprovalRequest.status.in_(["submitted", "under_review"])).count()
    pending_disposal_approval_count = ApprovalRequest.query.filter(
        ApprovalRequest.request_type == "asset_disposal",
        ApprovalRequest.status.in_(["submitted", "under_review"]),
    ).count()

    discrepancy_asset_ids = {
        row[0]
        for row in db.session.query(AssetVerification.asset_id)
        .filter(AssetVerification.verification_status.in_(["discrepancy_found", "missing"]))
        .distinct()
        .all()
    }

    due_maintenance_asset_ids = {
        row[0]
        for row in db.session.query(AssetMaintenance.asset_id)
        .filter(AssetMaintenance.next_maintenance_date.isnot(None))
        .filter(AssetMaintenance.next_maintenance_date <= date.today())
        .distinct()
        .all()
    }

    verification_summary = (
        db.session.query(AssetVerification.verification_status, func.count(AssetVerification.id))
        .group_by(AssetVerification.verification_status)
        .all()
    )
    verification_summary_map = {row[0]: row[1] for row in verification_summary}

    return render_template(
        "dashboard.html",
        total_assets=len(assets),
        total_quantity=sum(asset.quantity for asset in assets),
        total_purchase_cost=sum(asset.purchase_cost for asset in assets),
        total_accumulated_depreciation=sum(asset.accumulated_depreciation for asset in assets),
        total_net_book_value=sum(asset.net_book_value for asset in assets),
        disposed_assets_count=disposed_assets_count,
        active_assets_count=active_assets_count,
        under_maintenance_assets_count=under_maintenance_assets_count,
        nearing_end_assets_count=len(nearing_end_assets),
        pending_approval_count=pending_approval_count,
        pending_disposal_approval_count=pending_disposal_approval_count,
        assets_with_discrepancies_count=len(discrepancy_asset_ids),
        assets_due_maintenance_count=len(due_maintenance_asset_ids),
        total_maintenance_cost=db.session.query(func.sum(AssetMaintenance.maintenance_cost)).scalar() or 0,
        document_count=AssetDocument.query.count(),
        recent_assets=Asset.query.order_by(Asset.id.desc()).limit(5).all(),
        recent_audit_logs=AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(8).all(),
        nearing_end_assets=nearing_end_assets[:6],
        category_summary=category_summary,
        department_summary=department_summary,
        category_chart_labels=[row.category for row in category_summary],
        category_chart_values=[row.asset_count for row in category_summary],
        department_chart_labels=[row["department"] for row in department_summary],
        department_chart_values=[row["asset_count"] for row in department_summary],
        status_chart_labels=["Active", "Under Maintenance", "Disposed"],
        status_chart_values=[active_assets_count, under_maintenance_assets_count, disposed_assets_count],
        depreciation_department_labels=list(department_depreciation.keys()),
        depreciation_department_values=[round(value, 3) for value in department_depreciation.values()],
        verification_chart_labels=["Verified", "Discrepancy Found", "Missing"],
        verification_chart_values=[
            verification_summary_map.get("verified", 0),
            verification_summary_map.get("discrepancy_found", 0),
            verification_summary_map.get("missing", 0),
        ],
    )


@app.route("/approvals")
@login_required
def approval_list():
    query = ApprovalRequest.query.order_by(ApprovalRequest.submission_date.desc())
    if g.current_user.role != "admin":
        query = query.filter(ApprovalRequest.submitted_by == g.current_user.username)

    return render_template(
        "approvals_list.html",
        approvals=query.all(),
        status_options=APPROVAL_STATUS_OPTIONS,
    )


@app.route("/approvals/<int:id>/review", methods=["GET", "POST"])
@admin_required
def approval_review(id):
    approval = ApprovalRequest.query.get_or_404(id)
    payload = json.loads(approval.request_payload or "{}")

    if request.method == "POST":
        decision = request.form.get("decision", "").strip()
        review_comments = strip_html(request.form.get("review_comments"))
        rejection_reason = strip_html(request.form.get("rejection_reason"))

        if decision not in APPROVAL_DECISION_OPTIONS:
            flash("Invalid approval decision.", "danger")
            return render_template("approval_review.html", approval=approval, payload=payload)

        approval.reviewed_by = g.current_user.username
        approval.review_date = datetime.utcnow()
        approval.comments = review_comments or approval.comments

        if decision == "under_review":
            approval.status = "under_review"
            log_audit(
                "approval decision",
                asset=approval.asset,
                details=f"Approval request #{approval.id} moved to under_review.",
            )
            db.session.commit()
            flash("Approval request moved to under review.", "info")
            return redirect(url_for("approval_review", id=approval.id))

        if decision == "rejected":
            if not rejection_reason:
                flash("Rejection reason is required.", "danger")
                return render_template("approval_review.html", approval=approval, payload=payload)
            approval.status = "rejected"
            approval.rejection_reason = rejection_reason
            log_audit(
                "approval decision",
                asset=approval.asset,
                details=f"Approval request #{approval.id} rejected. Reason: {rejection_reason}",
            )
            db.session.commit()
            flash("Approval request rejected.", "warning")
            return redirect(url_for("approval_list"))

        try:
            approval.status = "approved"
            approval.approved_by = g.current_user.username
            approval.approval_date = datetime.utcnow()
            apply_approval_request(approval)
            log_audit(
                "approval decision",
                asset=approval.asset,
                details=f"Approval request #{approval.id} approved by {g.current_user.username}.",
            )
            db.session.commit()
            flash("Approval request approved and executed.", "success")
            return redirect(url_for("approval_list"))
        except ValueError as error:
            db.session.rollback()
            flash(str(error), "danger")
            return render_template("approval_review.html", approval=approval, payload=payload)

    return render_template("approval_review.html", approval=approval, payload=payload)


@app.route("/assets")
@login_required
def asset_list():
    query, filters = build_asset_query(request.args)
    assets = query.all()
    asset_ids = [asset.id for asset in assets]
    latest_transfer_status_by_asset = {}

    if asset_ids:
        transfer_approvals = (
            ApprovalRequest.query.filter(
                ApprovalRequest.request_type == "asset_transfer",
                ApprovalRequest.asset_id.in_(asset_ids),
            )
            .order_by(ApprovalRequest.asset_id.asc(), ApprovalRequest.submission_date.desc())
            .all()
        )

        for approval in transfer_approvals:
            if approval.asset_id in latest_transfer_status_by_asset:
                continue
            latest_transfer_status_by_asset[approval.asset_id] = build_transfer_workflow_view(approval)

    categories, departments = get_form_options()
    suppliers = sorted(set([row[0] for row in db.session.query(Asset.supplier).distinct().all() if row[0]]))
    return render_template(
        "asset_list.html",
        assets=assets,
        categories=categories,
        departments=departments,
        suppliers=suppliers,
        status_options=STATUS_OPTIONS,
        condition_options=ASSET_CONDITION_OPTIONS,
        filters=filters,
        latest_transfer_status_by_asset=latest_transfer_status_by_asset,
    )


@app.route("/assets/export/csv")
@app.route("/export/assets")
@login_required
def export_assets_csv():
    query, _ = build_asset_query(request.args)
    assets = query.all()
    rows = [
        [
            asset.asset_code,
            asset.asset_name,
            asset.category,
            asset.department,
            asset.quantity,
            asset.status,
            asset.purchase_cost,
            asset.salvage_value,
            asset.useful_life,
            asset.location or "",
            asset.serial_number or "",
            asset.asset_condition,
        ]
        for asset in assets
    ]
    return export_csv(
        "asset_register.csv",
        [
            "Asset Code",
            "Asset Name",
            "Category",
            "Department",
            "Quantity",
            "Status",
            "Purchase Cost",
            "Salvage Value",
            "Useful Life",
            "Location",
            "Serial Number",
            "Condition",
        ],
        rows,
    )


@app.route("/assets/new", methods=["GET", "POST"])
@admin_required
def add_asset():
    categories, departments = get_form_options()
    if request.method == "POST":
        submission_mode = request.form.get("submission_mode", "submitted").strip().lower()
        form_data, errors = get_asset_form_data()
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template(
                "asset_form.html",
                asset=None,
                form_data=request.form,
                generated_code=preview_asset_code(request.form.get("category"), request.form.get("department")),
                generated_invoice=preview_invoice_number(),
                categories=categories,
                departments=departments,
                status_options=FORM_STATUS_OPTIONS,
                condition_options=ASSET_CONDITION_OPTIONS,
                form_title="Add New Asset",
                submit_label="Submit for Approval",
            )

        comments = strip_html(request.form.get("comments"))
        approval = create_approval_request(
            "asset_registration",
            payload=form_data,
            status="draft" if submission_mode == "draft" else "submitted",
            comments=comments,
        )
        log_audit(
            "approval submission",
            details=f"Submitted asset registration approval request #{approval.id} with status {approval.status}.",
        )
        db.session.commit()
        flash("Asset registration request saved." if approval.status == "draft" else "Asset registration submitted for approval.", "success")
        return redirect(url_for("approval_list"))

    return render_template(
        "asset_form.html",
        asset=None,
        form_data={},
        generated_code="",
        generated_invoice=preview_invoice_number(),
        categories=categories,
        departments=departments,
        status_options=FORM_STATUS_OPTIONS,
        condition_options=ASSET_CONDITION_OPTIONS,
        form_title="Add New Asset",
        submit_label="Submit for Approval",
    )


@app.route("/assets/<int:id>")
@login_required
def asset_detail(id):
    asset = Asset.query.get_or_404(id)
    latest_transfer_approval = (
        ApprovalRequest.query.filter_by(asset_id=asset.id, request_type="asset_transfer")
        .order_by(ApprovalRequest.submission_date.desc())
        .first()
    )

    return render_template(
        "asset_detail.html",
        asset=asset,
        transfer_history=AssetTransfer.query.filter_by(asset_id=asset.id).order_by(AssetTransfer.transfer_date.desc()).all(),
        related_audit_logs=AuditLog.query.filter_by(asset_id=asset.id).order_by(AuditLog.timestamp.desc()).limit(15).all(),
        approval_history=ApprovalRequest.query.filter_by(asset_id=asset.id).order_by(ApprovalRequest.submission_date.desc()).all(),
        maintenance_history=AssetMaintenance.query.filter_by(asset_id=asset.id).order_by(AssetMaintenance.maintenance_date.desc()).all(),
        verification_history=AssetVerification.query.filter_by(asset_id=asset.id).order_by(AssetVerification.verification_date.desc()).all(),
        documents=AssetDocument.query.filter_by(asset_id=asset.id).order_by(AssetDocument.uploaded_at.desc()).all(),
        total_maintenance_cost=sum(row.maintenance_cost for row in AssetMaintenance.query.filter_by(asset_id=asset.id).all()),
        latest_transfer_approval=build_transfer_workflow_view(latest_transfer_approval),
    )


@app.route("/assets/<int:id>/edit", methods=["GET", "POST"])
@admin_required
def edit_asset(id):
    asset = Asset.query.get_or_404(id)
    if asset.is_disposed:
        flash("Disposed assets cannot be edited through the standard form.", "warning")
        return redirect(url_for("asset_detail", id=asset.id))

    categories, departments = get_form_options()
    if request.method == "POST":
        previous_status = asset.status
        previous_condition = asset.asset_condition
        previous_quantity = asset.quantity
        previous_department = asset.department
        previous_location = asset.location or ""
        previous_supplier = asset.supplier or ""

        form_data, errors = get_asset_form_data(asset=asset)
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template(
                "asset_form.html",
                asset=asset,
                form_data=request.form,
                generated_code=asset.asset_code,
                generated_invoice=asset.invoice_number or preview_invoice_number(),
                categories=categories,
                departments=departments,
                status_options=FORM_STATUS_OPTIONS,
                condition_options=ASSET_CONDITION_OPTIONS,
                form_title="Edit Asset",
                submit_label="Update Asset",
            )

        for field, value in form_data.items():
            setattr(asset, field, value)

        log_audit(
            "edit asset",
            asset=asset,
            details=(
                "Updated asset. "
                f"Department: {previous_department} -> {asset.department}; "
                f"Location: {previous_location or 'N/A'} -> {asset.location or 'N/A'}; "
                f"Status: {previous_status} -> {asset.status}; "
                f"Quantity: {previous_quantity} -> {asset.quantity}; "
                f"Condition: {previous_condition} -> {asset.asset_condition}; "
                f"Supplier: {previous_supplier or 'N/A'} -> {asset.supplier or 'N/A'}."
            ),
        )
        db.session.commit()
        flash("Asset updated successfully.", "success")
        return redirect(url_for("asset_detail", id=asset.id))

    return render_template(
        "asset_form.html",
        asset=asset,
        form_data={},
        generated_code=asset.asset_code,
        generated_invoice=asset.invoice_number or preview_invoice_number(),
        categories=categories,
        departments=departments,
        status_options=FORM_STATUS_OPTIONS,
        condition_options=ASSET_CONDITION_OPTIONS,
        form_title="Edit Asset",
        submit_label="Update Asset",
    )


@app.route("/assets/<int:id>/transfer", methods=["GET", "POST"])
@admin_required
def transfer_asset(id):
    asset = Asset.query.get_or_404(id)
    if asset.is_disposed:
        flash("Disposed assets cannot be transferred.", "warning")
        return redirect(url_for("asset_detail", id=asset.id))

    _, departments = get_form_options()
    available_departments = [department for department in departments if department != asset.department]
    latest_transfer_approval = (
        ApprovalRequest.query.filter_by(asset_id=asset.id, request_type="asset_transfer")
        .order_by(ApprovalRequest.submission_date.desc())
        .first()
    )

    if request.method == "POST":
        submission_mode = request.form.get("submission_mode", "submitted").strip().lower()
        form_data, errors = get_transfer_form_data(asset)
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template(
                "transfer_form.html",
                asset=asset,
                departments=available_departments,
                form_data=request.form,
                latest_transfer_approval=build_transfer_workflow_view(latest_transfer_approval),
            )

        payload = {
            "asset_id": asset.id,
            "new_department": form_data["new_department"],
            "transfer_date": form_data["transfer_date"],
            "reason": form_data["reason"],
        }
        approval = create_approval_request(
            "asset_transfer",
            payload=payload,
            status="draft" if submission_mode == "draft" else "submitted",
            asset=asset,
            comments=form_data.get("comments"),
        )
        log_audit(
            "approval submission",
            asset=asset,
            details=f"Submitted transfer approval request #{approval.id} for {asset.asset_code}.",
        )
        db.session.commit()
        flash("Transfer request saved." if approval.status == "draft" else "Transfer request submitted for approval.", "success")
        return redirect(url_for("asset_detail", id=asset.id))

    return render_template(
        "transfer_form.html",
        asset=asset,
        departments=available_departments,
        form_data={},
        latest_transfer_approval=build_transfer_workflow_view(latest_transfer_approval),
    )


@app.route("/assets/<int:id>/dispose", methods=["GET", "POST"])
@admin_required
def dispose_asset(id):
    asset = Asset.query.get_or_404(id)
    if asset.is_disposed:
        flash("Asset is already disposed.", "warning")
        return redirect(url_for("asset_detail", id=asset.id))

    if request.method == "POST":
        submission_mode = request.form.get("submission_mode", "submitted").strip().lower()
        form_data, errors = get_disposal_form_data(asset)
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("disposal_form.html", asset=asset, form_data=request.form)

        payload = {
            "asset_id": asset.id,
            "disposal_date": form_data["disposal_date"],
            "disposal_reason": form_data["disposal_reason"],
            "disposal_value": form_data["disposal_value"],
            "disposal_notes": form_data["disposal_notes"],
        }
        approval = create_approval_request(
            "asset_disposal",
            payload=payload,
            status="draft" if submission_mode == "draft" else "submitted",
            asset=asset,
            comments=form_data.get("comments"),
        )
        log_audit(
            "approval submission",
            asset=asset,
            details=f"Submitted disposal approval request #{approval.id} for {asset.asset_code}.",
        )
        db.session.commit()
        flash("Disposal request saved." if approval.status == "draft" else "Disposal request submitted for approval.", "success")
        return redirect(url_for("asset_detail", id=asset.id))

    return render_template("disposal_form.html", asset=asset, form_data={})


@app.route("/assets/<int:id>/delete", methods=["POST"])
@admin_required
def delete_asset(id):
    asset = Asset.query.get_or_404(id)
    asset_name = asset.asset_name
    asset_code = asset.asset_code
    log_audit("delete asset", asset=asset, details=f"Deleted asset {asset_code} - {asset_name}.")
    db.session.delete(asset)
    db.session.commit()
    flash("Asset deleted successfully.", "success")
    return redirect(url_for("asset_list"))


@app.route("/assets/<int:id>/maintenance/new", methods=["GET", "POST"])
@admin_required
def asset_maintenance_new(id):
    asset = Asset.query.get_or_404(id)
    if request.method == "POST":
        form_data, errors = get_maintenance_form_data(asset)
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("maintenance_form.html", asset=asset, form_data=request.form)

        record = AssetMaintenance(**form_data)
        db.session.add(record)
        log_audit(
            "maintenance record create",
            asset=asset,
            details=f"Maintenance recorded ({record.maintenance_type}) by {record.service_provider} costing {record.maintenance_cost:.3f}.",
        )
        db.session.commit()
        flash("Maintenance record created successfully.", "success")
        return redirect(url_for("asset_detail", id=asset.id))

    return render_template("maintenance_form.html", asset=asset, form_data={})


@app.route("/assets/<int:id>/maintenance")
@login_required
def asset_maintenance_list(id):
    asset = Asset.query.get_or_404(id)
    records = AssetMaintenance.query.filter_by(asset_id=asset.id).order_by(AssetMaintenance.maintenance_date.desc()).all()
    return render_template("maintenance_list.html", asset=asset, records=records)


@app.route("/assets/<int:id>/verify", methods=["GET", "POST"])
@admin_required
def asset_verify(id):
    asset = Asset.query.get_or_404(id)
    if request.method == "POST":
        form_data, errors = get_verification_form_data(asset)
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("verification_form.html", asset=asset, form_data=request.form)

        verification = AssetVerification(**form_data)
        db.session.add(verification)
        log_audit(
            "verification record create",
            asset=asset,
            details=f"Verification recorded with status {verification.verification_status}.",
        )
        db.session.commit()
        flash("Physical verification recorded successfully.", "success")
        return redirect(url_for("asset_detail", id=asset.id))

    return render_template("verification_form.html", asset=asset, form_data={})


@app.route("/assets/<int:id>/documents", methods=["GET"])
@login_required
def asset_documents_list(id):
    asset = Asset.query.get_or_404(id)
    documents = AssetDocument.query.filter_by(asset_id=asset.id).order_by(AssetDocument.uploaded_at.desc()).all()
    return render_template("document_list.html", asset=asset, documents=documents)


@app.route("/assets/<int:id>/documents/upload", methods=["GET", "POST"])
@admin_required
def asset_document_upload(id):
    asset = Asset.query.get_or_404(id)

    if request.method == "POST":
        uploaded_file = request.files.get("document_file")
        document_type = strip_html(request.form.get("document_type"))
        notes = strip_html(request.form.get("notes"))

        if document_type not in DOCUMENT_TYPE_OPTIONS:
            flash("Invalid document type selected.", "danger")
            return render_template("document_upload_form.html", asset=asset, document_types=DOCUMENT_TYPE_OPTIONS)

        if not uploaded_file or not uploaded_file.filename:
            flash("Please select a file to upload.", "danger")
            return render_template("document_upload_form.html", asset=asset, document_types=DOCUMENT_TYPE_OPTIONS)

        if not allowed_file(uploaded_file.filename):
            flash("Invalid file type. Allowed: pdf, png, jpg, jpeg, doc, docx.", "danger")
            return render_template("document_upload_form.html", asset=asset, document_types=DOCUMENT_TYPE_OPTIONS)

        clean_name = secure_filename(uploaded_file.filename)
        extension = clean_name.rsplit(".", 1)[1].lower()
        unique_name = f"{asset.id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}.{extension}"

        asset_upload_dir = os.path.join(app.config["UPLOAD_FOLDER"], str(asset.id))
        os.makedirs(asset_upload_dir, exist_ok=True)
        full_path = os.path.join(asset_upload_dir, unique_name)
        uploaded_file.save(full_path)

        stored_path = os.path.relpath(full_path, app.root_path)
        document = AssetDocument(
            asset_id=asset.id,
            document_type=document_type,
            file_name=clean_name,
            file_path=stored_path,
            uploaded_by=g.current_user.username,
            notes=notes or None,
        )
        db.session.add(document)
        log_audit(
            "document upload",
            asset=asset,
            details=f"Uploaded document {document.file_name} ({document.document_type}).",
        )
        db.session.commit()
        flash("Document uploaded successfully.", "success")
        return redirect(url_for("asset_documents_list", id=asset.id))

    return render_template("document_upload_form.html", asset=asset, document_types=DOCUMENT_TYPE_OPTIONS)


@app.route("/documents/<int:id>/download")
@login_required
def document_download(id):
    document = AssetDocument.query.get_or_404(id)
    path = absolute_document_path(document.file_path)
    if not os.path.exists(path):
        abort(404)

    log_audit("document download", asset=document.asset, details=f"Downloaded document {document.file_name}.")
    db.session.commit()
    return send_file(path, as_attachment=True, download_name=document.file_name)


@app.route("/documents/<int:id>/delete", methods=["POST"])
@admin_required
def document_delete(id):
    document = AssetDocument.query.get_or_404(id)
    asset_id = document.asset_id
    path = absolute_document_path(document.file_path)

    if os.path.exists(path):
        os.remove(path)

    log_audit("document delete", asset=document.asset, details=f"Deleted document {document.file_name}.")
    db.session.delete(document)
    db.session.commit()
    flash("Document deleted successfully.", "success")
    return redirect(url_for("asset_documents_list", id=asset_id))


@app.route("/report/depreciation")
@login_required
def depreciation_report():
    assets = Asset.query.order_by(Asset.asset_name.asc()).all()
    totals = {
        "purchase_cost": sum(asset.purchase_cost for asset in assets),
        "accumulated_depreciation": sum(asset.accumulated_depreciation for asset in assets),
        "net_book_value": sum(asset.net_book_value for asset in assets),
    }
    return render_template("depreciation_report.html", assets=assets, totals=totals)


@app.route("/reports")
@login_required
def reports_hub():
    report_links = [
        {"label": "Depreciation Report", "endpoint": "depreciation_report", "icon": "bi-graph-down-arrow"},
        {"label": "Depreciation Scenario", "endpoint": "depreciation_scenario", "icon": "bi-sliders"},
        {"label": "Department Report", "endpoint": "department_report", "icon": "bi-building"},
        {"label": "Disposed Assets Report", "endpoint": "disposed_assets_report", "icon": "bi-archive"},
        {"label": "End-of-Life Report", "endpoint": "end_of_life_report", "icon": "bi-hourglass-split"},
        {"label": "Verification Report", "endpoint": "verification_report", "icon": "bi-clipboard2-check"},
        {"label": "Maintenance Report", "endpoint": "maintenance_report", "icon": "bi-tools"},
        {"label": "Approvals Report", "endpoint": "approvals_report", "icon": "bi-check2-square"},
        {"label": "Documents Report", "endpoint": "documents_report", "icon": "bi-folder2-open"},
    ]
    return render_template("reports_hub.html", report_links=report_links)


@app.route("/report/depreciation/export/csv")
@app.route("/export/depreciation")
@login_required
def export_depreciation_csv():
    assets = Asset.query.order_by(Asset.asset_name.asc()).all()
    rows = [
        [
            asset.asset_code,
            asset.asset_name,
            asset.quantity,
            asset.purchase_cost,
            asset.salvage_value,
            asset.useful_life,
            asset.years_used,
            round(asset.annual_depreciation, 3),
            round(asset.accumulated_depreciation, 3),
            round(asset.net_book_value, 3),
            asset.status,
        ]
        for asset in assets
    ]
    return export_csv(
        "depreciation_report.csv",
        [
            "Asset Code",
            "Asset Name",
            "Quantity",
            "Purchase Cost",
            "Salvage Value",
            "Useful Life",
            "Years Used",
            "Annual Depreciation",
            "Accumulated Depreciation",
            "Net Book Value",
            "Status",
        ],
        rows,
    )


@app.route("/report/depreciation/scenario", methods=["GET", "POST"])
@login_required
def depreciation_scenario():
    scenario = None
    if request.method == "POST":
        purchase_cost_raw = request.form.get("purchase_cost", "").strip()
        salvage_value_raw = request.form.get("salvage_value", "").strip()
        useful_life_raw = request.form.get("useful_life", "").strip()
        years_used_raw = request.form.get("years_used", "").strip()
        errors = []

        try:
            purchase_cost = float(purchase_cost_raw)
            if purchase_cost < 0:
                errors.append("Purchase cost must be >= 0.")
        except ValueError:
            purchase_cost = 0
            errors.append("Purchase cost must be numeric.")

        try:
            salvage_value = float(salvage_value_raw)
            if salvage_value < 0:
                errors.append("Salvage value must be >= 0.")
        except ValueError:
            salvage_value = 0
            errors.append("Salvage value must be numeric.")

        try:
            useful_life = int(useful_life_raw)
            if useful_life <= 0:
                errors.append("Useful life must be > 0.")
        except ValueError:
            useful_life = 1
            errors.append("Useful life must be an integer.")

        try:
            years_used = int(years_used_raw)
            if years_used < 0:
                errors.append("Years used must be >= 0.")
        except ValueError:
            years_used = 0
            errors.append("Years used must be an integer.")

        if salvage_value > purchase_cost:
            errors.append("Salvage value cannot exceed purchase cost.")

        if errors:
            for error in errors:
                flash(error, "danger")
        else:
            annual = max(0, purchase_cost - salvage_value) / useful_life
            accumulated = min(annual * years_used, max(0, purchase_cost - salvage_value))
            net_book_value = max(purchase_cost - accumulated, salvage_value)
            scenario = {
                "purchase_cost": purchase_cost,
                "salvage_value": salvage_value,
                "useful_life": useful_life,
                "years_used": years_used,
                "annual_depreciation": annual,
                "accumulated_depreciation": accumulated,
                "net_book_value": net_book_value,
            }

    return render_template("depreciation_scenario.html", scenario=scenario)


@app.route("/report/disposed")
@login_required
def disposed_assets_report():
    return render_template(
        "disposed_report.html",
        assets=Asset.query.filter_by(status="Disposed").order_by(Asset.disposal_date.desc(), Asset.asset_name.asc()).all(),
    )


@app.route("/report/disposed/export/csv")
@app.route("/export/disposed")
@login_required
def export_disposed_assets_csv():
    disposed_assets = Asset.query.filter_by(status="Disposed").order_by(Asset.disposal_date.desc()).all()
    rows = [
        [
            asset.asset_code,
            asset.asset_name,
            asset.department,
            asset.quantity,
            asset.disposal_date or "",
            asset.disposal_reason or "",
            asset.disposal_value or 0,
            asset.disposal_notes or "",
        ]
        for asset in disposed_assets
    ]
    return export_csv(
        "disposed_assets_report.csv",
        [
            "Asset Code",
            "Asset Name",
            "Department",
            "Quantity",
            "Disposal Date",
            "Disposal Reason",
            "Disposal Value",
            "Disposal Notes",
        ],
        rows,
    )


@app.route("/report/departments")
@login_required
def department_report():
    summary = (
        db.session.query(
            Asset.department,
            func.count(Asset.id).label("asset_count"),
            func.sum(Asset.purchase_cost).label("purchase_total"),
            func.sum(Asset.salvage_value).label("salvage_total"),
        )
        .group_by(Asset.department)
        .order_by(Asset.department.asc())
        .all()
    )
    return render_template("department_report.html", summary=summary)


@app.route("/report/end-of-life")
@login_required
def end_of_life_report():
    assets = [
        asset
        for asset in Asset.query.filter(Asset.status != "Disposed").order_by(Asset.asset_name.asc()).all()
        if asset.remaining_useful_life <= 1
    ]
    return render_template("end_of_life_report.html", assets=assets)


@app.route("/report/verifications")
@login_required
def verification_report():
    verifications = AssetVerification.query.order_by(AssetVerification.verification_date.desc()).all()
    return render_template("verification_report.html", verifications=verifications)


@app.route("/report/maintenance")
@login_required
def maintenance_report():
    records = AssetMaintenance.query.order_by(AssetMaintenance.maintenance_date.desc()).all()
    return render_template("maintenance_report.html", records=records)


@app.route("/report/approvals")
@login_required
def approvals_report():
    approvals = ApprovalRequest.query.order_by(ApprovalRequest.submission_date.desc()).all()
    return render_template("approval_report.html", approvals=approvals)


@app.route("/report/documents")
@login_required
def documents_report():
    documents = AssetDocument.query.order_by(AssetDocument.uploaded_at.desc()).all()
    return render_template("document_report.html", documents=documents)


@app.route("/export/departments")
@login_required
def export_departments_csv():
    summary = (
        db.session.query(
            Asset.department,
            func.count(Asset.id).label("asset_count"),
            func.sum(Asset.purchase_cost).label("purchase_total"),
            func.sum(Asset.salvage_value).label("salvage_total"),
        )
        .group_by(Asset.department)
        .order_by(Asset.department.asc())
        .all()
    )
    rows = [[row.department, row.asset_count, row.purchase_total or 0, row.salvage_total or 0] for row in summary]
    return export_csv("department_summary_report.csv", ["Department", "Asset Count", "Total Purchase Cost", "Total Salvage Value"], rows)


@app.route("/export/verifications")
@login_required
def export_verifications_csv():
    rows = [
        [
            row.asset.asset_code if row.asset else "",
            row.asset.asset_name if row.asset else "",
            row.verification_date,
            row.verified_by,
            row.expected_location,
            row.actual_location,
            row.expected_condition,
            row.actual_condition,
            row.verification_status,
            row.discrepancy_notes or "",
        ]
        for row in AssetVerification.query.order_by(AssetVerification.verification_date.desc()).all()
    ]
    return export_csv(
        "verification_report.csv",
        [
            "Asset Code",
            "Asset Name",
            "Verification Date",
            "Verified By",
            "Expected Location",
            "Actual Location",
            "Expected Condition",
            "Actual Condition",
            "Status",
            "Discrepancy Notes",
        ],
        rows,
    )


@app.route("/export/maintenance")
@login_required
def export_maintenance_csv():
    rows = [
        [
            row.asset.asset_code if row.asset else "",
            row.asset.asset_name if row.asset else "",
            row.maintenance_date,
            row.maintenance_type,
            row.service_provider,
            row.maintenance_cost,
            row.next_maintenance_date or "",
            row.created_by,
            row.notes or "",
        ]
        for row in AssetMaintenance.query.order_by(AssetMaintenance.maintenance_date.desc()).all()
    ]
    return export_csv(
        "maintenance_report.csv",
        [
            "Asset Code",
            "Asset Name",
            "Maintenance Date",
            "Maintenance Type",
            "Service Provider",
            "Cost",
            "Next Maintenance Date",
            "Created By",
            "Notes",
        ],
        rows,
    )


@app.route("/export/approvals")
@login_required
def export_approvals_csv():
    rows = [
        [
            row.id,
            row.request_type,
            row.asset.asset_code if row.asset else "",
            row.status,
            row.submitted_by,
            row.reviewed_by or "",
            row.approved_by or "",
            row.submission_date,
            row.review_date or "",
            row.approval_date or "",
            row.rejection_reason or "",
        ]
        for row in ApprovalRequest.query.order_by(ApprovalRequest.submission_date.desc()).all()
    ]
    return export_csv(
        "approval_report.csv",
        [
            "Request ID",
            "Type",
            "Asset Code",
            "Status",
            "Submitted By",
            "Reviewed By",
            "Approved By",
            "Submission Date",
            "Review Date",
            "Approval Date",
            "Rejection Reason",
        ],
        rows,
    )


@app.route("/export/documents")
@login_required
def export_documents_csv():
    rows = [
        [
            row.asset.asset_code if row.asset else "",
            row.asset.asset_name if row.asset else "",
            row.document_type,
            row.file_name,
            row.uploaded_by,
            row.uploaded_at,
            row.notes or "",
        ]
        for row in AssetDocument.query.order_by(AssetDocument.uploaded_at.desc()).all()
    ]
    return export_csv(
        "document_report.csv",
        ["Asset Code", "Asset Name", "Document Type", "File Name", "Uploaded By", "Uploaded At", "Notes"],
        rows,
    )


@app.route("/audit-logs")
@login_required
def audit_logs():
    return render_template("audit_logs.html", logs=AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(500).all())


@app.route("/users")
@admin_required
def users_list():
    return render_template("user_list.html", users=User.query.order_by(User.created_at.desc()).all())


@app.route("/users/new", methods=["GET", "POST"])
@admin_required
def users_new():
    if request.method == "POST":
        username = strip_html(request.form.get("username"))
        full_name = strip_html(request.form.get("full_name"))
        email = strip_html(request.form.get("email"))
        role = request.form.get("role", "viewer").strip().lower()
        temporary_password = request.form.get("temporary_password", "")
        is_active = request.form.get("is_active") == "on"
        errors = []

        if not username:
            errors.append("Username cannot be empty.")
        if not full_name:
            errors.append("Full name cannot be empty.")
        if not email:
            errors.append("Email cannot be empty.")
        elif not is_valid_email(email):
            errors.append("Please provide a valid email address.")
        if not is_valid_role(role):
            errors.append("Role must be admin or viewer.")
        if not temporary_password:
            errors.append("Temporary password is required.")
        elif len(temporary_password) < 8:
            errors.append("Temporary password must be at least 8 characters.")
        if username and not is_unique_username(username):
            errors.append("Username must be unique.")
        if email and not is_unique_email(email):
            errors.append("Email must be unique.")

        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("user_form.html", form_mode="create", user=None, form_data=request.form, roles=USER_ROLES)

        db.session.add(
            User(
                username=username,
                full_name=full_name,
                email=email,
                role=role,
                is_active=is_active,
                must_change_password=True,
                password_hash=hash_password(temporary_password),
            )
        )
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Username or email already exists.", "danger")
            return render_template("user_form.html", form_mode="create", user=None, form_data=request.form, roles=USER_ROLES)

        log_audit("user created", details=f"Created user {username} with role {role}.")
        db.session.commit()
        flash("User created successfully.", "success")
        return redirect(url_for("users_list"))

    return render_template("user_form.html", form_mode="create", user=None, form_data={}, roles=USER_ROLES)


@app.route("/users/<int:id>")
@admin_required
def users_detail(id):
    return render_template("user_detail.html", user=User.query.get_or_404(id))


@app.route("/users/<int:id>/edit", methods=["GET", "POST"])
@admin_required
def users_edit(id):
    user = User.query.get_or_404(id)

    if request.method == "POST":
        full_name = strip_html(request.form.get("full_name"))
        email = strip_html(request.form.get("email"))
        role = request.form.get("role", "viewer").strip().lower()
        is_active = request.form.get("is_active") == "on"
        previous_full_name = user.full_name
        previous_email = user.email
        previous_role = user.role
        previous_active = user.is_active
        errors = []

        if not full_name:
            errors.append("Full name cannot be empty.")
        if not email:
            errors.append("Email cannot be empty.")
        elif not is_valid_email(email):
            errors.append("Please provide a valid email address.")
        if not is_valid_role(role):
            errors.append("Role must be admin or viewer.")
        if email and not is_unique_email(email, current_user_id=user.id):
            errors.append("Email must be unique.")
        if user.id == g.current_user.id and not is_active:
            errors.append("You cannot deactivate your own account.")
        if user.id == g.current_user.id and role != "admin":
            errors.append("You cannot change your own role.")
        if user.role == "admin" and user.is_active and not is_active and active_admin_count() <= 1:
            errors.append("You cannot deactivate the last active admin.")
        if user.role == "admin" and role != "admin" and active_admin_count() <= 1:
            errors.append("You cannot remove admin role from the last active admin.")

        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("user_form.html", form_mode="edit", user=user, form_data=request.form, roles=USER_ROLES)

        user.full_name = full_name
        user.email = email
        user.role = role
        user.is_active = is_active
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Email already exists.", "danger")
            return render_template("user_form.html", form_mode="edit", user=user, form_data=request.form, roles=USER_ROLES)

        if (
            previous_full_name != user.full_name
            or previous_email != user.email
            or previous_role != user.role
            or previous_active != user.is_active
        ):
            log_audit(
                "user updated",
                details=(
                    f"Updated user {user.username}. "
                    f"Full Name: {previous_full_name} -> {user.full_name}; "
                    f"Email: {previous_email} -> {user.email}; "
                    f"Role: {previous_role} -> {user.role}; "
                    f"Active: {previous_active} -> {user.is_active}"
                ),
            )
            db.session.commit()

        flash("User updated successfully.", "success")
        return redirect(url_for("users_detail", id=user.id))

    return render_template("user_form.html", form_mode="edit", user=user, form_data={}, roles=USER_ROLES)


@app.route("/users/<int:id>/reset-password", methods=["GET", "POST"])
@admin_required
def users_reset_password(id):
    user = User.query.get_or_404(id)

    if request.method == "POST":
        temporary_password = request.form.get("temporary_password", "")
        confirm_password = request.form.get("confirm_password", "")
        errors = []

        if not temporary_password:
            errors.append("Temporary password is required.")
        elif len(temporary_password) < 8:
            errors.append("Temporary password must be at least 8 characters.")
        if temporary_password != confirm_password:
            errors.append("Password confirmation does not match.")

        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("reset_password.html", user=user)

        user.password_hash = hash_password(temporary_password)
        user.must_change_password = True
        log_audit("password reset", details=f"Password reset for user {user.username}.")
        db.session.commit()
        flash("Password reset successfully.", "success")
        return redirect(url_for("users_detail", id=user.id))

    return render_template("reset_password.html", user=user)


@app.route("/users/<int:id>/toggle-active", methods=["POST"])
@admin_required
def users_toggle_active(id):
    user = User.query.get_or_404(id)
    if user.id == g.current_user.id:
        flash("You cannot deactivate your own account.", "danger")
        return redirect(url_for("users_list"))
    if user.role == "admin" and user.is_active and active_admin_count() <= 1:
        flash("You cannot deactivate the last active admin.", "danger")
        return redirect(url_for("users_list"))

    user.is_active = not user.is_active
    action = "user activation" if user.is_active else "user deactivation"
    log_audit(action, details=f"{action.title()} for user {user.username}.")
    db.session.commit()
    flash(f"User {'activated' if user.is_active else 'deactivated'} successfully.", "success")
    return redirect(url_for("users_list"))


@app.route("/users/<int:id>/delete", methods=["POST"])
@admin_required
def users_delete(id):
    user = User.query.get_or_404(id)
    if user.id == g.current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("users_list"))
    if user.role == "admin" and user.is_active and active_admin_count() <= 1:
        flash("You cannot delete the last active admin.", "danger")
        return redirect(url_for("users_list"))

    log_audit("user deletion", details=f"Deleted user {user.username} ({user.role}).")
    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully.", "success")
    return redirect(url_for("users_list"))


if __name__ == "__main__":
    app.run(debug=True)

```

## 3. Full code for models.py
```python
from datetime import date, datetime

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text
from werkzeug.security import check_password_hash, generate_password_hash


db = SQLAlchemy()


class Asset(db.Model):
    __tablename__ = "assets"

    id = db.Column(db.Integer, primary_key=True)
    asset_name = db.Column(db.String(120), nullable=False)
    asset_code = db.Column(db.String(50), nullable=False, unique=True, index=True)
    category = db.Column(db.String(80), nullable=False)
    department = db.Column(db.String(80), nullable=False)
    purchase_date = db.Column(db.Date, nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    purchase_cost = db.Column(db.Float, nullable=False, default=0.0)
    salvage_value = db.Column(db.Float, nullable=False, default=0.0)
    useful_life = db.Column(db.Integer, nullable=False, default=1)
    status = db.Column(db.String(30), nullable=False, default="Active")
    supplier = db.Column(db.String(120), nullable=True)
    invoice_number = db.Column(db.String(120), nullable=True)
    serial_number = db.Column(db.String(120), nullable=True)
    location = db.Column(db.String(120), nullable=True)
    warranty_expiry = db.Column(db.Date, nullable=True)
    asset_condition = db.Column(db.String(40), nullable=False, default="Good")
    disposal_date = db.Column(db.Date, nullable=True)
    disposal_reason = db.Column(db.String(255), nullable=True)
    disposal_value = db.Column(db.Float, nullable=True, default=0.0)
    disposal_notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    transfers = db.relationship(
        "AssetTransfer",
        backref="asset",
        lazy=True,
        cascade="all, delete-orphan",
        order_by="desc(AssetTransfer.transfer_date)",
    )
    disposals = db.relationship(
        "AssetDisposal",
        backref="asset",
        lazy=True,
        cascade="all, delete-orphan",
        order_by="desc(AssetDisposal.disposal_date)",
    )
    approvals = db.relationship(
        "ApprovalRequest",
        backref="asset",
        lazy=True,
        cascade="all, delete-orphan",
        order_by="desc(ApprovalRequest.submission_date)",
    )
    maintenance_records = db.relationship(
        "AssetMaintenance",
        backref="asset",
        lazy=True,
        cascade="all, delete-orphan",
        order_by="desc(AssetMaintenance.maintenance_date)",
    )
    verifications = db.relationship(
        "AssetVerification",
        backref="asset",
        lazy=True,
        cascade="all, delete-orphan",
        order_by="desc(AssetVerification.verification_date)",
    )
    documents = db.relationship(
        "AssetDocument",
        backref="asset",
        lazy=True,
        cascade="all, delete-orphan",
        order_by="desc(AssetDocument.uploaded_at)",
    )

    @property
    def years_used(self):
        return max(0, date.today().year - self.purchase_date.year)

    @property
    def annual_depreciation(self):
        if self.useful_life <= 0:
            return 0.0
        depreciable_amount = max(0.0, self.purchase_cost - self.salvage_value)
        return depreciable_amount / self.useful_life

    @property
    def accumulated_depreciation(self):
        depreciable_amount = max(0.0, self.purchase_cost - self.salvage_value)
        return min(self.annual_depreciation * self.years_used, depreciable_amount)

    @property
    def net_book_value(self):
        return max(self.purchase_cost - self.accumulated_depreciation, self.salvage_value)

    @property
    def remaining_useful_life(self):
        return max(0, self.useful_life - self.years_used)

    @property
    def nearing_end_of_life(self):
        return self.status != "Disposed" and self.remaining_useful_life <= 1

    @property
    def is_disposed(self):
        return self.status == "Disposed"

    @property
    def is_fully_depreciated(self):
        return self.net_book_value <= self.salvage_value and self.status != "Disposed"

    @property
    def total_maintenance_cost(self):
        return sum(record.maintenance_cost for record in self.maintenance_records)


class ApprovalRequest(db.Model):
    __tablename__ = "approval_requests"

    id = db.Column(db.Integer, primary_key=True)
    request_type = db.Column(db.String(40), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=True, index=True)
    submitted_by = db.Column(db.String(120), nullable=False)
    reviewed_by = db.Column(db.String(120), nullable=True)
    approved_by = db.Column(db.String(120), nullable=True)
    status = db.Column(db.String(30), nullable=False, default="draft", index=True)
    request_payload = db.Column(db.Text, nullable=True)
    comments = db.Column(db.Text, nullable=True)
    rejection_reason = db.Column(db.Text, nullable=True)
    submission_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    review_date = db.Column(db.DateTime, nullable=True)
    approval_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class AssetTransfer(db.Model):
    __tablename__ = "asset_transfers"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    old_department = db.Column(db.String(80), nullable=False)
    new_department = db.Column(db.String(80), nullable=False)
    transfer_date = db.Column(db.Date, nullable=False, default=date.today)
    reason = db.Column(db.String(255), nullable=False)
    transferred_by = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class AssetDisposal(db.Model):
    __tablename__ = "asset_disposals"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    disposal_date = db.Column(db.Date, nullable=False, default=date.today)
    disposal_reason = db.Column(db.String(255), nullable=False)
    disposal_value = db.Column(db.Float, nullable=False, default=0.0)
    disposal_notes = db.Column(db.Text, nullable=True)
    disposed_by = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class AssetMaintenance(db.Model):
    __tablename__ = "asset_maintenance"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    maintenance_date = db.Column(db.Date, nullable=False)
    maintenance_type = db.Column(db.String(80), nullable=False)
    service_provider = db.Column(db.String(120), nullable=False)
    maintenance_cost = db.Column(db.Float, nullable=False, default=0.0)
    next_maintenance_date = db.Column(db.Date, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class AssetVerification(db.Model):
    __tablename__ = "asset_verifications"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    verification_date = db.Column(db.Date, nullable=False)
    verified_by = db.Column(db.String(120), nullable=False)
    expected_location = db.Column(db.String(120), nullable=True)
    actual_location = db.Column(db.String(120), nullable=True)
    expected_condition = db.Column(db.String(40), nullable=True)
    actual_condition = db.Column(db.String(40), nullable=True)
    verification_status = db.Column(db.String(40), nullable=False, default="verified", index=True)
    discrepancy_notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class AssetDocument(db.Model):
    __tablename__ = "asset_documents"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    document_type = db.Column(db.String(40), nullable=False, index=True)
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    uploaded_by = db.Column(db.String(120), nullable=False)
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    notes = db.Column(db.Text, nullable=True)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True, index=True)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(80), nullable=False, index=True)
    asset_id = db.Column(db.Integer, nullable=True, index=True)
    asset_name = db.Column(db.String(120), nullable=True)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True, index=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="viewer")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    must_change_password = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method="pbkdf2:sha256")

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


def cleanup_removed_legacy_tables():
    inspector = inspect(db.engine)
    existing_tables = set(inspector.get_table_names())
    legacy_tables = [("re" "order_requests"), ("st" "ock_movements"), ("st" "ock_items")]
    for table_name in legacy_tables:
        if table_name in existing_tables:
            db.session.execute(text(f"DROP TABLE IF EXISTS {table_name}"))
    db.session.commit()


def migrate_asset_columns():
    inspector = inspect(db.engine)
    if "assets" not in inspector.get_table_names():
        return

    existing_columns = {column["name"] for column in inspector.get_columns("assets")}
    additions = {
        "quantity": "INTEGER DEFAULT 1",
        "supplier": "VARCHAR(120)",
        "invoice_number": "VARCHAR(120)",
        "serial_number": "VARCHAR(120)",
        "location": "VARCHAR(120)",
        "warranty_expiry": "DATE",
        "asset_condition": "VARCHAR(40) DEFAULT 'Good'",
        "disposal_date": "DATE",
        "disposal_reason": "VARCHAR(255)",
        "disposal_value": "FLOAT DEFAULT 0",
        "disposal_notes": "TEXT",
        "created_at": "DATETIME",
        "updated_at": "DATETIME",
    }

    changed = False
    for column_name, ddl in additions.items():
        if column_name not in existing_columns:
            db.session.execute(text(f"ALTER TABLE assets ADD COLUMN {column_name} {ddl}"))
            changed = True

    if changed:
        now = datetime.utcnow().isoformat(sep=" ")
        if "quantity" not in existing_columns:
            db.session.execute(text("UPDATE assets SET quantity = 1 WHERE quantity IS NULL OR quantity <= 0"))
        if "created_at" not in existing_columns:
            db.session.execute(text("UPDATE assets SET created_at = :now WHERE created_at IS NULL"), {"now": now})
        if "updated_at" not in existing_columns:
            db.session.execute(text("UPDATE assets SET updated_at = :now WHERE updated_at IS NULL"), {"now": now})
        db.session.commit()


def init_db(app):
    db.init_app(app)
    with app.app_context():
        cleanup_removed_legacy_tables()
        db.create_all()
        migrate_asset_columns()
        db.create_all()

```

## 4. Full code for seed_data.py
```python
from datetime import date

from werkzeug.security import generate_password_hash

from models import Asset, User, db


def seed_default_users():
    admin_user = User.query.filter_by(username="admin").first()
    if not admin_user:
        admin_user = User(username="admin")
        db.session.add(admin_user)
    admin_user.full_name = "System Administrator"
    admin_user.email = "admin@company.com"
    admin_user.role = "admin"
    admin_user.is_active = True
    admin_user.must_change_password = True
    if not admin_user.password_hash:
        admin_user.password_hash = generate_password_hash("Admin123!", method="pbkdf2:sha256")

    viewer_user = User.query.filter_by(username="viewer").first()
    if not viewer_user:
        viewer_user = User(username="viewer")
        db.session.add(viewer_user)
    viewer_user.full_name = "Finance Viewer"
    viewer_user.email = "viewer@company.com"
    viewer_user.role = "viewer"
    viewer_user.is_active = True
    viewer_user.must_change_password = True
    if not viewer_user.password_hash:
        viewer_user.password_hash = generate_password_hash("Viewer123!", method="pbkdf2:sha256")

    db.session.commit()


def seed_sample_data():
    """Insert realistic finance-department fixed assets when the database is empty."""
    seed_default_users()

    if Asset.query.count() > 0:
        return

    sample_assets = [
        Asset(
            asset_name="Dell Latitude 5440 Laptop",
            asset_code="IT-LAP-001",
            category="IT Equipment",
            department="Information Technology",
            purchase_date=date(2022, 5, 12),
            quantity=24,
            purchase_cost=1250.00,
            salvage_value=150.00,
            useful_life=5,
            status="Active",
            supplier="TechSource Bahrain",
            invoice_number="INV-IT-2022-0512",
            serial_number="DLL-5440-77821",
            location="Head Office - Floor 2",
            warranty_expiry=date(2025, 5, 12),
            asset_condition="Good",
        ),
        Asset(
            asset_name="HP LaserJet Enterprise Printer",
            asset_code="ADM-PRN-002",
            category="Office Equipment",
            department="Administration",
            purchase_date=date(2021, 9, 10),
            quantity=3,
            purchase_cost=800.00,
            salvage_value=100.00,
            useful_life=6,
            status="Under Maintenance",
            supplier="OfficePro Supplies",
            invoice_number="ADM-PRN-210910",
            serial_number="HP-LJ-009112",
            location="Administration Wing",
            warranty_expiry=date(2024, 9, 10),
            asset_condition="Fair",
        ),
        Asset(
            asset_name="Lenovo ThinkSystem Rack Server",
            asset_code="IT-SRV-003",
            category="IT Equipment",
            department="Information Technology",
            purchase_date=date(2020, 3, 5),
            quantity=2,
            purchase_cost=6500.00,
            salvage_value=600.00,
            useful_life=7,
            status="Active",
            supplier="Enterprise Compute Co.",
            invoice_number="IT-SRV-2020-305",
            serial_number="LNV-SRV-R540-11",
            location="Primary Data Center",
            warranty_expiry=date(2025, 3, 5),
            asset_condition="Good",
        ),
        Asset(
            asset_name="Toyota Hilux Utility Vehicle",
            asset_code="OPS-VEH-004",
            category="Vehicles",
            department="Operations",
            purchase_date=date(2019, 7, 18),
            quantity=4,
            purchase_cost=28500.00,
            salvage_value=5000.00,
            useful_life=8,
            status="Active",
            supplier="Bahrain Auto Fleet",
            invoice_number="OPS-VEH-190718",
            serial_number="HILUX-20219-44",
            location="Operations Garage",
            warranty_expiry=date(2024, 7, 18),
            asset_condition="Fair",
        ),
        Asset(
            asset_name="Industrial Water Pump",
            asset_code="MNT-PMP-005",
            category="Industrial Equipment",
            department="Maintenance",
            purchase_date=date(2018, 11, 1),
            quantity=2,
            purchase_cost=12000.00,
            salvage_value=2000.00,
            useful_life=10,
            status="Active",
            supplier="FlowTech Industrial",
            invoice_number="MNT-PUMP-181101",
            serial_number="FTP-WP-55102",
            location="Utility Yard",
            warranty_expiry=date(2021, 11, 1),
            asset_condition="Good",
        ),
        Asset(
            asset_name="Office Workstation Desk Set",
            asset_code="HR-FUR-006",
            category="Furniture",
            department="Human Resources",
            purchase_date=date(2023, 1, 20),
            quantity=12,
            purchase_cost=2200.00,
            salvage_value=300.00,
            useful_life=10,
            status="Active",
            supplier="Workspace Interiors",
            invoice_number="HR-FUR-230120",
            serial_number="WS-DESK-6603",
            location="HR Office Suite",
            warranty_expiry=date(2026, 1, 20),
            asset_condition="New",
        ),
        Asset(
            asset_name="Backup Power Generator",
            asset_code="FAC-GEN-007",
            category="Power Equipment",
            department="Facilities",
            purchase_date=date(2017, 6, 14),
            quantity=1,
            purchase_cost=18000.00,
            salvage_value=3500.00,
            useful_life=12,
            status="Under Maintenance",
            supplier="Prime Power Systems",
            invoice_number="FAC-GEN-170614",
            serial_number="PWR-GEN-7718",
            location="Main Utility Plant",
            warranty_expiry=date(2020, 6, 14),
            asset_condition="Poor",
        ),
        Asset(
            asset_name="CNC Milling Machine",
            asset_code="MFG-MCH-008",
            category="Industrial Equipment",
            department="Manufacturing",
            purchase_date=date(2016, 8, 30),
            quantity=1,
            purchase_cost=42000.00,
            salvage_value=7000.00,
            useful_life=15,
            status="Disposed",
            supplier="Precision Machines Ltd.",
            invoice_number="MFG-CNC-160830",
            serial_number="CNC-MIL-9012",
            location="Manufacturing Bay 3",
            warranty_expiry=date(2019, 8, 30),
            asset_condition="Poor",
            disposal_date=date(2024, 2, 14),
            disposal_reason="Obsolete equipment replaced during plant modernization.",
            disposal_value=5500.00,
            disposal_notes="Disposed through approved contractor sale.",
        ),
        Asset(
            asset_name="Cisco Catalyst Network Switch",
            asset_code="IT-NET-009",
            category="IT Equipment",
            department="Information Technology",
            purchase_date=date(2021, 4, 22),
            quantity=6,
            purchase_cost=3400.00,
            salvage_value=350.00,
            useful_life=6,
            status="Active",
            supplier="NetCore Solutions",
            invoice_number="IT-NET-210422",
            serial_number="CSC-9300-1928",
            location="Data Center Rack 2",
            warranty_expiry=date(2026, 4, 22),
            asset_condition="Good",
        ),
        Asset(
            asset_name="Operations Storage Racking Unit",
            asset_code="OPS-STR-010",
            category="Industrial Equipment",
            department="Operations",
            purchase_date=date(2020, 10, 15),
            quantity=8,
            purchase_cost=9800.00,
            salvage_value=1200.00,
            useful_life=12,
            status="Active",
            supplier="SteelStore Systems",
            invoice_number="OPS-STR-201015",
            serial_number="STR-RACK-7710",
            location="Central Storage Hall",
            warranty_expiry=date(2025, 10, 15),
            asset_condition="Fair",
        ),
    ]

    db.session.add_all(sample_assets)
    db.session.commit()

```

## 5. Full code for templates/base.html
```html
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}AssetTrack Pro{% endblock %}</title>
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Manrope:wght@500;600;700;800&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}?v=20260314-typo-table-force-rewrite">
</head>
<body>
<div class="app-frame">
    <header class="top-hero">
        <div class="hero-inner">
            <div class="hero-brand">
                <div class="hero-logo"><i class="bi bi-building"></i></div>
                <div>
                    <h1>AssetTrack Pro</h1>
                    <p>Enterprise Asset Lifecycle Management</p>
                </div>
            </div>
            <div class="hero-meta">
                <span class="meta-pill"><i class="bi bi-shield-check me-1"></i> Controlled Ledger</span>
                <span class="meta-pill"><i class="bi bi-currency-exchange me-1"></i> BHD Reporting</span>
                {% if current_user %}
                    <span class="meta-pill"><i class="bi bi-person-badge me-1"></i> {{ current_user.username }} ({{ current_user.role|upper }})</span>
                {% endif %}
            </div>
        </div>

        <nav class="primary-nav">
            {% if current_user %}
                <a class="nav-item {% if request.endpoint == 'dashboard' %}active{% endif %}" href="{{ url_for('dashboard') }}">
                    <i class="bi bi-columns-gap"></i><span>Dashboard</span>
                </a>
                <a class="nav-item {% if request.endpoint == 'asset_list' %}active{% endif %}" href="{{ url_for('asset_list') }}">
                    <i class="bi bi-table"></i><span>Assets</span>
                </a>
                {% if current_user.role == 'admin' %}
                    <a class="nav-item {% if request.endpoint == 'add_asset' %}active{% endif %}" href="{{ url_for('add_asset') }}">
                        <i class="bi bi-plus-circle"></i><span>Add Asset</span>
                    </a>
                {% endif %}
                <a class="nav-item {% if request.endpoint in ['reports_hub', 'depreciation_report', 'depreciation_scenario', 'department_report', 'disposed_assets_report', 'end_of_life_report', 'verification_report', 'maintenance_report', 'approvals_report', 'documents_report'] %}active{% endif %}" href="{{ url_for('reports_hub') }}">
                    <i class="bi bi-bar-chart"></i><span>Reports</span>
                </a>
                <a class="nav-item {% if request.endpoint == 'approval_list' or request.endpoint == 'approval_review' %}active{% endif %}" href="{{ url_for('approval_list') }}">
                    <i class="bi bi-check2-square"></i><span>Approvals</span>
                </a>
                <a class="nav-item {% if request.endpoint == 'audit_logs' %}active{% endif %}" href="{{ url_for('audit_logs') }}">
                    <i class="bi bi-clock-history"></i><span>Audit Logs</span>
                </a>
                <a class="nav-item {% if request.endpoint == 'change_password' %}active{% endif %}" href="{{ url_for('change_password') }}">
                    <i class="bi bi-key"></i><span>Change Password</span>
                </a>
                {% if current_user.role == 'admin' %}
                    <a class="nav-item {% if request.endpoint in ['users_list', 'users_new', 'users_detail', 'users_edit', 'users_reset_password'] %}active{% endif %}" href="{{ url_for('users_list') }}">
                        <i class="bi bi-people"></i><span>User Management</span>
                    </a>
                {% endif %}
                <form method="POST" action="{{ url_for('logout') }}" class="d-inline ms-auto">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <button type="submit" class="nav-item bg-transparent border-0">
                        <i class="bi bi-box-arrow-right"></i><span>Logout</span>
                    </button>
                </form>
            {% else %}
                <a class="nav-item {% if request.endpoint == 'login' %}active{% endif %}" href="{{ url_for('login') }}">
                    <i class="bi bi-box-arrow-in-right"></i><span>Login</span>
                </a>
            {% endif %}
        </nav>
    </header>

    <main class="workspace-wrap">
        <div class="workspace-shell">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                            <i class="bi bi-{% if category == 'success' %}check-circle-fill{% elif category == 'warning' %}exclamation-triangle-fill{% elif category == 'info' %}info-circle-fill{% else %}exclamation-circle-fill{% endif %} me-2"></i>
                            {{ message }}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}

            {% block content %}{% endblock %}
        </div>
    </main>

    <footer class="app-footer">
        AssetTrack Pro • Enterprise Asset Management • Finance Department
    </footer>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
{% block scripts %}{% endblock %}
</body>
</html>

```

## 6. Full code for templates/login.html
```html
{% extends 'base.html' %}

{% block title %}Login - AssetTrack Pro{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-lg-5 col-xl-4">
        <section class="glass-panel">
            <header class="glass-head">
                <h5><i class="bi bi-shield-lock me-2"></i>AssetTrack Pro</h5>
                <p class="small text-muted mb-0">Smart asset lifecycle and depreciation management</p>
            </header>
            <div class="glass-body">
                <form method="POST" action="{{ url_for('login', next=request.args.get('next', '')) }}">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input type="text" class="form-control" id="username" name="username" required autocomplete="username">
                    </div>

                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <input type="password" class="form-control" id="password" name="password" required autocomplete="current-password">
                    </div>

                    <div class="d-grid">
                        <button type="submit" class="btn btn-primary">Sign In</button>
                    </div>
                </form>
            </div>
        </section>
    </div>
</div>
{% endblock %}

```

## 7. Full code for templates/change_password.html
```html
{% extends 'base.html' %}

{% block title %}Change Password - AssetTrack Pro{% endblock %}
{% block page_title %}Change Password{% endblock %}

{% block content %}
<div class="page-banner">
    <div>
        <h2>Account Security</h2>
        <p>Set a new password to maintain secure system access.</p>
    </div>
</div>

<section class="glass-panel" style="max-width:720px;">
    <header class="glass-head"><h5><i class="bi bi-key me-2"></i>Update Password</h5></header>
    <div class="glass-body">
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <div class="row g-3">
                <div class="col-md-6">
                    <label for="new_password" class="form-label">New Password</label>
                    <input type="password" class="form-control" id="new_password" name="new_password" required minlength="8" autocomplete="new-password">
                </div>
                <div class="col-md-6">
                    <label for="confirm_password" class="form-label">Confirm Password</label>
                    <input type="password" class="form-control" id="confirm_password" name="confirm_password" required minlength="8" autocomplete="new-password">
                </div>
            </div>
            <div class="form-actions mt-4">
                <button type="submit" class="btn btn-primary">Update Password</button>
            </div>
        </form>
    </div>
</section>
{% endblock %}

```

## 8. Full code for templates/dashboard.html
```html
{% extends 'base.html' %}

{% block title %}Dashboard - AssetTrack Pro{% endblock %}
{% block page_title %}Dashboard{% endblock %}

{% block content %}
<div class="page-banner">
    <div>
        <h2>Executive Asset Overview</h2>
        <p>Financial, compliance, and lifecycle indicators for enterprise fixed assets.</p>
    </div>
    {% if current_user and current_user.role == 'admin' %}
    <a href="{{ url_for('add_asset') }}" class="btn btn-primary btn-lg-action"><i class="bi bi-plus-lg me-1"></i>Add New Asset</a>
    {% endif %}
</div>

<div class="kpi-grid">
    <article class="kpi-card"><span class="kpi-label">Total Assets</span><strong class="kpi-value">{{ total_assets }}</strong><span class="kpi-foot">Registered assets</span></article>
    <article class="kpi-card"><span class="kpi-label">Total Quantity</span><strong class="kpi-value">{{ total_quantity }}</strong><span class="kpi-foot">Total unit count</span></article>
    <article class="kpi-card"><span class="kpi-label">Purchase Cost</span><strong class="kpi-value">{{ total_purchase_cost | bhd }}</strong><span class="kpi-foot">Historical acquisition</span></article>
    <article class="kpi-card"><span class="kpi-label">Accumulated Depreciation</span><strong class="kpi-value">{{ total_accumulated_depreciation | bhd }}</strong><span class="kpi-foot">To date</span></article>
    <article class="kpi-card"><span class="kpi-label">Net Book Value</span><strong class="kpi-value">{{ total_net_book_value | bhd }}</strong><span class="kpi-foot">Current carrying value</span></article>
    <article class="kpi-card"><span class="kpi-label">Active Assets</span><strong class="kpi-value">{{ active_assets_count }}</strong><span class="kpi-foot">In-service assets</span></article>
    <article class="kpi-card"><span class="kpi-label">Under Maintenance</span><strong class="kpi-value">{{ under_maintenance_assets_count }}</strong><span class="kpi-foot">Temporarily unavailable</span></article>
    <article class="kpi-card"><span class="kpi-label">Disposed Assets</span><strong class="kpi-value">{{ disposed_assets_count }}</strong><span class="kpi-foot">Retired assets</span></article>
    <article class="kpi-card"><span class="kpi-label">Pending Approvals</span><strong class="kpi-value">{{ pending_approval_count }}</strong><span class="kpi-foot">Submitted + review</span></article>
    <article class="kpi-card"><span class="kpi-label">Pending Disposal Approvals</span><strong class="kpi-value">{{ pending_disposal_approval_count }}</strong><span class="kpi-foot">Awaiting decision</span></article>
    <article class="kpi-card"><span class="kpi-label">Verification Discrepancies</span><strong class="kpi-value">{{ assets_with_discrepancies_count }}</strong><span class="kpi-foot">Mismatch / missing</span></article>
    <article class="kpi-card"><span class="kpi-label">Maintenance Due</span><strong class="kpi-value">{{ assets_due_maintenance_count }}</strong><span class="kpi-foot">Assets due for service</span></article>
    <article class="kpi-card"><span class="kpi-label">Maintenance Cost</span><strong class="kpi-value">{{ total_maintenance_cost | bhd }}</strong><span class="kpi-foot">Recorded spend</span></article>
    <article class="kpi-card"><span class="kpi-label">Documents</span><strong class="kpi-value">{{ document_count }}</strong><span class="kpi-foot">Linked files</span></article>
    <article class="kpi-card"><span class="kpi-label">Near End of Life</span><strong class="kpi-value">{{ nearing_end_assets_count }}</strong><span class="kpi-foot">Replacement planning</span></article>
</div>

<div class="row g-3">
    <div class="col-xl-7">
        <section class="glass-panel h-100">
            <header class="glass-head"><h5><i class="bi bi-clock-history me-2"></i>Most Recent Assets</h5></header>
            <div class="table-responsive premium-table-wrap">
                <table class="table premium-table mb-0">
                    <thead><tr><th>Code</th><th>Name</th><th>Status</th></tr></thead>
                    <tbody>
                    {% for asset in recent_assets %}
                    <tr>
                        <td>{{ asset.asset_code }}</td>
                        <td><a href="{{ url_for('asset_detail', id=asset.id) }}" class="text-decoration-none fw-semibold">{{ asset.asset_name }}</a></td>
                        <td><span class="badge status-{{ asset.status|lower|replace(' ', '-') }}">{{ asset.status }}</span></td>
                    </tr>
                    {% else %}
                    <tr><td colspan="3" class="text-center py-4 text-muted">No assets found.</td></tr>
                    {% endfor %}
                    </tbody>
                </table>
            </div>
        </section>
    </div>

    <div class="col-xl-5">
        <section class="glass-panel h-100">
            <header class="glass-head"><h5><i class="bi bi-exclamation-diamond me-2"></i>Near End of Useful Life</h5></header>
            <div class="table-responsive premium-table-wrap">
                <table class="table premium-table mb-0">
                    <thead><tr><th>Asset</th><th>Department</th><th>Remaining</th></tr></thead>
                    <tbody>
                    {% for asset in nearing_end_assets %}
                    <tr>
                        <td><a href="{{ url_for('asset_detail', id=asset.id) }}" class="text-decoration-none fw-semibold">{{ asset.asset_name }}</a></td>
                        <td>{{ asset.department }}</td>
                        <td>{{ asset.remaining_useful_life }} year{{ 's' if asset.remaining_useful_life != 1 else '' }}</td>
                    </tr>
                    {% else %}
                    <tr><td colspan="3" class="text-center py-4 text-muted">No assets currently near end of life.</td></tr>
                    {% endfor %}
                    </tbody>
                </table>
            </div>
        </section>
    </div>
</div>

<div class="row g-3 mt-1">
    <div class="col-xl-4"><section class="glass-panel"><header class="glass-head"><h5><i class="bi bi-pie-chart me-2"></i>Assets by Category</h5></header><div class="glass-body"><canvas id="categoryChart" height="150"></canvas></div></section></div>
    <div class="col-xl-4"><section class="glass-panel"><header class="glass-head"><h5><i class="bi bi-bar-chart me-2"></i>Asset Status Mix</h5></header><div class="glass-body"><canvas id="statusChart" height="150"></canvas></div></section></div>
    <div class="col-xl-4"><section class="glass-panel"><header class="glass-head"><h5><i class="bi bi-check2-square me-2"></i>Verification Summary</h5></header><div class="glass-body"><canvas id="verificationChart" height="150"></canvas></div></section></div>
</div>

<div class="row g-3 mt-1">
    <div class="col-xl-6"><section class="glass-panel"><header class="glass-head"><h5><i class="bi bi-building me-2"></i>Assets by Department</h5></header><div class="glass-body"><canvas id="departmentChart" height="170"></canvas></div></section></div>
    <div class="col-xl-6"><section class="glass-panel"><header class="glass-head"><h5><i class="bi bi-currency-exchange me-2"></i>Depreciation by Department</h5></header><div class="glass-body"><canvas id="depreciationDepartmentChart" height="170"></canvas></div></section></div>
</div>

<section class="glass-panel mt-3">
    <header class="glass-head"><h5><i class="bi bi-activity me-2"></i>Recent Audit Log Entries</h5></header>
    <div class="table-responsive premium-table-wrap">
        <table class="table premium-table mb-0">
            <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Asset</th><th>Details</th></tr></thead>
            <tbody>
            {% for log in recent_audit_logs %}
            <tr>
                <td>{{ log.timestamp.strftime('%Y-%m-%d %H:%M') }}</td>
                <td>{{ log.username }}</td>
                <td>{{ log.action|title }}</td>
                <td>{{ log.asset_name or '—' }}</td>
                <td>{{ log.details or '—' }}</td>
            </tr>
            {% else %}
            <tr><td colspan="5" class="text-center py-4 text-muted">No recent audit activity.</td></tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
</section>
{% endblock %}

{% block scripts %}
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<script id="category-chart-labels" type="application/json">{{ category_chart_labels|tojson }}</script>
<script id="category-chart-values" type="application/json">{{ category_chart_values|tojson }}</script>
<script id="department-chart-labels" type="application/json">{{ department_chart_labels|tojson }}</script>
<script id="department-chart-values" type="application/json">{{ department_chart_values|tojson }}</script>
<script id="status-chart-labels" type="application/json">{{ status_chart_labels|tojson }}</script>
<script id="status-chart-values" type="application/json">{{ status_chart_values|tojson }}</script>
<script id="verification-chart-labels" type="application/json">{{ verification_chart_labels|tojson }}</script>
<script id="verification-chart-values" type="application/json">{{ verification_chart_values|tojson }}</script>
<script id="depr-dept-labels" type="application/json">{{ depreciation_department_labels|tojson }}</script>
<script id="depr-dept-values" type="application/json">{{ depreciation_department_values|tojson }}</script>
<script>
const categoryLabels = JSON.parse(document.getElementById('category-chart-labels').textContent);
const categoryValues = JSON.parse(document.getElementById('category-chart-values').textContent);
const departmentLabels = JSON.parse(document.getElementById('department-chart-labels').textContent);
const departmentValues = JSON.parse(document.getElementById('department-chart-values').textContent);
const statusLabels = JSON.parse(document.getElementById('status-chart-labels').textContent);
const statusValues = JSON.parse(document.getElementById('status-chart-values').textContent);
const verificationLabels = JSON.parse(document.getElementById('verification-chart-labels').textContent);
const verificationValues = JSON.parse(document.getElementById('verification-chart-values').textContent);
const depreciationLabels = JSON.parse(document.getElementById('depr-dept-labels').textContent);
const depreciationValues = JSON.parse(document.getElementById('depr-dept-values').textContent);

new Chart(document.getElementById('categoryChart'), {
    type: 'doughnut',
    data: {labels: categoryLabels, datasets: [{data: categoryValues, backgroundColor: ['#4f82e6','#7c5cff','#00b8a9','#ff8a65','#ffd166','#6c757d']}]},
    options: {responsive: true, maintainAspectRatio: false, plugins: {legend: {position: 'bottom'}}}
});
new Chart(document.getElementById('statusChart'), {
    type: 'pie',
    data: {labels: statusLabels, datasets: [{data: statusValues, backgroundColor: ['#16a34a','#f59e0b','#ef4444']}]},
    options: {responsive: true, maintainAspectRatio: false, plugins: {legend: {position: 'bottom'}}}
});
new Chart(document.getElementById('verificationChart'), {
    type: 'polarArea',
    data: {labels: verificationLabels, datasets: [{data: verificationValues, backgroundColor: ['#2563eb','#fb8c00','#e53935']}]},
    options: {responsive: true, maintainAspectRatio: false}
});
new Chart(document.getElementById('departmentChart'), {
    type: 'bar',
    data: {labels: departmentLabels, datasets: [{label: 'Assets', data: departmentValues, backgroundColor: '#4f82e6', borderRadius: 6}]},
    options: {responsive: true, maintainAspectRatio: false, plugins: {legend: {display: false}}, scales: {y: {beginAtZero: true, ticks: {precision: 0}}}}
});
new Chart(document.getElementById('depreciationDepartmentChart'), {
    type: 'bar',
    data: {labels: depreciationLabels, datasets: [{label: 'Accumulated Depreciation (BHD)', data: depreciationValues, backgroundColor: '#7c5cff', borderRadius: 6}]},
    options: {responsive: true, maintainAspectRatio: false, plugins: {legend: {display: false}}, scales: {y: {beginAtZero: true}}}
});
</script>
{% endblock %}

```

## 9. Full code for templates/asset_list.html
```html
{% extends 'base.html' %}

{% block title %}Assets - AssetTrack Pro{% endblock %}
{% block page_title %}Assets{% endblock %}

{% block content %}
<div class="page-banner">
    <div>
        <h2>Asset Register Workspace</h2>
        <p>Comprehensive ledger with filtering, control actions and lifecycle visibility.</p>
    </div>
    <div class="d-flex gap-2">
        <a href="{{ url_for('export_assets_csv', **filters) }}" class="btn btn-outline-primary btn-lg-action"><i class="bi bi-download me-1"></i>Export CSV</a>
        {% if current_user and current_user.role == 'admin' %}
        <a href="{{ url_for('add_asset') }}" class="btn btn-primary btn-lg-action"><i class="bi bi-plus-lg me-1"></i>Add Asset</a>
        {% endif %}
    </div>
</div>

<section class="glass-panel mb-3">
    <header class="glass-head"><h5><i class="bi bi-sliders me-2"></i>Search, Filters & Sorting</h5></header>
    <div class="glass-body">
        <form method="GET" action="{{ url_for('asset_list') }}" class="row g-3 filter-grid">
            <div class="col-md-4"><label for="search" class="form-label">Search</label><input type="text" id="search" name="search" class="form-control" value="{{ filters.search }}" placeholder="Asset name or code"></div>
            <div class="col-md-2"><label for="category" class="form-label">Category</label><select id="category" name="category" class="form-select"><option value="">All</option>{% for item in categories %}<option value="{{ item }}" {% if filters.category == item %}selected{% endif %}>{{ item }}</option>{% endfor %}</select></div>
            <div class="col-md-2"><label for="department" class="form-label">Department</label><select id="department" name="department" class="form-select"><option value="">All</option>{% for item in departments %}<option value="{{ item }}" {% if filters.department == item %}selected{% endif %}>{{ item }}</option>{% endfor %}</select></div>
            <div class="col-md-2"><label for="status" class="form-label">Status</label><select id="status" name="status" class="form-select"><option value="">All</option>{% for item in status_options %}<option value="{{ item }}" {% if filters.status == item %}selected{% endif %}>{{ item }}</option>{% endfor %}</select></div>
            <div class="col-md-2"><label for="supplier" class="form-label">Supplier</label><select id="supplier" name="supplier" class="form-select"><option value="">All</option>{% for item in suppliers %}<option value="{{ item }}" {% if filters.supplier == item %}selected{% endif %}>{{ item }}</option>{% endfor %}</select></div>
            <div class="col-md-2"><label for="condition" class="form-label">Condition</label><select id="condition" name="condition" class="form-select"><option value="">All</option>{% for item in condition_options %}<option value="{{ item }}" {% if filters.condition == item %}selected{% endif %}>{{ item }}</option>{% endfor %}</select></div>
            <div class="col-md-2"><label for="start_date" class="form-label">Purchase From</label><input type="date" id="start_date" name="start_date" class="form-control" value="{{ filters.start_date }}"></div>
            <div class="col-md-2"><label for="end_date" class="form-label">Purchase To</label><input type="date" id="end_date" name="end_date" class="form-control" value="{{ filters.end_date }}"></div>
            <div class="col-md-2"><label for="min_cost" class="form-label">Min Cost</label><input type="number" id="min_cost" name="min_cost" min="0" step="0.001" class="form-control" value="{{ filters.min_cost }}"></div>
            <div class="col-md-2"><label for="max_cost" class="form-label">Max Cost</label><input type="number" id="max_cost" name="max_cost" min="0" step="0.001" class="form-control" value="{{ filters.max_cost }}"></div>
            <div class="col-md-2"><label for="sort_by" class="form-label">Sort By</label><select id="sort_by" name="sort_by" class="form-select"><option value="asset_name" {% if filters.sort_by == 'asset_name' %}selected{% endif %}>Asset Name</option><option value="purchase_date" {% if filters.sort_by == 'purchase_date' %}selected{% endif %}>Purchase Date</option><option value="purchase_cost" {% if filters.sort_by == 'purchase_cost' %}selected{% endif %}>Purchase Cost</option><option value="department" {% if filters.sort_by == 'department' %}selected{% endif %}>Department</option><option value="status" {% if filters.sort_by == 'status' %}selected{% endif %}>Status</option></select></div>
            <div class="col-md-2"><label for="sort_dir" class="form-label">Direction</label><select id="sort_dir" name="sort_dir" class="form-select"><option value="asc" {% if filters.sort_dir == 'asc' %}selected{% endif %}>Ascending</option><option value="desc" {% if filters.sort_dir == 'desc' %}selected{% endif %}>Descending</option></select></div>
            <div class="col-md-2 d-flex align-items-end gap-2"><button type="submit" class="btn btn-primary w-100">Apply</button><a href="{{ url_for('asset_list') }}" class="btn btn-outline-secondary w-100">Reset</a></div>
        </form>
    </div>
</section>

<section class="glass-panel">
    <header class="glass-head"><h5><i class="bi bi-table me-2"></i>Asset Records</h5></header>
    <div class="table-responsive premium-table-wrap">
        <table class="table premium-table align-middle mb-0">
            <thead>
            <tr>
                <th>Asset Code</th><th>Asset Name</th><th>Category</th><th>Department</th><th>Qty</th><th>Supplier</th><th>Purchase Cost</th><th>Annual Depr.</th><th>Net Book Value</th><th>Status</th><th class="text-end asset-actions-col">Actions</th>
            </tr>
            </thead>
            <tbody>
            {% for asset in assets %}
            <tr>
                <td>{{ asset.asset_code }}</td>
                <td class="fw-semibold">{{ asset.asset_name }}</td>
                <td>{{ asset.category }}</td>
                <td>
                    {{ asset.department }}
                    {% set transfer_workflow = latest_transfer_status_by_asset.get(asset.id) %}
                    {% if transfer_workflow %}
                        <br><small class="text-muted">Transfer: <span class="badge status-{{ transfer_workflow.status }}">{{ transfer_workflow.status_label }}</span></small>
                    {% endif %}
                </td>
                <td>{{ asset.quantity }}</td>
                <td>{{ asset.supplier or '—' }}</td>
                <td>{{ asset.purchase_cost | bhd }}</td>
                <td>{{ asset.annual_depreciation | bhd }}</td>
                <td class="fw-bold">{{ asset.net_book_value | bhd }}</td>
                <td><span class="badge status-{{ asset.status|lower|replace(' ', '-') }}">{{ asset.status }}</span></td>
                <td class="text-end asset-actions-cell">
                    <div class="asset-actions">
                        <a href="{{ url_for('asset_detail', id=asset.id) }}" class="btn btn-sm btn-outline-info"><i class="bi bi-eye"></i></a>
                        {% if current_user and current_user.role == 'admin' %}
                            {% if not asset.is_disposed %}
                                <a href="{{ url_for('edit_asset', id=asset.id) }}" class="btn btn-sm btn-outline-warning"><i class="bi bi-pencil"></i></a>
                                <a href="{{ url_for('transfer_asset', id=asset.id) }}" class="btn btn-sm btn-outline-primary"><i class="bi bi-arrow-left-right"></i></a>
                                <a href="{{ url_for('dispose_asset', id=asset.id) }}" class="btn btn-sm btn-outline-danger"><i class="bi bi-archive"></i></a>
                            {% endif %}
                            <form action="{{ url_for('delete_asset', id=asset.id) }}" method="POST" class="d-inline" onsubmit="return confirm('Are you sure you want to delete this asset?');">
                                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                <button type="submit" class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button>
                            </form>
                        {% endif %}
                    </div>
                </td>
            </tr>
            {% else %}
            <tr><td colspan="11" class="text-center py-5 text-muted">No assets found for selected filters.</td></tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
</section>
{% endblock %}

```

## 10. Full code for templates/asset_form.html
```html
{% extends 'base.html' %}

{% block title %}{{ form_title }} - AssetTrack Pro{% endblock %}
{% block page_title %}Asset Form{% endblock %}

{% block content %}
<div class="page-banner">
    <div>
        <h2>{{ form_title }}</h2>
        <p>Use standardized fields to keep the asset ledger clean, auditable, and valuation-ready.</p>
    </div>
    <a href="{{ url_for('asset_list') }}" class="btn btn-outline-secondary btn-lg-action">Back to Register</a>
</div>

<section class="glass-panel">
    <header class="glass-head">
        <h5><i class="bi bi-input-cursor-text me-2"></i>Asset Submission Form</h5>
    </header>
    <div class="glass-body">
        <form method="POST" id="asset-form" data-edit-mode="{{ 'true' if asset else 'false' }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <div class="auto-preview-panel mb-4">
                <div class="auto-preview-head">
                    <h6><i class="bi bi-magic me-2"></i>Auto-calculated Preview</h6>
                    <span>Generated from your form values</span>
                </div>
                <div class="auto-preview-grid">
                    <div class="preview-card preview-wide">
                        <small>Generated Asset Code</small>
                        <strong id="asset_code_preview_text">{{ generated_code if generated_code else 'Will appear automatically' }}</strong>
                        <input type="hidden" id="asset_code" name="asset_code" value="{{ generated_code if generated_code else (asset.asset_code if asset else '') }}">
                    </div>
                    <div class="preview-card preview-wide">
                        <small>Generated Invoice Number</small>
                        <strong id="invoice_number_preview_text">{{ generated_invoice if generated_invoice else 'Generated automatically on save' }}</strong>
                    </div>
                    <div class="preview-card">
                        <small>Annual Depreciation</small>
                        <strong id="annual_depreciation_preview">BD 0.000</strong>
                    </div>
                    <div class="preview-card">
                        <small>Initial Net Book Value</small>
                        <strong id="net_book_value_preview">BD 0.000</strong>
                    </div>
                </div>
            </div>

            <div class="row g-3 filter-grid">
                <div class="col-md-6">
                    <label class="form-label" for="asset_name">Asset Name <span class="text-danger">*</span></label>
                    <input type="text" class="form-control" id="asset_name" name="asset_name" required
                           value="{{ form_data.get('asset_name', asset.asset_name if asset else '') }}">
                </div>
                <div class="col-md-6">
                    <label class="form-label">Asset Code Rule</label>
                    <div class="form-static-note">Code is generated automatically using department, category, and running sequence, for example OPS-VEH-004.</div>
                </div>

                <div class="col-md-6">
                    <label class="form-label" for="category">Category <span class="text-danger">*</span></label>
                    {% set selected_category = form_data.get('category', asset.category if asset else '') %}
                    <select class="form-select" id="category" name="category" required>
                        <option value="">Select category</option>
                        {% for item in categories %}
                            <option value="{{ item }}" {% if selected_category == item %}selected{% endif %}>{{ item }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div class="col-md-6">
                    <label class="form-label" for="department">Department <span class="text-danger">*</span></label>
                    {% set selected_department = form_data.get('department', asset.department if asset else '') %}
                    <select class="form-select" id="department" name="department" required>
                        <option value="">Select department</option>
                        {% for item in departments %}
                            <option value="{{ item }}" {% if selected_department == item %}selected{% endif %}>{{ item }}</option>
                        {% endfor %}
                    </select>
                </div>

                <div class="col-md-6">
                    <label class="form-label" for="purchase_date">Purchase Date <span class="text-danger">*</span></label>
                    <input type="date" class="form-control" id="purchase_date" name="purchase_date" required
                           value="{{ form_data.get('purchase_date', asset.purchase_date.strftime('%Y-%m-%d') if asset else '') }}">
                </div>
                <div class="col-md-3">
                    <label class="form-label" for="quantity">Quantity <span class="text-danger">*</span></label>
                    <input type="number" class="form-control" id="quantity" name="quantity" min="1" step="1" required
                           value="{{ form_data.get('quantity', asset.quantity if asset else 1) }}">
                </div>
                <div class="col-md-3">
                    <label class="form-label" for="useful_life">Useful Life (Years) <span class="text-danger">*</span></label>
                    <input type="number" class="form-control" id="useful_life" name="useful_life" min="1" required
                           value="{{ form_data.get('useful_life', asset.useful_life if asset else '') }}">
                </div>

                <div class="col-md-6">
                    <label class="form-label" for="purchase_cost">Purchase Cost (BHD) <span class="text-danger">*</span></label>
                    <input type="number" class="form-control" id="purchase_cost" name="purchase_cost" min="0" step="0.001" required
                           value="{{ form_data.get('purchase_cost', asset.purchase_cost if asset else '') }}">
                </div>
                <div class="col-md-6">
                    <label class="form-label" for="salvage_value">Salvage Value (BHD)</label>
                    <input type="number" class="form-control" id="salvage_value" name="salvage_value" min="0" step="0.001"
                           value="{{ form_data.get('salvage_value', asset.salvage_value if asset else '') }}">
                    <div class="form-text mt-1">Optional. Leave blank if unknown and the system will use 0.000.</div>
                </div>

                <div class="col-md-6">
                    <label class="form-label" for="status">Status <span class="text-danger">*</span></label>
                    <select class="form-select" id="status" name="status" required>
                        {% set selected_status = form_data.get('status', asset.status if asset else 'Active') %}
                        {% for option in status_options %}
                            <option value="{{ option }}" {% if selected_status == option %}selected{% endif %}>{{ option }}</option>
                        {% endfor %}
                    </select>
                </div>

                <div class="col-md-6">
                    <label class="form-label" for="supplier">Supplier</label>
                    <input type="text" class="form-control" id="supplier" name="supplier"
                           value="{{ form_data.get('supplier', asset.supplier if asset else '') }}">
                </div>
                <div class="col-md-6">
                    <label class="form-label" for="invoice_number">Invoice Number</label>
                      <input type="text" class="form-control" id="invoice_number" name="invoice_number" readonly
                          value="{{ asset.invoice_number if asset else generated_invoice }}">
                      <div class="form-text mt-1">Invoice number is generated automatically by the system.</div>
                </div>

                <div class="col-md-6">
                    <label class="form-label" for="serial_number">Serial Number</label>
                    <input type="text" class="form-control" id="serial_number" name="serial_number"
                           value="{{ form_data.get('serial_number', asset.serial_number if asset else '') }}">
                </div>
                <div class="col-md-6">
                    <label class="form-label" for="location">Location</label>
                    <input type="text" class="form-control" id="location" name="location"
                           value="{{ form_data.get('location', asset.location if asset else '') }}">
                </div>

                <div class="col-md-6">
                    <label class="form-label" for="warranty_expiry">Warranty Expiry</label>
                    <input type="date" class="form-control" id="warranty_expiry" name="warranty_expiry"
                           value="{{ form_data.get('warranty_expiry', asset.warranty_expiry.strftime('%Y-%m-%d') if asset and asset.warranty_expiry else '') }}">
                </div>
                <div class="col-md-6">
                    <label class="form-label" for="asset_condition">Condition <span class="text-danger">*</span></label>
                    {% set selected_condition = form_data.get('asset_condition', asset.asset_condition if asset else 'Good') %}
                    <select class="form-select" id="asset_condition" name="asset_condition" required>
                        {% for option in condition_options %}
                            <option value="{{ option }}" {% if selected_condition == option %}selected{% endif %}>{{ option }}</option>
                        {% endfor %}
                    </select>
                </div>
            </div>

            <div class="form-actions mt-4">
                <a href="{{ url_for('asset_list') }}" class="btn btn-outline-secondary">Cancel</a>
                {% if not asset %}
                    <button type="submit" name="submission_mode" value="draft" class="btn btn-outline-primary">Save as Draft</button>
                    <button type="submit" name="submission_mode" value="submitted" class="btn btn-primary">{{ submit_label }}</button>
                {% else %}
                    <button type="submit" class="btn btn-primary">{{ submit_label }}</button>
                {% endif %}
            </div>

            {% if not asset %}
                <div class="mt-3">
                    <label class="form-label" for="comments">Submission Comments</label>
                    <textarea id="comments" name="comments" class="form-control" rows="2" placeholder="Optional context for approval reviewers.">{{ form_data.get('comments', '') }}</textarea>
                </div>
            {% endif %}
        </form>
    </div>
</section>
{% endblock %}

{% block scripts %}
<script>
    (function () {
        const assetForm = document.getElementById('asset-form');
        const categoryInput = document.getElementById('category');
        const departmentInput = document.getElementById('department');
        const purchaseDateInput = document.getElementById('purchase_date');
        const purchaseCostInput = document.getElementById('purchase_cost');
        const salvageValueInput = document.getElementById('salvage_value');
        const usefulLifeInput = document.getElementById('useful_life');
        const assetCodeInput = document.getElementById('asset_code');
        const assetCodePreviewText = document.getElementById('asset_code_preview_text');
        const invoicePreviewText = document.getElementById('invoice_number_preview_text');
        const annualPreview = document.getElementById('annual_depreciation_preview');
        const nbvPreview = document.getElementById('net_book_value_preview');

        const isEditMode = assetForm.dataset.editMode === 'true';

        function segment(value, fallback) {
            const tokens = (value || '').toUpperCase().match(/[A-Z0-9]+/g) || [];
            if (!tokens.length) return fallback;
            if (tokens.length >= 2) {
                return tokens.slice(0, 3).map(token => token[0]).join('').slice(0, 4);
            }
            return tokens[0].slice(0, 3);
        }

        function formatBhd(value) {
            const numeric = Number.isFinite(value) ? value : 0;
            return `BD ${numeric.toLocaleString(undefined, { minimumFractionDigits: 3, maximumFractionDigits: 3 })}`;
        }

        function updateAssetCodePreview() {
            if (isEditMode) {
                assetCodePreviewText.textContent = assetCodeInput.value || 'Existing asset code retained';
                return;
            }

            const category = categoryInput.value.trim();
            const department = departmentInput.value.trim();
            const purchaseDate = purchaseDateInput.value;

            if (!category || !department || !purchaseDate) {
                if (!category || !department) {
                    assetCodeInput.value = '';
                    assetCodePreviewText.textContent = 'Will appear automatically';
                    return;
                }

                assetCodeInput.value = `${segment(department, 'DEP')}-${segment(category, 'CAT')}-###`;
                assetCodePreviewText.textContent = assetCodeInput.value;
                return;
            }

            if (!category || !department) {
                assetCodeInput.value = '';
                assetCodePreviewText.textContent = 'Will appear automatically';
                return;
            }

            assetCodeInput.value = `${segment(department, 'DEP')}-${segment(category, 'CAT')}-###`;
            assetCodePreviewText.textContent = assetCodeInput.value;
        }

        function updateInvoicePreview() {
            if (isEditMode) return;

            const today = new Date();
            const yyyy = today.getFullYear().toString();
            const mm = String(today.getMonth() + 1).padStart(2, '0');
            invoicePreviewText.textContent = `INV-${yyyy}${mm}-####`;
        }

        function updateFinancePreview() {
            const purchaseCost = parseFloat(purchaseCostInput.value || '0');
            const salvageValue = parseFloat(salvageValueInput.value || '0');
            const usefulLife = parseInt(usefulLifeInput.value || '0', 10);

            const annualDepreciation = usefulLife > 0 ? Math.max(0, purchaseCost - salvageValue) / usefulLife : 0;
            const initialNetBookValue = Math.max(purchaseCost, 0);

            annualPreview.textContent = formatBhd(annualDepreciation);
            nbvPreview.textContent = formatBhd(initialNetBookValue);
        }

        categoryInput.addEventListener('input', updateAssetCodePreview);
        departmentInput.addEventListener('input', updateAssetCodePreview);
        purchaseDateInput.addEventListener('input', updateAssetCodePreview);
        purchaseCostInput.addEventListener('input', updateFinancePreview);
        salvageValueInput.addEventListener('input', updateFinancePreview);
        usefulLifeInput.addEventListener('input', updateFinancePreview);

        updateAssetCodePreview();
        updateInvoicePreview();
        updateFinancePreview();
    })();
</script>
{% endblock %}

```

## 11. Full code for templates/asset_detail.html
```html
{% extends 'base.html' %}

{% block title %}Asset Detail - {{ asset.asset_name }}{% endblock %}
{% block page_title %}Asset Detail{% endblock %}

{% block content %}
<div class="page-banner">
    <div>
        <h2>Asset Intelligence Profile</h2>
        <p>Enterprise control view with lifecycle, approvals, maintenance, verification, and document governance.</p>
    </div>
    <div class="d-flex gap-2 flex-wrap">
        {% if current_user and current_user.role == 'admin' %}
            {% if not asset.is_disposed %}
                <a href="{{ url_for('edit_asset', id=asset.id) }}" class="btn btn-warning btn-lg-action">Edit Asset</a>
                <a href="{{ url_for('transfer_asset', id=asset.id) }}" class="btn btn-outline-primary btn-lg-action">Transfer Request</a>
                <a href="{{ url_for('dispose_asset', id=asset.id) }}" class="btn btn-outline-danger btn-lg-action">Disposal Request</a>
                <a href="{{ url_for('asset_maintenance_new', id=asset.id) }}" class="btn btn-outline-primary btn-lg-action">Add Maintenance</a>
                <a href="{{ url_for('asset_verify', id=asset.id) }}" class="btn btn-outline-primary btn-lg-action">Record Verification</a>
                <a href="{{ url_for('asset_document_upload', id=asset.id) }}" class="btn btn-outline-primary btn-lg-action">Upload Document</a>
            {% endif %}
        {% endif %}
        <a href="{{ url_for('asset_documents_list', id=asset.id) }}" class="btn btn-outline-secondary btn-lg-action">Documents</a>
        <a href="{{ url_for('asset_maintenance_list', id=asset.id) }}" class="btn btn-outline-secondary btn-lg-action">Maintenance</a>
        <a href="{{ url_for('asset_list') }}" class="btn btn-outline-secondary btn-lg-action">Back to Register</a>
    </div>
</div>

<div class="row g-4">
    <div class="col-xl-8">
        <section class="glass-panel h-100">
            <header class="glass-head"><h5><i class="bi bi-person-vcard me-2"></i>Master Information</h5></header>
            <div class="glass-body">
                <div class="profile-grid">
                    <div class="profile-row"><span>Asset Name</span><strong>{{ asset.asset_name }}</strong></div>
                    <div class="profile-row"><span>Asset Code</span><strong>{{ asset.asset_code }}</strong></div>
                    <div class="profile-row"><span>Category</span><strong>{{ asset.category }}</strong></div>
                    <div class="profile-row"><span>Department</span><strong>{{ asset.department }}</strong></div>
                    <div class="profile-row"><span>Quantity</span><strong>{{ asset.quantity }}</strong></div>
                    <div class="profile-row"><span>Purchase Date</span><strong>{{ asset.purchase_date.strftime('%Y-%m-%d') }}</strong></div>
                    <div class="profile-row"><span>Purchase Cost</span><strong>{{ asset.purchase_cost | bhd }}</strong></div>
                    <div class="profile-row"><span>Salvage Value</span><strong>{{ asset.salvage_value | bhd }}</strong></div>
                    <div class="profile-row"><span>Useful Life</span><strong>{{ asset.useful_life }} years</strong></div>
                    <div class="profile-row"><span>Supplier</span><strong>{{ asset.supplier or '—' }}</strong></div>
                    <div class="profile-row"><span>Invoice Number</span><strong>{{ asset.invoice_number or '—' }}</strong></div>
                    <div class="profile-row"><span>Serial Number</span><strong>{{ asset.serial_number or '—' }}</strong></div>
                    <div class="profile-row"><span>Location</span><strong>{{ asset.location or '—' }}</strong></div>
                    <div class="profile-row"><span>Condition</span><strong>{{ asset.asset_condition }}</strong></div>
                    <div class="profile-row"><span>Warranty Expiry</span><strong>{{ asset.warranty_expiry.strftime('%Y-%m-%d') if asset.warranty_expiry else '—' }}</strong></div>
                    <div class="profile-row"><span>Status</span><strong><span class="badge status-{{ asset.status|lower|replace(' ', '-') }}">{{ asset.status }}</span></strong></div>
                    <div class="profile-row"><span>Transfer Workflow</span><strong>{% if latest_transfer_approval %}<span class="badge status-{{ latest_transfer_approval.status }}">{{ latest_transfer_approval.status_label }}</span>{% else %}—{% endif %}</strong></div>
                    {% if latest_transfer_approval %}
                    <div class="profile-row"><span>Transfer Target Dept.</span><strong>{{ latest_transfer_approval.target_department or '—' }}</strong></div>
                    <div class="profile-row"><span>Transfer Requested On</span><strong>{{ latest_transfer_approval.transfer_date.strftime('%Y-%m-%d') if latest_transfer_approval.transfer_date else '—' }}</strong></div>
                    {% endif %}
                </div>
            </div>
        </section>
    </div>

    <div class="col-xl-4">
        <section class="glass-panel">
            <header class="glass-head"><h5><i class="bi bi-graph-down-arrow me-2"></i>Depreciation Snapshot</h5></header>
            <div class="glass-body">
                <div class="snapshot-list">
                    <article class="snapshot-item"><small>Years Used</small><strong>{{ asset.years_used }} yr{{ 's' if asset.years_used != 1 else '' }}</strong></article>
                    <article class="snapshot-item"><small>Annual Depreciation</small><strong>{{ asset.annual_depreciation | bhd }}</strong></article>
                    <article class="snapshot-item"><small>Accumulated Depreciation</small><strong>{{ asset.accumulated_depreciation | bhd }}</strong></article>
                    <article class="snapshot-item"><small>Net Book Value</small><strong class="text-success">{{ asset.net_book_value | bhd }}</strong></article>
                    <article class="snapshot-item"><small>Total Maintenance Cost</small><strong>{{ total_maintenance_cost | bhd }}</strong></article>
                </div>
            </div>
        </section>
    </div>
</div>

<div class="row g-4 mt-1">
    <div class="col-xl-6">
        <section class="glass-panel h-100">
            <header class="glass-head"><h5><i class="bi bi-check2-square me-2"></i>Approval Workflow History</h5></header>
            <div class="table-responsive premium-table-wrap">
                <table class="table premium-table mb-0">
                    <thead><tr><th>ID</th><th>Type</th><th>Status</th><th>Submitted</th><th>Reviewed/Approved</th></tr></thead>
                    <tbody>
                    {% for row in approval_history %}
                        <tr>
                            <td>#{{ row.id }}</td>
                            <td>{{ row.request_type.replace('_', ' ')|title }}</td>
                            <td><span class="badge status-{{ row.status|replace('_', '-') }}">{{ row.status|replace('_', ' ')|title }}</span></td>
                            <td>{{ row.submitted_by }}<br><small class="text-muted">{{ row.submission_date.strftime('%Y-%m-%d %H:%M') }}</small></td>
                            <td>{{ row.approved_by or row.reviewed_by or '—' }}</td>
                        </tr>
                        {% if row.rejection_reason %}
                            <tr><td colspan="5" class="text-danger small">Rejection Reason: {{ row.rejection_reason }}</td></tr>
                        {% endif %}
                    {% else %}
                        <tr><td colspan="5" class="text-center py-4 text-muted">No approval records found.</td></tr>
                    {% endfor %}
                    </tbody>
                </table>
            </div>
        </section>
    </div>

    <div class="col-xl-6">
        <section class="glass-panel h-100">
            <header class="glass-head"><h5><i class="bi bi-tools me-2"></i>Maintenance History</h5></header>
            <div class="table-responsive premium-table-wrap">
                <table class="table premium-table mb-0">
                    <thead><tr><th>Date</th><th>Type</th><th>Provider</th><th>Cost</th><th>Next Due</th></tr></thead>
                    <tbody>
                    {% for row in maintenance_history %}
                        <tr>
                            <td>{{ row.maintenance_date.strftime('%Y-%m-%d') }}</td>
                            <td>{{ row.maintenance_type }}</td>
                            <td>{{ row.service_provider }}</td>
                            <td>{{ row.maintenance_cost | bhd }}</td>
                            <td>{{ row.next_maintenance_date.strftime('%Y-%m-%d') if row.next_maintenance_date else '—' }}</td>
                        </tr>
                    {% else %}
                        <tr><td colspan="5" class="text-center py-4 text-muted">No maintenance records found.</td></tr>
                    {% endfor %}
                    </tbody>
                </table>
            </div>
        </section>
    </div>
</div>

<div class="row g-4 mt-1">
    <div class="col-xl-6">
        <section class="glass-panel h-100">
            <header class="glass-head"><h5><i class="bi bi-clipboard2-check me-2"></i>Verification History</h5></header>
            <div class="table-responsive premium-table-wrap">
                <table class="table premium-table mb-0">
                    <thead><tr><th>Date</th><th>Status</th><th>Expected</th><th>Actual</th></tr></thead>
                    <tbody>
                    {% for row in verification_history %}
                        <tr>
                            <td>{{ row.verification_date.strftime('%Y-%m-%d') }}</td>
                            <td><span class="badge status-{{ row.verification_status|replace('_','-') }}">{{ row.verification_status|replace('_',' ')|title }}</span></td>
                            <td>{{ row.expected_location }} / {{ row.expected_condition }}</td>
                            <td>{{ row.actual_location or '—' }} / {{ row.actual_condition or '—' }}</td>
                        </tr>
                        {% if row.discrepancy_notes %}
                            <tr><td colspan="4" class="text-muted small">{{ row.discrepancy_notes }}</td></tr>
                        {% endif %}
                    {% else %}
                        <tr><td colspan="4" class="text-center py-4 text-muted">No verification records found.</td></tr>
                    {% endfor %}
                    </tbody>
                </table>
            </div>
        </section>
    </div>

    <div class="col-xl-6">
        <section class="glass-panel h-100">
            <header class="glass-head"><h5><i class="bi bi-folder2-open me-2"></i>Document Attachments</h5></header>
            <div class="table-responsive premium-table-wrap">
                <table class="table premium-table mb-0">
                    <thead><tr><th>Type</th><th>File</th><th>Uploaded By</th><th>Date</th><th>Action</th></tr></thead>
                    <tbody>
                    {% for row in documents %}
                        <tr>
                            <td>{{ row.document_type|replace('_', ' ')|title }}</td>
                            <td>{{ row.file_name }}</td>
                            <td>{{ row.uploaded_by }}</td>
                            <td>{{ row.uploaded_at.strftime('%Y-%m-%d') }}</td>
                            <td><a href="{{ url_for('document_download', id=row.id) }}" class="btn btn-sm btn-outline-primary">Download</a></td>
                        </tr>
                    {% else %}
                        <tr><td colspan="5" class="text-center py-4 text-muted">No documents uploaded.</td></tr>
                    {% endfor %}
                    </tbody>
                </table>
            </div>
        </section>
    </div>
</div>

<section class="glass-panel mt-4">
    <header class="glass-head"><h5><i class="bi bi-shield-check me-2"></i>Audit Trail</h5></header>
    <div class="table-responsive premium-table-wrap">
        <table class="table premium-table mb-0">
            <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Details</th></tr></thead>
            <tbody>
            {% for log in related_audit_logs %}
                <tr>
                    <td>{{ log.timestamp.strftime('%Y-%m-%d %H:%M') }}</td>
                    <td>{{ log.username }}</td>
                    <td>{{ log.action|title }}</td>
                    <td>{{ log.details or '—' }}</td>
                </tr>
            {% else %}
                <tr><td colspan="4" class="text-center py-4 text-muted">No audit activity recorded.</td></tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
</section>

{% if asset.is_disposed %}
<section class="glass-panel mt-4">
    <header class="glass-head"><h5><i class="bi bi-archive-fill me-2"></i>Disposal Details</h5></header>
    <div class="glass-body">
        <div class="profile-grid">
            <div class="profile-row"><span>Disposal Date</span><strong>{{ asset.disposal_date.strftime('%Y-%m-%d') if asset.disposal_date else '—' }}</strong></div>
            <div class="profile-row"><span>Disposal Value</span><strong>{{ (asset.disposal_value or 0) | bhd }}</strong></div>
            <div class="profile-row"><span>Reason</span><strong>{{ asset.disposal_reason or '—' }}</strong></div>
            <div class="profile-row"><span>Notes</span><strong>{{ asset.disposal_notes or '—' }}</strong></div>
        </div>
    </div>
</section>
{% endif %}
{% endblock %}

```

## 12. Full code for templates/depreciation_report.html
```html
{% extends 'base.html' %}

{% block title %}Depreciation Report - AssetTrack Pro{% endblock %}

{% block content %}
<div class="page-banner">
    <div>
        <h2>Depreciation Intelligence Report</h2>
        <p>Portfolio-level depreciation analytics with transparent carrying value positions.</p>
    </div>
    <div class="d-flex gap-2">
        <a href="{{ url_for('export_depreciation_csv') }}" class="btn btn-outline-primary btn-lg-action">Export CSV</a>
        <a href="{{ url_for('asset_list') }}" class="btn btn-outline-primary btn-lg-action">Open Asset Register</a>
    </div>
</div>

<div class="kpi-grid report-kpis">
    <article class="kpi-card">
        <span class="kpi-label">Total Purchase Cost</span>
        <strong class="kpi-value">{{ totals.purchase_cost | bhd }}</strong>
        <span class="kpi-foot">Base historical value</span>
    </article>
    <article class="kpi-card">
        <span class="kpi-label">Accumulated Depreciation</span>
        <strong class="kpi-value">{{ totals.accumulated_depreciation | bhd }}</strong>
        <span class="kpi-foot">Depreciation already absorbed</span>
    </article>
    <article class="kpi-card">
        <span class="kpi-label">Net Book Value</span>
        <strong class="kpi-value">{{ totals.net_book_value | bhd }}</strong>
        <span class="kpi-foot">Current remaining value</span>
    </article>
</div>

<section class="glass-panel">
    <header class="glass-head">
        <h5><i class="bi bi-journal-text me-2"></i>Depreciation Ledger</h5>
    </header>
    <div class="table-responsive premium-table-wrap">
        <table class="table premium-table table-striped mb-0">
            <thead>
            <tr>
                <th>Asset Code</th>
                <th>Asset Name</th>
                <th>Purchase Cost</th>
                <th>Salvage Value</th>
                <th>Useful Life</th>
                <th>Yrs Used</th>
                <th>Annual Depr.</th>
                <th>Accumulated Depr.</th>
                <th>Net Book Value</th>
                <th>Status</th>
            </tr>
            </thead>
            <tbody>
            {% for asset in assets %}
                <tr>
                    <td>{{ asset.asset_code }}</td>
                    <td>{{ asset.asset_name }}</td>
                    <td>{{ asset.purchase_cost | bhd }}</td>
                    <td>{{ asset.salvage_value | bhd }}</td>
                    <td>{{ asset.useful_life }}</td>
                    <td>{{ asset.years_used }}</td>
                    <td>{{ asset.annual_depreciation | bhd }}</td>
                    <td>{{ asset.accumulated_depreciation | bhd }}</td>
                    <td class="fw-bold">{{ asset.net_book_value | bhd }}</td>
                    <td><span class="badge status-{{ asset.status|lower|replace(' ', '-') }}">{{ asset.status }}</span></td>
                </tr>
            {% else %}
                <tr>
                    <td colspan="10" class="text-center py-4 text-muted">No assets available.</td>
                </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
</section>
{% endblock %}

```

## 13. Full code for templates/department_report.html
```html
{% extends 'base.html' %}

{% block title %}Department Summary Report - AssetTrack Pro{% endblock %}

{% block content %}
<div class="page-banner">
    <div>
        <h2>Department Summary Report</h2>
        <p>Department-wise asset counts and value exposure.</p>
    </div>
    <div class="d-flex gap-2">
        <a href="{{ url_for('export_departments_csv') }}" class="btn btn-outline-primary btn-lg-action">Export CSV</a>
        <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary btn-lg-action">Back to Dashboard</a>
    </div>
</div>

<section class="glass-panel">
    <header class="glass-head">
        <h5><i class="bi bi-diagram-3 me-2"></i>Department Ledger</h5>
    </header>
    <div class="table-responsive premium-table-wrap">
        <table class="table premium-table mb-0">
            <thead>
                <tr>
                    <th>Department</th>
                    <th>Asset Count</th>
                    <th>Total Purchase Cost</th>
                    <th>Total Salvage Value</th>
                </tr>
            </thead>
            <tbody>
            {% for row in summary %}
                <tr>
                    <td>{{ row.department }}</td>
                    <td>{{ row.asset_count }}</td>
                    <td>{{ (row.purchase_total or 0) | bhd }}</td>
                    <td>{{ (row.salvage_total or 0) | bhd }}</td>
                </tr>
            {% else %}
                <tr><td colspan="4" class="text-center py-4 text-muted">No department records found.</td></tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
</section>
{% endblock %}

```

## 14. Full code for templates/disposed_report.html
```html
{% extends 'base.html' %}

{% block title %}Disposed Assets Report - AssetTrack Pro{% endblock %}

{% block content %}
<div class="page-banner">
    <div>
        <h2>Disposed Assets Report</h2>
        <p>Closed lifecycle assets with final disposal values and supporting reasons.</p>
    </div>
    <div class="d-flex gap-2">
        <a href="{{ url_for('export_disposed_assets_csv') }}" class="btn btn-outline-primary btn-lg-action">Export CSV</a>
        <a href="{{ url_for('asset_list') }}" class="btn btn-outline-secondary btn-lg-action">Open Asset Register</a>
    </div>
</div>

<section class="glass-panel">
    <header class="glass-head">
        <h5><i class="bi bi-archive-fill me-2"></i>Disposed Asset Ledger</h5>
    </header>
    <div class="table-responsive premium-table-wrap">
        <table class="table premium-table mb-0">
            <thead>
            <tr>
                <th>Asset Code</th>
                <th>Asset Name</th>
                <th>Department</th>
                <th>Disposal Date</th>
                <th>Reason</th>
                <th>Disposal Value</th>
            </tr>
            </thead>
            <tbody>
            {% for asset in assets %}
                <tr>
                    <td>{{ asset.asset_code }}</td>
                    <td><a href="{{ url_for('asset_detail', id=asset.id) }}" class="text-decoration-none fw-semibold">{{ asset.asset_name }}</a></td>
                    <td>{{ asset.department }}</td>
                    <td>{{ asset.disposal_date.strftime('%Y-%m-%d') if asset.disposal_date else '—' }}</td>
                    <td>{{ asset.disposal_reason or '—' }}</td>
                    <td>{{ (asset.disposal_value or 0) | bhd }}</td>
                </tr>
            {% else %}
                <tr><td colspan="6" class="text-center py-5 text-muted">No disposed assets available.</td></tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
</section>
{% endblock %}

```

## 15. Full code for templates/end_of_life_report.html
```html
{% extends 'base.html' %}

{% block title %}End of Life Report - AssetTrack Pro{% endblock %}

{% block content %}
<div class="page-banner">
    <div>
        <h2>Assets Near End of Useful Life</h2>
        <p>Assets with very low or zero remaining useful life for replacement planning.</p>
    </div>
    <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary btn-lg-action">Back to Dashboard</a>
</div>

<section class="glass-panel">
    <header class="glass-head">
        <h5><i class="bi bi-exclamation-diamond me-2"></i>End-of-Life Assets</h5>
    </header>
    <div class="table-responsive premium-table-wrap">
        <table class="table premium-table mb-0">
            <thead>
                <tr>
                    <th>Asset Code</th>
                    <th>Asset Name</th>
                    <th>Department</th>
                    <th>Useful Life</th>
                    <th>Years Used</th>
                    <th>Remaining</th>
                    <th>Net Book Value</th>
                </tr>
            </thead>
            <tbody>
            {% for asset in assets %}
                <tr>
                    <td>{{ asset.asset_code }}</td>
                    <td><a href="{{ url_for('asset_detail', id=asset.id) }}" class="text-decoration-none fw-semibold">{{ asset.asset_name }}</a></td>
                    <td>{{ asset.department }}</td>
                    <td>{{ asset.useful_life }}</td>
                    <td>{{ asset.years_used }}</td>
                    <td>{{ asset.remaining_useful_life }}</td>
                    <td>{{ asset.net_book_value | bhd }}</td>
                </tr>
            {% else %}
                <tr><td colspan="7" class="text-center py-4 text-muted">No assets currently near end of life.</td></tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
</section>
{% endblock %}

```

## 16. Full code for templates/transfer_form.html
```html
{% extends 'base.html' %}

{% block title %}Transfer Asset - AssetTrack Pro{% endblock %}
{% block page_title %}Transfer Asset{% endblock %}

{% block content %}
<div class="page-banner">
    <div>
        <h2>Transfer Asset</h2>
        <p>Submit transfer workflow for approval before final department reassignment.</p>
    </div>
    <a href="{{ url_for('asset_detail', id=asset.id) }}" class="btn btn-outline-secondary btn-lg-action">Back to Asset</a>
</div>

<section class="glass-panel">
    <header class="glass-head">
        <h5><i class="bi bi-arrow-left-right me-2"></i>{{ asset.asset_name }}</h5>
    </header>
    <div class="glass-body">
        {% if latest_transfer_approval %}
        <div class="alert alert-success mb-3" role="alert">
            Latest transfer request: <strong>#{{ latest_transfer_approval.id }}</strong> —
            <span class="badge status-{{ latest_transfer_approval.status }}">{{ latest_transfer_approval.status_label }}</span>
            {% if latest_transfer_approval.target_department %}
                to <strong>{{ latest_transfer_approval.target_department }}</strong>
            {% endif %}
        </div>
        {% endif %}
        <form method="POST" class="row g-3 filter-grid">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <div class="col-md-6">
                <label class="form-label">Current Department</label>
                <input type="text" class="form-control" value="{{ asset.department }}" disabled>
            </div>
            <div class="col-md-6">
                <label class="form-label" for="new_department">New Department</label>
                <select class="form-select" id="new_department" name="new_department" required>
                    <option value="">Select department</option>
                    {% for department in departments %}
                        <option value="{{ department }}" {% if form_data.get('new_department') == department %}selected{% endif %}>{{ department }}</option>
                    {% endfor %}
                </select>
            </div>
            <div class="col-md-6">
                <label class="form-label" for="transfer_date">Transfer Date</label>
                <input type="date" class="form-control" id="transfer_date" name="transfer_date" required value="{{ form_data.get('transfer_date', '') }}">
            </div>
            <div class="col-md-12">
                <label class="form-label" for="reason">Reason</label>
                <textarea class="form-control" id="reason" name="reason" rows="4" required>{{ form_data.get('reason', '') }}</textarea>
            </div>
            <div class="col-md-12">
                <label class="form-label" for="comments">Approval Comments</label>
                <textarea class="form-control" id="comments" name="comments" rows="2">{{ form_data.get('comments', '') }}</textarea>
            </div>
            <div class="form-actions mt-4">
                <a href="{{ url_for('asset_detail', id=asset.id) }}" class="btn btn-outline-secondary">Cancel</a>
                <button type="submit" name="submission_mode" value="draft" class="btn btn-outline-primary">Save as Draft</button>
                <button type="submit" name="submission_mode" value="submitted" class="btn btn-primary">Submit for Approval</button>
            </div>
        </form>
    </div>
</section>
{% endblock %}

```

## 17. Full code for templates/disposal_form.html
```html
{% extends 'base.html' %}

{% block title %}Dispose Asset - AssetTrack Pro{% endblock %}
{% block page_title %}Dispose Asset{% endblock %}

{% block content %}
<div class="page-banner">
    <div>
        <h2>Dispose Asset</h2>
        <p>Submit disposal workflow for approval before retirement is finalized.</p>
    </div>
    <a href="{{ url_for('asset_detail', id=asset.id) }}" class="btn btn-outline-secondary btn-lg-action">Back to Asset</a>
</div>

<section class="glass-panel">
    <header class="glass-head">
        <h5><i class="bi bi-archive me-2"></i>{{ asset.asset_name }}</h5>
    </header>
    <div class="glass-body">
        <form method="POST" class="row g-3 filter-grid">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <div class="col-md-6">
                <label class="form-label" for="disposal_date">Disposal Date</label>
                <input type="date" class="form-control" id="disposal_date" name="disposal_date" required value="{{ form_data.get('disposal_date', '') }}">
            </div>
            <div class="col-md-6">
                <label class="form-label" for="disposal_value">Disposal Value (BHD)</label>
                <input type="number" class="form-control" id="disposal_value" name="disposal_value" min="0" step="0.001" value="{{ form_data.get('disposal_value', '0') }}">
            </div>
            <div class="col-md-12">
                <label class="form-label" for="disposal_reason">Disposal Reason</label>
                <input type="text" class="form-control" id="disposal_reason" name="disposal_reason" required value="{{ form_data.get('disposal_reason', '') }}">
            </div>
            <div class="col-md-12">
                <label class="form-label" for="disposal_notes">Disposal Notes</label>
                <textarea class="form-control" id="disposal_notes" name="disposal_notes" rows="4">{{ form_data.get('disposal_notes', '') }}</textarea>
            </div>
            <div class="col-md-12">
                <label class="form-label" for="comments">Approval Comments</label>
                <textarea class="form-control" id="comments" name="comments" rows="2">{{ form_data.get('comments', '') }}</textarea>
            </div>
            <div class="form-actions mt-4">
                <a href="{{ url_for('asset_detail', id=asset.id) }}" class="btn btn-outline-secondary">Cancel</a>
                <button type="submit" name="submission_mode" value="draft" class="btn btn-outline-primary">Save as Draft</button>
                <button type="submit" name="submission_mode" value="submitted" class="btn btn-danger">Submit for Approval</button>
            </div>
        </form>
    </div>
</section>
{% endblock %}

```

## 18. Full code for templates/audit_logs.html
```html
{% extends 'base.html' %}

{% block title %}Audit Logs - AssetTrack Pro{% endblock %}
{% block page_title %}Audit Logs{% endblock %}

{% block content %}
<div class="page-banner">
    <div>
        <h2>Audit Logs</h2>
        <p>Chronological activity records for authentication, user administration, and asset lifecycle events.</p>
    </div>
    <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary btn-lg-action">Back to Dashboard</a>
</div>

<section class="glass-panel">
    <header class="glass-head">
        <h5><i class="bi bi-clock-history me-2"></i>System Activity</h5>
    </header>
    <div class="table-responsive premium-table-wrap">
        <table class="table premium-table mb-0">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>User</th>
                    <th>Action</th>
                    <th>Asset</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
            {% for log in logs %}
                <tr>
                    <td>{{ log.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                    <td>{{ log.username }}</td>
                    <td>{{ log.action|title }}</td>
                    <td>{% if log.asset_id %}<a href="{{ url_for('asset_detail', id=log.asset_id) }}" class="text-decoration-none fw-semibold">{{ log.asset_name or ('Asset #' ~ log.asset_id) }}</a>{% else %}—{% endif %}</td>
                    <td>{{ log.details or '—' }}</td>
                </tr>
            {% else %}
                <tr><td colspan="5" class="text-center py-4 text-muted">No audit entries available.</td></tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
</section>
{% endblock %}

```

## 19. Full code for templates/user_list.html
```html
{% extends 'base.html' %}

{% block title %}User Management - AssetTrack Pro{% endblock %}
{% block page_title %}User Management{% endblock %}

{% block content %}
<div class="page-banner">
    <div>
        <h2>User Management</h2>
        <p>Manage application accounts, access roles, and security status.</p>
    </div>
    <a href="{{ url_for('users_new') }}" class="btn btn-primary btn-lg-action"><i class="bi bi-person-plus me-1"></i>Add User</a>
</div>

<section class="glass-panel">
    <header class="glass-head">
        <h5><i class="bi bi-people me-2"></i>System Users</h5>
    </header>
    <div class="table-responsive premium-table-wrap">
        <table class="table premium-table align-middle mb-0">
            <thead>
            <tr>
                <th>Username</th>
                <th>Full Name</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Password Policy</th>
                <th>Last Login</th>
                <th class="text-end">Actions</th>
            </tr>
            </thead>
            <tbody>
            {% for user in users %}
                <tr>
                    <td class="fw-semibold">{{ user.username }}</td>
                    <td>{{ user.full_name }}</td>
                    <td>{{ user.email }}</td>
                    <td><span class="badge {% if user.role == 'admin' %}text-bg-primary{% else %}text-bg-secondary{% endif %}">{{ user.role|upper }}</span></td>
                    <td>
                        {% if user.is_active %}
                            <span class="badge status-active">Active</span>
                        {% else %}
                            <span class="badge status-disposed">Inactive</span>
                        {% endif %}
                    </td>
                    <td>
                        {% if user.must_change_password %}
                            <span class="badge text-bg-warning">Must Change</span>
                        {% else %}
                            <span class="badge text-bg-success">OK</span>
                        {% endif %}
                    </td>
                    <td>{{ user.last_login.strftime('%Y-%m-%d %H:%M') if user.last_login else 'Never' }}</td>
                    <td class="text-end">
                        <a href="{{ url_for('users_detail', id=user.id) }}" class="btn btn-sm btn-outline-info"><i class="bi bi-eye"></i></a>
                        <a href="{{ url_for('users_edit', id=user.id) }}" class="btn btn-sm btn-outline-warning"><i class="bi bi-pencil"></i></a>
                        <a href="{{ url_for('users_reset_password', id=user.id) }}" class="btn btn-sm btn-outline-secondary"><i class="bi bi-key"></i></a>
                        <form action="{{ url_for('users_toggle_active', id=user.id) }}" method="POST" class="d-inline">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                            <button type="submit" class="btn btn-sm {% if user.is_active %}btn-outline-dark{% else %}btn-outline-success{% endif %}">
                                <i class="bi {% if user.is_active %}bi-pause-circle{% else %}bi-play-circle{% endif %}"></i>
                            </button>
                        </form>
                        <form action="{{ url_for('users_delete', id=user.id) }}" method="POST" class="d-inline" onsubmit="return confirm('Delete this user account?');">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                            <button type="submit" class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button>
                        </form>
                    </td>
                </tr>
            {% else %}
                <tr>
                    <td colspan="8" class="text-center py-5 text-muted">No users found.</td>
                </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
</section>
{% endblock %}

```

## 20. Full code for templates/user_form.html
```html
{% extends 'base.html' %}

{% block title %}{% if form_mode == 'create' %}Create User{% else %}Edit User{% endif %} - AssetTrack Pro{% endblock %}
{% block page_title %}User Form{% endblock %}

{% block content %}
<div class="page-banner">
    <div>
        <h2>{% if form_mode == 'create' %}Create User{% else %}Edit User{% endif %}</h2>
        <p>Configure identity details, role assignment, and account status.</p>
    </div>
    <a href="{{ url_for('users_list') }}" class="btn btn-outline-secondary btn-lg-action">Back to Users</a>
</div>

<section class="glass-panel">
    <header class="glass-head">
        <h5><i class="bi bi-person-vcard me-2"></i>User Profile Form</h5>
    </header>
    <div class="glass-body">
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

            <div class="row g-3 filter-grid">
                <div class="col-md-6">
                    <label for="username" class="form-label">Username</label>
                    <input
                        type="text"
                        class="form-control"
                        id="username"
                        name="username"
                        required
                        {% if form_mode == 'edit' %}readonly{% endif %}
                        value="{{ form_data.get('username', user.username if user else '') }}"
                    >
                    {% if form_mode == 'edit' %}
                        <div class="form-text">Username cannot be changed after creation.</div>
                    {% endif %}
                </div>

                <div class="col-md-6">
                    <label for="full_name" class="form-label">Full Name</label>
                    <input type="text" class="form-control" id="full_name" name="full_name" required value="{{ form_data.get('full_name', user.full_name if user else '') }}">
                </div>

                <div class="col-md-6">
                    <label for="email" class="form-label">Email</label>
                    <input type="email" class="form-control" id="email" name="email" required value="{{ form_data.get('email', user.email if user else '') }}">
                </div>

                <div class="col-md-6">
                    <label for="role" class="form-label">Role</label>
                    {% set selected_role = form_data.get('role', user.role if user else 'viewer') %}
                    <select id="role" name="role" class="form-select" required>
                        {% for role in roles %}
                            <option value="{{ role }}" {% if selected_role == role %}selected{% endif %}>{{ role|upper }}</option>
                        {% endfor %}
                    </select>
                </div>

                {% if form_mode == 'create' %}
                    <div class="col-md-6">
                        <label for="temporary_password" class="form-label">Temporary Password</label>
                        <input type="password" class="form-control" id="temporary_password" name="temporary_password" required minlength="8" autocomplete="new-password">
                        <div class="form-text">User will be forced to change password at next login.</div>
                    </div>
                {% endif %}

                <div class="col-md-6">
                    {% set active_checked = form_data.get('is_active') == 'on' if form_data else (user.is_active if user else True) %}
                    <label class="form-label d-block">Account Status</label>
                    <div class="form-check form-switch">
                        <input class="form-check-input" type="checkbox" role="switch" id="is_active" name="is_active" {% if active_checked %}checked{% endif %}>
                        <label class="form-check-label" for="is_active">Active account</label>
                    </div>
                </div>
            </div>

            <div class="form-actions mt-4">
                <a href="{{ url_for('users_list') }}" class="btn btn-outline-secondary">Cancel</a>
                <button type="submit" class="btn btn-primary">{% if form_mode == 'create' %}Create User{% else %}Update User{% endif %}</button>
            </div>
        </form>
    </div>
</section>
{% endblock %}

```

## 21. Full code for templates/user_detail.html
```html
{% extends 'base.html' %}

{% block title %}User Detail - {{ user.username }}{% endblock %}
{% block page_title %}User Detail{% endblock %}

{% block content %}
<div class="page-banner">
    <div>
        <h2>User Detail</h2>
        <p>Review identity attributes, security state, and account activity.</p>
    </div>
    <div class="d-flex gap-2">
        <a href="{{ url_for('users_edit', id=user.id) }}" class="btn btn-warning btn-lg-action">Edit User</a>
        <a href="{{ url_for('users_reset_password', id=user.id) }}" class="btn btn-outline-secondary btn-lg-action">Reset Password</a>
        <a href="{{ url_for('users_list') }}" class="btn btn-outline-primary btn-lg-action">Back to Users</a>
    </div>
</div>

<section class="glass-panel">
    <header class="glass-head">
        <h5><i class="bi bi-person-lines-fill me-2"></i>User Information</h5>
    </header>
    <div class="glass-body">
        <div class="profile-grid">
            <div class="profile-row"><span>Username</span><strong>{{ user.username }}</strong></div>
            <div class="profile-row"><span>Full Name</span><strong>{{ user.full_name }}</strong></div>
            <div class="profile-row"><span>Email</span><strong>{{ user.email }}</strong></div>
            <div class="profile-row"><span>Role</span><strong>{{ user.role|upper }}</strong></div>
            <div class="profile-row"><span>Status</span><strong>{% if user.is_active %}Active{% else %}Inactive{% endif %}</strong></div>
            <div class="profile-row"><span>Must Change Password</span><strong>{% if user.must_change_password %}Yes{% else %}No{% endif %}</strong></div>
            <div class="profile-row"><span>Created At</span><strong>{{ user.created_at.strftime('%Y-%m-%d %H:%M') }}</strong></div>
            <div class="profile-row"><span>Last Login</span><strong>{{ user.last_login.strftime('%Y-%m-%d %H:%M') if user.last_login else 'Never' }}</strong></div>
        </div>
    </div>
</section>
{% endblock %}

```

## 22. Full code for templates/reset_password.html
```html
{% extends 'base.html' %}

{% block title %}Reset Password - {{ user.username }}{% endblock %}
{% block page_title %}Reset Password{% endblock %}

{% block content %}
<div class="page-banner">
    <div>
        <h2>Reset Password</h2>
        <p>Assign a temporary password. User will be required to change it on next login.</p>
    </div>
    <a href="{{ url_for('users_detail', id=user.id) }}" class="btn btn-outline-secondary btn-lg-action">Back to User</a>
</div>

<section class="glass-panel">
    <header class="glass-head">
        <h5><i class="bi bi-key-fill me-2"></i>Temporary Password Setup</h5>
    </header>
    <div class="glass-body">
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

            <div class="row g-3 filter-grid">
                <div class="col-md-6">
                    <label class="form-label" for="temporary_password">Temporary Password</label>
                    <input type="password" class="form-control" id="temporary_password" name="temporary_password" required minlength="8" autocomplete="new-password">
                </div>
                <div class="col-md-6">
                    <label class="form-label" for="confirm_password">Confirm Password</label>
                    <input type="password" class="form-control" id="confirm_password" name="confirm_password" required minlength="8" autocomplete="new-password">
                </div>
            </div>

            <div class="form-actions mt-4">
                <a href="{{ url_for('users_detail', id=user.id) }}" class="btn btn-outline-secondary">Cancel</a>
                <button type="submit" class="btn btn-primary">Reset Password</button>
            </div>
        </form>
    </div>
</section>
{% endblock %}

```

## 23. Full code for static/css/style.css
```css
:root {
    --font-body: "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
    --font-heading: "Manrope", "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
    --bs-body-font-family: var(--font-body);
    --bs-font-sans-serif: var(--font-body);

    --bg: #f3f6fb;
    --surface: #ffffff;
    --surface-alt: #f8fafe;
    --line: #d8e1ef;
    --line-soft: #e7edf7;
    --text: #14253d;
    --muted: #5f738f;
    --brand: #2b5fae;
    --brand-soft: rgba(43, 95, 174, 0.11);
    --shadow-soft: 0 14px 32px rgba(20, 37, 61, 0.08);
    --shadow-card: 0 10px 24px rgba(20, 37, 61, 0.07);
    --success-bg: #e4f7ec;
    --success-text: #1f7a4e;
    --warn-bg: #fff2df;
    --warn-text: #946019;
    --neutral-bg: #ebf0f7;
    --neutral-text: #4e6079;
}

* {
    box-sizing: border-box;
}

.bi,
.bi::before {
    font-family: "bootstrap-icons" !important;
}

html,
body,
main,
nav,
header,
footer,
section,
article,
aside,
div,
span,
p,
small,
label,
a,
button,
input,
select,
textarea,
form,
ul,
ol,
li,
.card,
.card *,
.btn,
.btn *,
.nav,
.nav *,
.navbar,
.navbar *,
.dropdown,
.dropdown *,
.alert,
.alert *,
.badge,
.table,
.table *,
thead,
tbody,
th,
td,
caption,
.form-control,
.form-select,
.form-check-input,
.form-check-label,
.input-group,
.input-group-text,
.page-link,
.pagination,
.modal,
.modal * {
    font-family: var(--font-body) !important;
}

html,
body {
    margin: 0;
    min-height: 100%;
    background: radial-gradient(circle at top right, #e2eaf8 0%, #f3f6fb 35%, #f3f6fb 100%);
    color: var(--text);
    font-size: 0.97rem;
    line-height: 1.55;
    font-weight: 500;
    font-variant-numeric: tabular-nums lining-nums;
    font-feature-settings: "tnum" 1, "lnum" 1;
    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
}

h1,
h2,
h3,
h4,
h5,
h6,
.card-title,
.page-banner h2,
.glass-head h5,
.kpi-label,
.kpi-value,
.form-label,
.filter-grid .form-label,
.primary-nav .nav-item,
.report-card-title,
.report-card-tag,
.reports-center-eyebrow,
.reports-center-head h3,
.table thead th,
.premium-table thead th,
.auto-preview-head h6,
.snapshot-item small,
.profile-row span,
.insight-item small,
.app-footer {
    font-family: var(--font-heading) !important;
}

p,
span,
small,
label,
a,
button,
input,
select,
textarea,
.nav-item,
.card,
.badge,
.alert,
.table,
.table td,
.table th,
.form-control,
.form-select,
.input-group-text,
.form-check-label,
.form-text,
.text-muted,
::placeholder {
    font-family: var(--font-body) !important;
}

.form-control::placeholder,
.form-select::placeholder,
textarea::placeholder,
input::placeholder {
    font-family: var(--font-body) !important;
    color: #7b8ea7 !important;
}

a,
a:hover,
a:focus,
a:active {
    text-decoration: none;
}

a:not(.btn):not(.nav-item) {
    color: #1f4f90;
    transition: color 0.18s ease;
}

a:not(.btn):not(.nav-item):hover,
a:not(.btn):not(.nav-item):focus {
    color: #173c6e;
}

.app-frame {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

.top-hero {
    background: linear-gradient(120deg, #122640 0%, #1b3a63 58%, #2a5fae 100%);
    color: #edf4ff;
    border-bottom: 1px solid rgba(255, 255, 255, 0.25);
    box-shadow: 0 12px 34px rgba(13, 26, 47, 0.26);
}

.hero-inner {
    max-width: 1540px;
    margin: 0 auto;
    padding: 1.1rem 1.2rem 1rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
}

.hero-brand {
    display: flex;
    align-items: center;
    gap: 0.9rem;
}

.hero-logo {
    width: 48px;
    height: 48px;
    border-radius: 12px;
    background: rgba(255, 255, 255, 0.16);
    border: 1px solid rgba(255, 255, 255, 0.35);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.25rem;
}

.hero-brand h1 {
    margin: 0;
    font-size: 1.28rem;
    font-weight: 800;
    letter-spacing: 0.012em;
    line-height: 1.2;
}

.hero-brand p {
    margin: 0.2rem 0 0;
    font-size: 0.79rem;
    color: #d2e2f8;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    font-weight: 600;
}

.hero-meta {
    display: flex;
    align-items: center;
    gap: 0.45rem;
    flex-wrap: wrap;
}

.meta-pill {
    display: inline-flex;
    align-items: center;
    border: 1px solid rgba(255, 255, 255, 0.3);
    background: rgba(255, 255, 255, 0.12);
    color: #edf5ff;
    border-radius: 999px;
    padding: 0.33rem 0.72rem;
    font-size: 0.71rem;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    font-weight: 700;
}

.primary-nav {
    max-width: 1540px;
    margin: 0 auto;
    padding: 0 1.2rem;
    display: flex;
    gap: 0.55rem;
    align-items: center;
    overflow-x: auto;
}

.primary-nav .nav-item {
    color: #d8e6fa;
    text-decoration: none;
    font-size: 0.73rem;
    text-transform: uppercase;
    letter-spacing: 0.085em;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.74rem 0.88rem;
    border-top-left-radius: 10px;
    border-top-right-radius: 10px;
    border: 1px solid transparent;
    border-bottom: none;
    white-space: nowrap;
}

.primary-nav .nav-item:hover {
    color: #ffffff;
    background: rgba(255, 255, 255, 0.12);
}

.primary-nav .nav-item.active {
    color: #244b84;
    background: #fafdff;
    border-color: rgba(255, 255, 255, 0.36);
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.65);
}

.primary-nav .dropdown {
    position: relative;
}

.primary-nav .dropdown-menu {
    z-index: 2000;
    margin-top: 0.2rem;
}

.primary-nav .dropdown-item {
    font-size: 0.78rem;
}

.workspace-wrap {
    flex: 1;
    padding: 1.25rem;
}

.workspace-shell {
    max-width: 1540px;
    margin: 0 auto;
}

.page-banner {
    border: 1px solid var(--line);
    border-radius: 16px;
    background: linear-gradient(135deg, #ffffff 0%, #f7faff 100%);
    box-shadow: var(--shadow-soft);
    padding: 1.08rem 1.1rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 1.1rem;
}

.page-banner h2 {
    margin: 0;
    font-size: 1.62rem;
    font-weight: 800;
    line-height: 1.15;
    letter-spacing: -0.015em;
}

.page-banner p {
    margin: 0.34rem 0 0;
    color: var(--muted);
    font-size: 0.9rem;
    max-width: 72ch;
}

.btn,
.btn:focus,
.btn:hover,
button,
input[type="button"],
input[type="submit"] {
    border-radius: 10px;
    font-size: 0.82rem;
    font-weight: 600;
    letter-spacing: 0.028em;
    font-family: var(--font-body) !important;
    transition: all 0.18s ease;
    text-transform: none;
}

.btn {
    padding: 0.46rem 0.86rem;
}

.btn-lg-action {
    padding: 0.52rem 0.98rem;
}

.btn-primary {
    background: linear-gradient(135deg, #2f68bd, #1f4e93) !important;
    border: 1px solid #2a5ca8 !important;
    box-shadow: 0 8px 18px rgba(42, 95, 176, 0.26);
}

.btn-primary:hover {
    background: linear-gradient(135deg, #2a5cad, #18437f) !important;
    box-shadow: 0 10px 20px rgba(42, 95, 176, 0.3);
    transform: translateY(-1px);
}

.btn-warning {
    background: linear-gradient(135deg, #f2c35d, #dfa43d) !important;
    border-color: #d49a34 !important;
    color: #3c2a07 !important;
    box-shadow: 0 8px 18px rgba(212, 154, 52, 0.2);
}

.btn-warning:hover {
    background: linear-gradient(135deg, #ebb94a, #d8952d) !important;
    color: #312102 !important;
}

.btn-outline-primary,
.btn-outline-secondary,
.btn-outline-info,
.btn-outline-warning,
.btn-outline-danger {
    background: #fff;
    border-width: 1px;
    font-weight: 600;
}

.btn-outline-primary:hover,
.btn-outline-secondary:hover,
.btn-outline-info:hover,
.btn-outline-warning:hover,
.btn-outline-danger:hover {
    transform: translateY(-1px);
}

.btn-outline-info {
    color: #1f5f85;
    border-color: #9fc5dd;
}

.btn-outline-info:hover {
    background: #eaf5fb;
    color: #174865;
    border-color: #8ab7d3;
}

.btn-outline-warning {
    color: #8b620f;
    border-color: #e1c07c;
}

.btn-outline-warning:hover {
    background: #fff6e3;
    color: #6f4c09;
    border-color: #d4b165;
}

.btn-outline-danger {
    color: #9c3842;
    border-color: #e2b1b8;
}

.btn-outline-danger:hover {
    background: #fff0f2;
    color: #812c35;
    border-color: #d89aa3;
}

.btn-outline-secondary {
    color: #516883;
    border-color: #c9d6e7;
}

.btn-outline-secondary:hover {
    background: #f4f8fd;
    color: #354c67;
    border-color: #b8c8dd;
}

.btn-close {
    font-size: 0.72rem;
}

.kpi-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 0.95rem;
    margin-bottom: 1.05rem;
}

.report-kpis {
    grid-template-columns: repeat(3, minmax(0, 1fr));
}

.kpi-card {
    border: 1px solid var(--line);
    border-radius: 14px;
    background: var(--surface);
    padding: 1rem;
    box-shadow: var(--shadow-card);
    position: relative;
    overflow: hidden;
}

.kpi-card::after {
    content: "";
    position: absolute;
    right: -30px;
    top: -36px;
    width: 96px;
    height: 96px;
    border-radius: 999px;
    background: var(--brand-soft);
}

.kpi-label {
    display: block;
    font-size: 0.67rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-weight: 800;
    margin-bottom: 0.48rem;
}

.kpi-value {
    display: block;
    font-size: 1.38rem;
    line-height: 1.15;
    letter-spacing: -0.02em;
    margin-bottom: 0.45rem;
    font-variant-numeric: tabular-nums lining-nums;
    font-feature-settings: "tnum" 1, "lnum" 1;
}

.kpi-foot {
    font-size: 0.76rem;
    color: #6e819a;
    font-weight: 500;
}

.insight-band {
    border: 1px solid var(--line);
    border-radius: 14px;
    background: var(--surface-alt);
    display: grid;
    grid-template-columns: 1.2fr 1fr;
    gap: 0.8rem;
    padding: 0.8rem 0.9rem;
    margin-bottom: 1.05rem;
}

.insight-item small {
    display: block;
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-weight: 800;
    color: var(--muted);
    margin-bottom: 0.35rem;
}

.insight-item span {
    font-size: 0.84rem;
    color: #4e617c;
}

.progress-shell {
    width: 100%;
    height: 10px;
    border-radius: 999px;
    background: #dbe5f3;
    overflow: hidden;
    margin-bottom: 0.4rem;
}

.progress-fill {
    height: 100%;
    background: linear-gradient(90deg, #3d86e8, #2c5ba7);
    border-radius: 999px;
}

.glass-panel {
    border: 1px solid var(--line);
    border-radius: 14px;
    background: linear-gradient(180deg, #ffffff, #fbfdff);
    box-shadow: var(--shadow-card);
    overflow: hidden;
}

.glass-head {
    border-bottom: 1px solid #e3ebf6;
    background: #f8fbff;
    padding: 0.75rem 0.92rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.glass-head h5 {
    margin: 0;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #3b5578;
    font-weight: 800;
}

.glass-body {
    padding: 0.95rem;
}

.reports-center-panel {
    border: 1px solid var(--line);
    border-radius: 16px;
    background: linear-gradient(180deg, #ffffff 0%, #fbfdff 100%);
    box-shadow: var(--shadow-soft);
    padding: 1.1rem;
}

.reports-center-head {
    margin-bottom: 1rem;
    padding-bottom: 0.95rem;
    border-bottom: 1px solid #e6edf7;
}

.reports-center-eyebrow {
    display: inline-block;
    margin-bottom: 0.35rem;
    font-size: 0.68rem;
    font-weight: 800;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: #5d7698;
}

.reports-center-head h3 {
    margin: 0;
    font-size: 1.18rem;
    font-weight: 800;
    line-height: 1.2;
    color: #17304e;
    letter-spacing: -0.015em;
}

.reports-center-head p {
    margin: 0.38rem 0 0;
    font-size: 0.88rem;
    color: var(--muted);
    max-width: 72ch;
}

.report-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 1rem;
}

.report-card {
    border: 1px solid #dbe4f1;
    border-radius: 16px;
    background: linear-gradient(180deg, #ffffff 0%, #f9fbff 100%);
    box-shadow: 0 10px 24px rgba(20, 37, 61, 0.06);
    padding: 1rem;
    display: flex;
    flex-direction: column;
    min-height: 100%;
    transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease;
}

.report-card:hover {
    transform: translateY(-2px);
    border-color: #bfd0e7;
    box-shadow: 0 14px 30px rgba(20, 37, 61, 0.1);
}

.report-card-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    margin-bottom: 0.95rem;
}

.report-icon-badge {
    width: 50px;
    height: 50px;
    border-radius: 14px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, rgba(42, 95, 174, 0.14), rgba(42, 95, 174, 0.06));
    color: var(--brand);
    border: 1px solid rgba(42, 95, 174, 0.12);
    font-size: 1.15rem;
    flex-shrink: 0;
}

.report-card-tag {
    display: inline-flex;
    align-items: center;
    border-radius: 999px;
    background: #eef4fd;
    color: #567299;
    border: 1px solid #d8e4f5;
    padding: 0.3rem 0.58rem;
    font-size: 0.62rem;
    font-weight: 800;
    letter-spacing: 0.11em;
    text-transform: uppercase;
    white-space: nowrap;
}

.report-card-body {
    flex: 1;
}

.report-card-title {
    margin: 0 0 0.45rem;
    font-size: 1rem;
    font-weight: 800;
    line-height: 1.28;
    color: #18304f;
    letter-spacing: -0.015em;
}

.report-card-description {
    margin: 0;
    font-size: 0.84rem;
    line-height: 1.55;
    color: #657b97;
}

.report-card-actions {
    margin-top: 1rem;
    padding-top: 0.95rem;
    border-top: 1px solid #edf2f9;
}

.report-open-btn {
    width: 100%;
    justify-content: center;
}

/* Premium table system */
.table-responsive,
.premium-table-wrap,
.table-card,
.data-table-wrap {
    border: 1px solid #d6e0ee !important;
    border-radius: 14px !important;
    background: linear-gradient(180deg, #ffffff 0%, #f9fbff 100%) !important;
    overflow-x: auto;
    overflow-y: hidden;
    box-shadow: 0 14px 30px rgba(20, 37, 61, 0.08), 0 2px 0 rgba(255, 255, 255, 0.9) inset !important;
    position: relative;
}

.table-responsive::before,
.premium-table-wrap::before,
.table-card::before,
.data-table-wrap::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 46px;
    background: linear-gradient(180deg, rgba(237, 243, 251, 0.92), rgba(237, 243, 251, 0.36));
    border-bottom: 1px solid #dce6f3;
    pointer-events: none;
    z-index: 0;
}

.table,
.premium-table,
.table.table-striped,
.table.table-hover,
.table.table-bordered,
.table.table-sm {
    margin: 0;
    font-size: 0.86rem !important;
    border-color: var(--line-soft) !important;
    line-height: 1.36;
    font-family: var(--font-body) !important;
    border-collapse: separate !important;
    border-spacing: 0 6px !important;
    background: transparent !important;
    position: relative;
    z-index: 1;
}

.table > :not(caption) > * > *,
.premium-table > :not(caption) > * > * {
    border-color: #e2e9f4 !important;
}

.table thead th,
.premium-table thead th,
.table > :not(caption) > * > th,
.table > thead > tr > th,
.table-light > th,
.table-light > td {
    background: linear-gradient(180deg, #eef4fb 0%, #e8f0fa 100%) !important;
    color: #3b5578 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.11em !important;
    font-size: 0.67rem !important;
    font-weight: 800 !important;
    border-bottom: 1px solid #d5e0ef !important;
    box-shadow: inset 0 -1px 0 #d5e0ef;
    padding: 0.74rem 0.84rem !important;
    vertical-align: middle !important;
    font-family: var(--font-heading) !important;
    white-space: nowrap;
}

.table tbody tr,
.premium-table tbody tr {
    border-bottom: none !important;
}

.table tbody tr:nth-child(even),
.premium-table tbody tr:nth-child(even) {
    background: transparent !important;
}

.table tbody tr:hover,
.premium-table tbody tr:hover,
.table.table-hover > tbody > tr:hover > *,
.table-hover > tbody > tr:hover > td,
.table-hover > tbody > tr:hover > th {
    background: #f3f8ff !important;
}

.table tbody td,
.premium-table tbody td,
.table > :not(caption) > * > td {
    padding: 0.6rem 0.78rem !important;
    vertical-align: middle !important;
    color: #203550 !important;
    font-weight: 500;
    line-height: 1.34;
    font-family: var(--font-body) !important;
    font-variant-numeric: tabular-nums lining-nums;
    font-feature-settings: "tnum" 1, "lnum" 1;
    border-top: 1px solid #e4ebf6 !important;
    border-bottom: 1px solid #e4ebf6 !important;
    background: #ffffff !important;
}

.table tbody tr > td:first-child,
.premium-table tbody tr > td:first-child {
    border-left: 1px solid #e4ebf6 !important;
    border-top-left-radius: 10px;
    border-bottom-left-radius: 10px;
}

.table tbody tr > td:last-child,
.premium-table tbody tr > td:last-child {
    border-right: 1px solid #e4ebf6 !important;
    border-top-right-radius: 10px;
    border-bottom-right-radius: 10px;
}

.table tbody td.fw-bold,
.table tbody td.fw-semibold,
.premium-table tbody td.fw-bold,
.premium-table tbody td.fw-semibold {
    color: #16314f !important;
    font-weight: 700 !important;
}

.table td.text-end,
.table th.text-end,
.premium-table td.text-end,
.premium-table th.text-end {
    text-align: right !important;
}

.table td.text-end,
.premium-table td.text-end {
    font-variant-numeric: tabular-nums lining-nums;
    letter-spacing: 0.01em;
}

.table tbody td small,
.premium-table tbody td small,
.table tbody td .text-muted,
.premium-table tbody td .text-muted {
    font-size: 0.72rem !important;
    color: #6f839f !important;
    font-weight: 500 !important;
}

.table tbody td a,
.premium-table tbody td a,
.table a,
.text-decoration-none.fw-semibold {
    color: #1f4f90 !important;
    font-weight: 600 !important;
}

.table tbody td a:hover,
.premium-table tbody td a:hover,
.table tbody td a:focus,
.premium-table tbody td a:focus,
.text-decoration-none.fw-semibold:hover,
.text-decoration-none.fw-semibold:focus {
    color: #173c6e !important;
}

.table .btn,
.premium-table .btn,
.table .btn-sm,
.premium-table .btn-sm {
    padding: 0.22rem 0.4rem !important;
    font-size: 0.69rem !important;
    line-height: 1.1;
    border-radius: 8px !important;
    font-family: var(--font-body) !important;
    box-shadow: none !important;
}

.table td .btn + .btn,
.premium-table td .btn + .btn {
    margin-left: 0.18rem;
}

.table td form.d-inline,
.premium-table td form.d-inline {
    margin-left: 0.18rem;
}

.table td .d-flex.gap-2,
.premium-table td .d-flex.gap-2 {
    gap: 0.24rem !important;
    justify-content: flex-end;
    align-items: center;
}

.table td.text-end,
.premium-table td.text-end {
    white-space: nowrap;
}

.asset-actions-col,
.asset-actions-cell {
    min-width: 12.5rem !important;
    width: 12.5rem;
}

.asset-actions {
    display: inline-flex;
    align-items: center;
    justify-content: flex-end;
    flex-wrap: nowrap;
    gap: 0.24rem;
    min-width: max-content;
}

.asset-actions form {
    margin: 0;
}

.glass-panel .glass-body > .filter-grid,
.glass-panel .glass-body form.filter-grid,
.glass-panel .glass-body .row.filter-grid {
    border: 1px solid #dce5f2;
    border-radius: 12px;
    background: #f9fbff;
    padding: 0.68rem 0.75rem;
    margin: 0;
}

.glass-panel .glass-body .filter-grid .form-control,
.glass-panel .glass-body .filter-grid .form-select,
.glass-panel .glass-body .filter-grid .input-group-text {
    min-height: 36px;
    padding-top: 0.42rem;
    padding-bottom: 0.42rem;
    font-size: 0.83rem;
}

.glass-panel .glass-body .filter-grid .btn {
    min-height: 36px;
    padding: 0.35rem 0.66rem;
    font-size: 0.75rem;
}

.badge,
[class^="status-"],
[class*=" status-"] {
    border: 1px solid rgba(46, 74, 112, 0.14) !important;
    box-shadow: 0 1px 0 rgba(255, 255, 255, 0.85) inset;
}

.filter-grid .form-label {
    font-size: 0.67rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #5f7491;
    font-weight: 800;
    margin-bottom: 0.34rem;
}

.form-control,
.form-select,
.input-group-text,
.form-check-input,
.form-check-label {
    border-radius: 10px;
    border-color: #cfdbeb;
    font-size: 0.88rem;
    color: #18304f;
    font-family: var(--font-body) !important;
}

.form-control,
.form-select,
.input-group-text {
    padding: 0.52rem 0.7rem;
}

.input-group-text {
    background: #f6f9fe;
    color: #4f6787;
}

.form-control:focus,
.form-select:focus,
.form-check-input:focus {
    border-color: #7da7de;
    box-shadow: 0 0 0 0.18rem rgba(42, 95, 176, 0.14);
}

.form-label {
    font-size: 0.79rem;
    font-weight: 700;
    letter-spacing: 0.01em;
    color: #415a7c;
}

.form-text,
.text-muted {
    color: #6a7f99 !important;
    font-size: 0.76rem;
}

.badge {
    border-radius: 999px;
    font-size: 0.65rem;
    letter-spacing: 0.045em;
    text-transform: uppercase;
    padding: 0.34rem 0.54rem;
    font-weight: 800;
}

.status-active {
    background: var(--success-bg) !important;
    color: var(--success-text) !important;
}

.status-under-maintenance {
    background: var(--warn-bg) !important;
    color: var(--warn-text) !important;
}

.status-disposed {
    background: var(--neutral-bg) !important;
    color: var(--neutral-text) !important;
}

.status-pending,
.status-submitted,
.status-draft {
    background: #fff2df !important;
    color: #946019 !important;
}

.status-under_review,
.status-under-review {
    background: #e8f1ff !important;
    color: #2b5fae !important;
}

.status-approved {
    background: #e4f7ec !important;
    color: #1f7a4e !important;
}

.status-rejected {
    background: #fdeff0 !important;
    color: #8d2f37 !important;
}

.status-verified {
    background: #e4f7ec !important;
    color: #1f7a4e !important;
}

.status-discrepancy-found {
    background: #fff2df !important;
    color: #946019 !important;
}

.status-missing {
    background: #fdeff0 !important;
    color: #8d2f37 !important;
}

.profile-grid {
    display: grid;
    gap: 0.55rem;
}

.profile-row {
    border: 1px solid #e2e9f5;
    border-radius: 12px;
    background: #fbfdff;
    padding: 0.64rem 0.74rem;
    display: flex;
    justify-content: space-between;
    gap: 0.7rem;
    align-items: center;
}

.profile-row span {
    color: #637992;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-weight: 800;
}

.profile-row strong {
    font-size: 0.9rem;
    font-weight: 700;
    text-align: right;
    font-variant-numeric: tabular-nums lining-nums;
}

.snapshot-list {
    display: grid;
    gap: 0.6rem;
}

.snapshot-item {
    border: 1px solid #e1e8f4;
    border-radius: 12px;
    background: #f9fcff;
    padding: 0.7rem 0.75rem;
}

.snapshot-item small {
    display: block;
    text-transform: uppercase;
    letter-spacing: 0.095em;
    font-size: 0.65rem;
    color: #667d97;
    margin-bottom: 0.22rem;
    font-weight: 800;
}

.snapshot-item strong {
    font-size: 0.98rem;
    font-weight: 700;
    font-variant-numeric: tabular-nums lining-nums;
}

.form-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.6rem;
}

.auto-preview-panel {
    border: 1px solid #d7e2f0;
    border-radius: 16px;
    background: linear-gradient(135deg, #f8fbff 0%, #eef4fc 100%);
    padding: 0.9rem;
}

.auto-preview-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    margin-bottom: 0.75rem;
}

.auto-preview-head h6 {
    margin: 0;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #35527d;
    font-weight: 800;
}

.auto-preview-head span {
    font-size: 0.74rem;
    color: #637892;
}

.auto-preview-grid {
    display: grid;
    grid-template-columns: 1.4fr 1fr 1fr;
    gap: 0.7rem;
}

.preview-card {
    border: 1px solid #dce5f2;
    border-radius: 14px;
    background: rgba(255, 255, 255, 0.88);
    padding: 0.84rem 0.88rem;
}

.preview-card small {
    display: block;
    margin-bottom: 0.3rem;
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #68809d;
    font-weight: 800;
}

.preview-card strong {
    display: block;
    font-size: 1rem;
    font-weight: 700;
    color: #19304f;
    line-height: 1.3;
    font-variant-numeric: tabular-nums lining-nums;
}

.form-static-note {
    min-height: 40px;
    display: flex;
    align-items: center;
    border: 1px dashed #cddaea;
    border-radius: 10px;
    background: #f8fbff;
    padding: 0.5rem 0.65rem;
    font-size: 0.78rem;
    color: #627893;
}

.alert {
    border-radius: 12px;
    border: 1px solid;
    font-size: 0.83rem;
    margin-bottom: 0.85rem;
}

.alert-success {
    background: #eaf8f1;
    color: #1d6e47;
    border-color: #b9e2cd;
}

.alert-danger {
    background: #fdeff0;
    color: #8d2f37;
    border-color: #f1bec4;
}

.app-footer {
    text-align: center;
    padding: 0.68rem;
    background: #e9eff8;
    color: #4b6280;
    font-size: 0.73rem;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    border-top: 1px solid #ccd8ea;
}

@media (max-width: 1200px) {
    .kpi-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    .report-kpis {
        grid-template-columns: repeat(3, minmax(0, 1fr));
    }

    .report-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }
}

@media (max-width: 992px) {
    .hero-inner {
        flex-direction: column;
        align-items: flex-start;
    }

    .page-banner {
        flex-direction: column;
        align-items: flex-start;
    }

    .insight-band {
        grid-template-columns: 1fr;
    }

    .report-kpis {
        grid-template-columns: 1fr;
    }

    .auto-preview-grid {
        grid-template-columns: 1fr;
    }

    .report-grid {
        grid-template-columns: 1fr;
    }
}

@media (max-width: 768px) {
    .workspace-wrap {
        padding: 0.75rem;
    }

    .hero-inner,
    .primary-nav {
        padding-left: 0.75rem;
        padding-right: 0.75rem;
    }

    .kpi-grid {
        grid-template-columns: 1fr;
    }

    .profile-row {
        flex-direction: column;
        align-items: flex-start;
    }

    .profile-row strong {
        text-align: left;
    }
}

```

## 24. Full code for requirements.txt
```txt
Flask==3.1.0
Flask-SQLAlchemy==3.1.1
Flask-WTF==1.2.2
SQLAlchemy==2.0.36
Werkzeug==3.1.3

```

## 25. Full code for README.md
```markdown
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
    ├── maintenance_form.html
    ├── maintenance_list.html
    ├── verification_form.html
    ├── verification_report.html
    ├── document_upload_form.html
    ├── document_list.html
    ├── maintenance_report.html
    ├── approval_report.html
    ├── document_report.html
    ├── depreciation_scenario.html
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

```
