import csv
import io
import json
import os
import re
import uuid
from datetime import date, datetime
from zoneinfo import ZoneInfo
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

# Use in-memory database for serverless, file-based for local
is_serverless = os.getenv('VERCEL') == '1' or os.getenv('AWS_LAMBDA_FUNCTION_NAME')
if is_serverless:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///assets.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "university-fixed-asset-secret-key"
app.config["WTF_CSRF_ENABLED"] = True
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

try:
    csrf = CSRFProtect(app)
except Exception as e:
    app.logger.warning(f"CSRF protection initialization failed: {e}")

try:
    init_db(app)
except Exception as e:
    app.logger.warning(f"Database initialization failed: {e}")

try:
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
except Exception as e:
    app.logger.warning(f"Could not create upload folder: {e}")

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
    try:
        seed_sample_data()
    except Exception as e:
        # Database initialization failed - continue without seeding
        # This is expected in serverless environments
        app.logger.warning(f"Could not seed data: {e}")


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


@app.template_filter("friendly_status")
def friendly_status(value):
    if not value:
        return value
    return value.replace("_", " ").title()


def strip_html(value):
    return re.sub(r"<[^>]*>", "", (value or "")).strip()


def is_valid_email(email):
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email or ""))


@app.template_filter('as_bahrain')
def as_bahrain(value, fmt='%Y-%m-%d %H:%M'):
    if value is None:
        return ''
    # Convert date to datetime at midnight
    if isinstance(value, date) and not isinstance(value, datetime):
        dt = datetime.combine(value, datetime.min.time())
    elif isinstance(value, datetime):
        dt = value
    else:
        try:
            return str(value)
        except Exception:
            return ''

    # Assume naive datetimes are UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo('UTC'))

    try:
        local = dt.astimezone(ZoneInfo('Asia/Bahrain'))
        return local.strftime(fmt)
    except Exception:
        return dt.strftime(fmt)


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
        if submission_mode == "draft":
            # Create an Asset record directly for drafts so users can edit later
            from models import Asset

            new_asset = Asset(
                asset_name=form_data["asset_name"],
                asset_code=form_data["asset_code"],
                category=form_data["category"],
                department=form_data["department"],
                purchase_date=form_data["purchase_date"],
                quantity=form_data["quantity"] or 1,
                purchase_cost=form_data["purchase_cost"] or 0.0,
                salvage_value=form_data["salvage_value"] or 0.0,
                useful_life=form_data["useful_life"] or 1,
                status=form_data["status"] or "Active",
                supplier=form_data.get("supplier"),
                invoice_number=form_data.get("invoice_number"),
                serial_number=form_data.get("serial_number"),
                location=form_data.get("location"),
                warranty_expiry=form_data.get("warranty_expiry"),
                asset_condition=form_data.get("asset_condition") or "Good",
            )
            db.session.add(new_asset)
            db.session.commit()
            log_audit("create asset (draft)", asset=new_asset, details=f"Created draft asset {new_asset.asset_code} by user.")
            flash("Asset saved as draft.", "success")
            return redirect(url_for("asset_detail", id=new_asset.id))

        approval = create_approval_request(
            "asset_registration",
            payload=form_data,
            status="submitted",
            comments=comments,
        )
        log_audit(
            "approval submission",
            details=f"Submitted asset registration approval request #{approval.id} with status {approval.status}.",
        )
        db.session.commit()
        flash("Asset registration submitted for approval.", "success")
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
