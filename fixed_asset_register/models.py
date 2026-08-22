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
