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
