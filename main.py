from fastapi import (
    FastAPI,
    Depends,
    Request,
    Form,
    Query,
    Response,
    Cookie,
)
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Enum,
    DateTime,
    ForeignKey,
    Boolean,
)
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
from datetime import datetime
import enum
from pydantic import BaseModel

# ------------------ DATABASE SETUP ------------------ #

DATABASE_URL = "sqlite:///./factory.db"   # For demo; switch to Postgres/MySQL in prod

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ------------------ MODELS ------------------ #

class RoleEnum(str, enum.Enum):
    procurement = "procurement"
    manufacturing = "manufacturing"
    qa = "qa"
    packaging = "packaging"
    inventory = "inventory"
    management = "management"


class WorkOrderStatus(str, enum.Enum):
    # Generic statuses
    new = "new"
    in_progress = "in_progress"
    waiting_qc = "waiting_qc"   # kept for compatibility, not really used now
    completed = "completed"
    rejected = "rejected"
    # Department / special
    testing = "testing"      # QA
    failed = "failed"        # QA
    packing = "packing"      # Packaging
    packed = "packed"        # Packaging
    on_shelf = "on_shelf"    # Inventory
    shipped = "shipped"      # Inventory
    expired = "expired"      # Inventory
    blocked = "blocked"      # Blocked by dependency


class ProcurementRequestStatus(str, enum.Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)    # DEMO ONLY
    role = Column(Enum(RoleEnum), nullable=False)


class Vendor(Base):
    __tablename__ = "vendors"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    contact_person = Column(String, nullable=True)
    phone = Column(String, nullable=True)
    email = Column(String, nullable=True)
    address = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)

    workorders = relationship("WorkOrder", back_populates="vendor")


class WorkOrder(Base):
    __tablename__ = "workorders"
    id = Column(Integer, primary_key=True, index=True)
    # Human-friendly ID: MGMT / FTRY / PROC / QUAL / PACK / INVN + DDMMYYYYHHMM
    display_id = Column(String, index=True, nullable=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    status = Column(Enum(WorkOrderStatus), default=WorkOrderStatus.new)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    assigned_role = Column(Enum(RoleEnum), nullable=False)
    vendor_id = Column(Integer, ForeignKey("vendors.id"), nullable=True)
    quantity = Column(Integer, default=1)
    unit = Column(String, default="Count")  # KG / Count / Litres

    vendor = relationship("Vendor", back_populates="workorders")


class InventoryItem(Base):
    __tablename__ = "inventory_items"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    quantity = Column(Integer, default=0)
    unit = Column(String, default="pcs")


class ProcurementRequest(Base):
    __tablename__ = "procurement_requests"
    id = Column(Integer, primary_key=True, index=True)
    # Human-friendly ID for requests, e.g. REQ221120251912
    display_id = Column(String, index=True, nullable=True)

    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    quantity = Column(Integer, default=1)
    unit = Column(String, default="Count")  # KG / Count / Litres

    # Manufacturing task that depends on this procurement
    dependency_workorder_id = Column(Integer, ForeignKey("workorders.id"), nullable=True)

    # Linked procurement work order created after approval
    procurement_workorder_id = Column(Integer, ForeignKey("workorders.id"), nullable=True)

    status = Column(Enum(ProcurementRequestStatus), default=ProcurementRequestStatus.pending)
    created_by_role = Column(Enum(RoleEnum), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    decided_at = Column(DateTime, nullable=True)


# relationship from ProcurementRequest to its procurement WorkOrder
ProcurementRequest.procurement_workorder = relationship(
    "WorkOrder",
    foreign_keys=[ProcurementRequest.procurement_workorder_id],
)

Base.metadata.create_all(bind=engine)


# ------------------ Pydantic Schemas ------------------ #

class UserLogin(BaseModel):
    username: str
    password: str


class WorkOrderCreate(BaseModel):
    title: str
    description: str | None = None
    assigned_role: RoleEnum
    vendor_id: int | None = None
    quantity: int = 1
    unit: str = "Count"


class WorkOrderUpdateStatus(BaseModel):
    status: WorkOrderStatus


class InventoryUpdate(BaseModel):
    item_id: int
    quantity: int


# ------------------ FASTAPI APP INIT ------------------ #

app = FastAPI(title="Factory Work Management")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# ------------------ ID GENERATION ------------------ #

def generate_display_id(source: str, role: RoleEnum | None = None) -> str:
    """
    Create IDs like MGMT221120251912, FTRY221120251912, REQ221120251912.
    source examples: "dashboard", "role", "api", "request".
    """
    now = datetime.now()
    ts = now.strftime("%d%m%Y%H%M")

    if source == "dashboard":
        prefix = "MGMT"
    elif source == "request":
        prefix = "REQ"
    else:
        if role == RoleEnum.manufacturing:
            prefix = "FTRY"
        elif role == RoleEnum.procurement:
            prefix = "PROC"
        elif role == RoleEnum.qa:
            prefix = "QUAL"
        elif role == RoleEnum.packaging:
            prefix = "PACK"
        elif role == RoleEnum.inventory:
            prefix = "INVN"
        elif role == RoleEnum.management:
            prefix = "MGMT"
        else:
            prefix = "TASK"

    return f"{prefix}{ts}"


# ------------------ ROLE-SPECIFIC STATUS OPTIONS ------------------ #

def get_status_options_for_role(role: RoleEnum):
    """Return department-specific status options."""
    if role == RoleEnum.qa:
        return [
            ("new", "New"),
            ("testing", "Testing"),
            ("completed", "Passed"),
            ("failed", "Failed"),
        ]
    elif role == RoleEnum.packaging:
        return [
            ("new", "New"),
            ("packing", "Packing"),
            ("packed", "Packed"),
        ]
    elif role == RoleEnum.inventory:
        return [
            ("new", "Received"),
            ("on_shelf", "On Shelf"),
            ("shipped", "Shipped"),
            ("expired", "Expired"),
        ]
    else:
        # Default for procurement, manufacturing
        return [
            ("new", "New"),
            ("in_progress", "In Progress"),
            ("blocked", "Blocked"),
            ("completed", "Completed"),
            ("rejected", "Rejected"),
        ]


# ---- Jinja filter to show enums nicely ---- #

def pretty_enum(value):
    if isinstance(value, enum.Enum):
        raw = value.value
    else:
        raw = str(value)

    raw_lower = raw.lower()

    role_labels = {
        "procurement": "Procurement",
        "manufacturing": "Manufacturing",
        "qa": "Quality Assurance",
        "packaging": "Packaging",
        "inventory": "Inventory",
        "management": "Management",
    }

    status_labels = {
        "new": "New",
        "in_progress": "In Progress",
        "waiting_qc": "Waiting QC",
        "completed": "Completed",
        "rejected": "Rejected",
        "testing": "Testing",
        "failed": "Failed",
        "packing": "Packing",
        "packed": "Packed",
        "on_shelf": "On Shelf",
        "shipped": "Shipped",
        "expired": "Expired",
        "blocked": "Blocked",
    }

    if raw_lower in role_labels:
        return role_labels[raw_lower]
    if raw_lower in status_labels:
        return status_labels[raw_lower]

    return raw.replace("_", " ").title()


templates.env.filters["pretty"] = pretty_enum


# ------------------ DB DEPENDENCY ------------------ #

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ------------------ SIMPLE AUTH (for API) ------------------ #

def authenticate_user(db: Session, username: str, password: str):
    return db.query(User).filter(User.username == username, User.password == password).first()


def seed_users():
    db = SessionLocal()
    if db.query(User).count() == 0:
        demo_users = [
            ("proc1", "1234", RoleEnum.procurement),
            ("manuf1", "1234", RoleEnum.manufacturing),
            ("qa1", "1234", RoleEnum.qa),
            ("pack1", "1234", RoleEnum.packaging),
            ("inv1", "1234", RoleEnum.inventory),
            ("mgr1", "1234", RoleEnum.management),
        ]
        for u, p, r in demo_users:
            db.add(User(username=u, password=p, role=r))
        db.commit()
    db.close()


seed_users()


# ------------------ HELPER: STAGE PROGRESSION ------------------ #

def is_completion_for_role(role: RoleEnum, status: WorkOrderStatus) -> bool:
    if role == RoleEnum.procurement and status == WorkOrderStatus.completed:
        return True
    if role == RoleEnum.manufacturing and status == WorkOrderStatus.completed:
        return True
    if role == RoleEnum.qa and status == WorkOrderStatus.completed:
        return True
    if role == RoleEnum.packaging and status == WorkOrderStatus.packed:
        return True
    return False


def apply_stage_progression(wo: WorkOrder, new_status: WorkOrderStatus):
    """
    Automatic flow with department-specific completion statuses.
    """
    wo.status = new_status

    if not is_completion_for_role(wo.assigned_role, new_status):
        return

    if wo.assigned_role == RoleEnum.procurement:
        wo.assigned_role = RoleEnum.manufacturing
        wo.status = WorkOrderStatus.new
    elif wo.assigned_role == RoleEnum.manufacturing:
        wo.assigned_role = RoleEnum.qa
        wo.status = WorkOrderStatus.new
    elif wo.assigned_role == RoleEnum.qa:
        wo.assigned_role = RoleEnum.packaging
        wo.status = WorkOrderStatus.new
    elif wo.assigned_role == RoleEnum.packaging:
        wo.assigned_role = RoleEnum.inventory
        wo.status = WorkOrderStatus.new


# ------------------ API ENDPOINTS (for Android & integrations) ------------------ #

@app.post("/api/login")
def api_login(credentials: UserLogin, db: Session = Depends(get_db)):
    user = authenticate_user(db, credentials.username, credentials.password)
    if not user:
        return {"success": False, "message": "Invalid credentials"}
    return {
        "success": True,
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role
        }
    }


@app.get("/api/workorders")
def api_list_workorders(role: RoleEnum | None = None, db: Session = Depends(get_db)):
    q = db.query(WorkOrder)
    if role:
        q = q.filter(WorkOrder.assigned_role == role)
    orders = q.order_by(WorkOrder.created_at.desc()).all()
    return orders


@app.post("/api/workorders")
def api_create_workorder(order: WorkOrderCreate, db: Session = Depends(get_db)):
    wo = WorkOrder(
        display_id=generate_display_id("role", order.assigned_role),
        title=order.title,
        description=order.description,
        assigned_role=order.assigned_role,
        status=WorkOrderStatus.new,
        vendor_id=order.vendor_id,
        quantity=max(1, order.quantity),
        unit=order.unit or "Count",
    )
    db.add(wo)
    db.commit()
    db.refresh(wo)
    return wo


@app.patch("/api/workorders/{order_id}/status")
def api_update_workorder_status(order_id: int, status_update: WorkOrderUpdateStatus,
                                db: Session = Depends(get_db)):
    wo = db.query(WorkOrder).filter(WorkOrder.id == order_id).first()
    if not wo:
        return {"success": False, "message": "WorkOrder not found"}

    apply_stage_progression(wo, status_update.status)
    wo.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(wo)
    return {"success": True, "workorder": wo}


@app.get("/api/inventory")
def api_list_inventory(db: Session = Depends(get_db)):
    items = db.query(InventoryItem).all()
    return items


@app.post("/api/inventory/update")
def api_update_inventory(update: InventoryUpdate, db: Session = Depends(get_db)):
    item = db.query(InventoryItem).filter(InventoryItem.id == update.item_id).first()
    if not item:
        return {"success": False, "message": "Item not found"}
    item.quantity = update.quantity
    db.commit()
    return {"success": True}


# ------------------ WEB PAGES (Dashboard + Role Views) ------------------ #

@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    status: str | None = Query(default=None),
    db: Session = Depends(get_db)
):
    total = db.query(WorkOrder).count()
    new = db.query(WorkOrder).filter(WorkOrder.status == WorkOrderStatus.new).count()
    in_progress = db.query(WorkOrder).filter(WorkOrder.status == WorkOrderStatus.in_progress).count()
    waiting_qc = db.query(WorkOrder).filter(WorkOrder.status == WorkOrderStatus.waiting_qc).count()
    blocked = db.query(WorkOrder).filter(WorkOrder.status == WorkOrderStatus.blocked).count()
    completed = db.query(WorkOrder).filter(WorkOrder.status == WorkOrderStatus.completed).count()
    rejected = db.query(WorkOrder).filter(WorkOrder.status == WorkOrderStatus.rejected).count()

    selected_status = None
    if status:
        try:
            selected_status = WorkOrderStatus(status)
        except ValueError:
            selected_status = None

    q = db.query(WorkOrder).order_by(WorkOrder.created_at.desc())
    if selected_status:
        q = q.filter(WorkOrder.status == selected_status)
    orders = q.limit(50).all()

    vendors = db.query(Vendor).filter(Vendor.is_active == True).order_by(Vendor.name).all()

    pending_reqs = (
        db.query(ProcurementRequest)
        .filter(ProcurementRequest.status == ProcurementRequestStatus.pending)
        .order_by(ProcurementRequest.created_at.desc())
        .all()
    )

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "stats": {
            "total": total,
            "new": new,
            "in_progress": in_progress,
            "waiting_qc": waiting_qc,
            "blocked": blocked,
            "completed": completed,
            "rejected": rejected,
        },
        "orders": orders,
        "selected_status": selected_status,
        "vendors": vendors,
        "pending_reqs": pending_reqs,
    })


@app.post("/create-order")
def create_order_web(
    title: str = Form(...),
    description: str = Form(""),
    assigned_role: RoleEnum = Form(...),
    vendor_id: int | None = Form(default=None),
    quantity: int = Form(default=1),
    unit: str = Form(default="Count"),
    db: Session = Depends(get_db),
):
    if vendor_id == 0:
        vendor_id = None
    qty = max(1, quantity)
    wo = WorkOrder(
        display_id=generate_display_id("dashboard"),
        title=title,
        description=description,
        assigned_role=assigned_role,
        status=WorkOrderStatus.new,
        vendor_id=vendor_id,
        quantity=qty,
        unit=unit or "Count",
    )
    db.add(wo)
    db.commit()
    return RedirectResponse(url="/", status_code=303)


# -------- Manufacturing Procurement Requests (WEB) -------- #

@app.post("/procurement-request")
def create_procurement_request(
    title: str = Form(...),
    description: str = Form(""),
    quantity: int = Form(1),
    unit: str = Form("Count"),
    dependency_workorder_id: int = Form(0),
    db: Session = Depends(get_db),
):
    qty = max(1, quantity)
    unit_norm = unit or "Count"
    dep_id = dependency_workorder_id if dependency_workorder_id > 0 else None

    req = ProcurementRequest(
        display_id=generate_display_id("request", RoleEnum.manufacturing),
        title=title,
        description=description,
        quantity=qty,
        unit=unit_norm,
        dependency_workorder_id=dep_id,
        created_by_role=RoleEnum.manufacturing,
        status=ProcurementRequestStatus.pending,
    )
    db.add(req)
    db.commit()
    return RedirectResponse(url="/role/manufacturing", status_code=303)


@app.post("/procurement-request/{req_id}/approve")
def approve_procurement_request(
    req_id: int,
    vendor_id: int = Form(default=0),
    db: Session = Depends(get_db),
):
    req = db.query(ProcurementRequest).filter(ProcurementRequest.id == req_id).first()
    if req and req.status == ProcurementRequestStatus.pending:
        req.status = ProcurementRequestStatus.approved
        req.decided_at = datetime.utcnow()

        if vendor_id == 0:
            vendor_id = None

        desc = req.description or ""
        if req.quantity and req.unit:
            detail = f"Requested: {req.quantity} {req.unit}"
            desc = f"{desc} ({detail})" if desc else detail

        wo = WorkOrder(
            display_id=generate_display_id("dashboard"),  # created via dashboard approval
            title=req.title,
            description=desc,
            assigned_role=RoleEnum.procurement,
            status=WorkOrderStatus.new,
            vendor_id=vendor_id,
            quantity=req.quantity or 1,
            unit=req.unit or "Count",
        )
        db.add(wo)
        db.flush()  # to get wo.id and wo.display_id

        # Link this request to its procurement work order
        req.procurement_workorder_id = wo.id

        # If there is a dependency task, mark it blocked with reason
        if req.dependency_workorder_id:
            dep_wo = db.query(WorkOrder).filter(
                WorkOrder.id == req.dependency_workorder_id
            ).first()
            if dep_wo:
                dep_wo.status = WorkOrderStatus.blocked
                blocked_reason = f"Waiting for procurement task {wo.display_id}"
                if dep_wo.description:
                    dep_wo.description += f" | {blocked_reason}"
                else:
                    dep_wo.description = blocked_reason

        db.commit()
    return RedirectResponse(url="/", status_code=303)


@app.post("/procurement-request/{req_id}/reject")
def reject_procurement_request(req_id: int, db: Session = Depends(get_db)):
    req = db.query(ProcurementRequest).filter(ProcurementRequest.id == req_id).first()
    if req and req.status == ProcurementRequestStatus.pending:
        req.status = ProcurementRequestStatus.rejected
        req.decided_at = datetime.utcnow()
        db.commit()
    return RedirectResponse(url="/", status_code=303)


# -------- Vendors (WEB) with password-protected page -------- #

VENDOR_PASSWORD = "Mrudu"
VENDOR_COOKIE_NAME = "vendor_auth"
VENDOR_COOKIE_MAX_AGE = 30 * 60  # 30 minutes


@app.get("/vendors", response_class=HTMLResponse)
def vendor_page(
    request: Request,
    vendor_auth: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
):
    if vendor_auth != "ok":
        return templates.TemplateResponse("vendor_login.html", {
            "request": request,
            "error": None
        })

    vendors = db.query(Vendor).filter(Vendor.is_active == True).order_by(Vendor.name).all()
    return templates.TemplateResponse("vendor_list.html", {
        "request": request,
        "vendors": vendors,
    })


@app.post("/vendors/login")
def vendor_login(
    request: Request,
    response: Response,
    password: str = Form(...),
):
    if password == VENDOR_PASSWORD:
        resp = RedirectResponse(url="/vendors", status_code=303)
        resp.set_cookie(
            VENDOR_COOKIE_NAME,
            "ok",
            httponly=True,
            max_age=VENDOR_COOKIE_MAX_AGE,
        )
        return resp

    return templates.TemplateResponse("vendor_login.html", {
        "request": request,
        "error": "Incorrect password",
    })


@app.post("/create-vendor")
def create_vendor(
    name: str = Form(...),
    contact_person: str = Form(""),
    phone: str = Form(""),
    email: str = Form(""),
    address: str = Form(""),
    vendor_auth: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
):
    if vendor_auth != "ok":
        return RedirectResponse(url="/vendors", status_code=303)

    vendor = Vendor(
        name=name,
        contact_person=contact_person or None,
        phone=phone or None,
        email=email or None,
        address=address or None,
        is_active=True,
    )
    db.add(vendor)
    db.commit()
    return RedirectResponse(url="/vendors", status_code=303)


# -------- ROLE PAGES (procurement, manufacturing, QA, packaging, inventory) -------- #

@app.get("/role/{role}", response_class=HTMLResponse)
def role_view(role: RoleEnum, request: Request, db: Session = Depends(get_db)):
    orders = (
        db.query(WorkOrder)
        .filter(WorkOrder.assigned_role == role)
        .order_by(WorkOrder.created_at.desc())
        .all()
    )

    manufacturing_reqs = []
    if role == RoleEnum.manufacturing:
        manufacturing_reqs = (
            db.query(ProcurementRequest)
            .filter(ProcurementRequest.created_by_role == RoleEnum.manufacturing)
            .order_by(ProcurementRequest.created_at.desc())
            .all()
        )

    status_options = get_status_options_for_role(role)

    return templates.TemplateResponse("role_view.html", {
        "request": request,
        "role": role,
        "orders": orders,
        "manufacturing_reqs": manufacturing_reqs,
        "status_options": status_options,
    })


@app.post("/role/{role}/update-status")
def role_update_status(
    role: RoleEnum,
    order_id: int = Form(...),
    status: WorkOrderStatus = Form(...),
    qty_done: str = Form(default=""),
    db: Session = Depends(get_db),
):
    wo = db.query(WorkOrder).filter(WorkOrder.id == order_id).first()
    if not wo:
        return RedirectResponse(url=f"/role/{role.value}", status_code=303)

    total = wo.quantity or 1

    is_complete = is_completion_for_role(role, status)

    if is_complete:
        try:
            parsed_qty = int(qty_done.strip()) if qty_done.strip() != "" else total
        except ValueError:
            parsed_qty = total

        if parsed_qty <= 0 or parsed_qty > total:
            parsed_qty = total

        qty_done_int = parsed_qty
        remaining = total - qty_done_int

        if remaining > 0:
            remaining_wo = WorkOrder(
                display_id=generate_display_id("role", wo.assigned_role),
                title=wo.title,
                description=wo.description,
                assigned_role=wo.assigned_role,
                status=WorkOrderStatus.new,
                vendor_id=wo.vendor_id,
                quantity=remaining,
                unit=wo.unit,
            )
            db.add(remaining_wo)

        wo.quantity = qty_done_int
        apply_stage_progression(wo, status)
        wo.updated_at = datetime.utcnow()
        db.commit()
    else:
        apply_stage_progression(wo, status)
        wo.updated_at = datetime.utcnow()
        db.commit()

    return RedirectResponse(url=f"/role/{role.value}", status_code=303)


@app.post("/role/{role}/delete-order")
def delete_order(
    role: RoleEnum,
    order_id: int = Form(...),
    db: Session = Depends(get_db),
):
    wo = db.query(WorkOrder).filter(WorkOrder.id == order_id).first()
    if wo:
        db.delete(wo)
        db.commit()
    return RedirectResponse(url=f"/role/{role.value}", status_code=303)
