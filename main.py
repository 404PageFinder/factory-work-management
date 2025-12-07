from fastapi import (
    FastAPI,
    Depends,
    Request,
    Form,
    Query,
    Response,
    Cookie,
    UploadFile,
    File,
    HTTPException,
    status,
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
    Text,
    Float,
)
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
from datetime import datetime, timedelta
import enum
from pydantic import BaseModel
import csv
import io
from typing import Optional
import hashlib
import secrets

# ------------------ DATABASE SETUP ------------------ #

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Use DATABASE_URL from environment (Vercel / local export)
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./factory.db"  # fallback if env not set
)

# For Postgres, no special connect_args needed
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

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
    new = "new"
    in_progress = "in_progress"
    procured = "procured"  # NEW: For procurement items
    waiting_qc = "waiting_qc"
    completed = "completed"
    rejected = "rejected"
    testing = "testing"
    failed = "failed"
    packing = "packing"
    packed = "packed"
    on_shelf = "on_shelf"
    shipped = "shipped"
    expired = "expired"
    blocked = "blocked"


class OrderType(str, enum.Enum):
    bulk = "bulk"
    instant = "instant"


class OrderCategory(str, enum.Enum):
    new = "new"  # New order with title/description
    existing = "existing"  # Existing order using recipe


class ItemType(str, enum.Enum):
    raw = "raw"  # Raw materials (from procurement/manufacturing requests)
    delivery = "delivery"  # Delivery items (from packaging)
    packaging = "packaging"  # Packaging materials


class ProcurementOrderType(str, enum.Enum):
    raw_material = "raw_material"
    packaging = "packaging"


class PackagingType(str, enum.Enum):
    cardboard_boxes = "Cardboard boxes"
    tubs = "Tubs"
    pouches = "Pouches"


class ProcurementRequestStatus(str, enum.Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
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


class Recipe(Base):
    __tablename__ = "recipes"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)
    description = Column(Text, nullable=True)
    ingredients = Column(Text, nullable=True)
    instructions = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class WorkOrder(Base):
    __tablename__ = "workorders"
    id = Column(Integer, primary_key=True, index=True)
    display_id = Column(String, index=True, nullable=True)
    title = Column(String, nullable=True)  # Nullable for existing orders
    description = Column(String, nullable=True)
    status = Column(Enum(WorkOrderStatus), default=WorkOrderStatus.new)
    blocked_reason = Column(Text, nullable=True)
    order_type = Column(Enum(OrderType), default=OrderType.instant)
    order_category = Column(Enum(OrderCategory), default=OrderCategory.existing)
    item_type = Column(Enum(ItemType), default=ItemType.delivery)
    recipe_id = Column(Integer, ForeignKey("recipes.id"), nullable=True)
    packaging_size_gm = Column(Float, nullable=True)  # NEW: Packaging size in grams
    # NEW: Procurement order type and packaging details
    procurement_order_type = Column(String, nullable=True)  # "raw_material" or "packaging"
    packaging_type = Column(String, nullable=True)  # "Cardboard boxes", "Tubs", "Pouches"
    packaging_size = Column(String, nullable=True)  # e.g., "24 tubs", "65gms", "1kg"
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    assigned_role = Column(Enum(RoleEnum), nullable=False)
    vendor_id = Column(Integer, ForeignKey("vendors.id"), nullable=True)
    quantity = Column(Integer, default=1)
    unit = Column(String, default="Count")

    vendor = relationship("Vendor", back_populates="workorders")
    recipe = relationship("Recipe")


class InventoryItem(Base):
    __tablename__ = "inventory_items"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    quantity = Column(Integer, default=0)
    unit = Column(String, default="pcs")


class ProcurementRequest(Base):
    __tablename__ = "procurement_requests"
    id = Column(Integer, primary_key=True, index=True)
    display_id = Column(String, index=True, nullable=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    quantity = Column(Integer, default=1)
    unit = Column(String, default="Count")
    dependency_workorder_id = Column(Integer, ForeignKey("workorders.id"), nullable=True)
    procurement_workorder_id = Column(Integer, ForeignKey("workorders.id"), nullable=True)
    status = Column(Enum(ProcurementRequestStatus), default=ProcurementRequestStatus.pending)
    created_by_role = Column(Enum(RoleEnum), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    decided_at = Column(DateTime, nullable=True)


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
    title: str | None = None
    description: str | None = None
    assigned_role: RoleEnum
    vendor_id: int | None = None
    quantity: int = 1
    unit: str = "Count"
    order_type: OrderType = OrderType.instant
    order_category: OrderCategory = OrderCategory.existing
    recipe_id: int | None = None
    packaging_size_gm: float | None = None


class WorkOrderUpdateStatus(BaseModel):
    status: WorkOrderStatus
    blocked_reason: str | None = None


# ------------------ FASTAPI APP INIT ------------------ #

app = FastAPI(title="Factory Work Management")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# ------------------ AUTHENTICATION ------------------ #

# Store active sessions in memory (in production, use Redis or database)
active_sessions = {}

def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return hash_password(plain_password) == hashed_password

def create_session_token() -> str:
    """Generate a secure random session token"""
    return secrets.token_urlsafe(32)

def get_current_user(
    session_token: Optional[str] = Cookie(None, alias="session_token"),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Get current logged-in user from session token"""
    if not session_token or session_token not in active_sessions:
        return None
    
    user_id = active_sessions[session_token]
    user = db.query(User).filter(User.id == user_id).first()
    return user

def require_auth(
    session_token: Optional[str] = Cookie(None, alias="session_token"),
    db: Session = Depends(get_db)
) -> User:
    """Require authentication - redirect to login if not authenticated"""
    user = get_current_user(session_token, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"}
        )
    return user

def init_default_users(db: Session):
    """Initialize default users if they don't exist"""
    default_users = [
        {"username": "mgr1", "password": "1234", "role": RoleEnum.management},
        {"username": "proc1", "password": "1234", "role": RoleEnum.procurement},
        {"username": "manuf1", "password": "1234", "role": RoleEnum.manufacturing},
        {"username": "qa1", "password": "1234", "role": RoleEnum.qa},
        {"username": "pack1", "password": "1234", "role": RoleEnum.packaging},
        {"username": "inv1", "password": "1234", "role": RoleEnum.inventory},
    ]
    
    for user_data in default_users:
        existing_user = db.query(User).filter(User.username == user_data["username"]).first()
        if not existing_user:
            new_user = User(
                username=user_data["username"],
                password=hash_password(user_data["password"]),
                role=user_data["role"]
            )
            db.add(new_user)
    
    db.commit()

# Initialize default users on startup
@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    try:
        init_default_users(db)
    finally:
        db.close()


# ------------------ ID GENERATION ------------------ #

def generate_display_id(source: str, role: RoleEnum | None = None) -> str:
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


# ------------------ STATUS OPTIONS ------------------ #

def get_next_status_buttons(role: RoleEnum, current_status: WorkOrderStatus):
    """Return next status button options for the role"""
    if role == RoleEnum.procurement:
        if current_status == WorkOrderStatus.new:
            return [("in_progress", "Start Work", "warning")]
        elif current_status == WorkOrderStatus.in_progress:
            return [("procured", "Mark Procured", "success"), ("rejected", "Mark Rejected", "danger")]
        elif current_status in [WorkOrderStatus.procured, WorkOrderStatus.rejected]:
            return []
    
    elif role == RoleEnum.qa:
        if current_status == WorkOrderStatus.new:
            return [("testing", "Start Testing", "warning")]
        elif current_status == WorkOrderStatus.testing:
            return [("completed", "Mark Passed", "success"), ("failed", "Mark Failed", "danger")]
        elif current_status in [WorkOrderStatus.completed, WorkOrderStatus.failed]:
            return []
    
    elif role == RoleEnum.packaging:
        if current_status == WorkOrderStatus.new:
            return [("packing", "Start Packing", "warning")]
        elif current_status == WorkOrderStatus.packing:
            return [("packed", "Mark Packed", "success")]
        elif current_status == WorkOrderStatus.packed:
            return []
    
    elif role == RoleEnum.inventory:
        if current_status == WorkOrderStatus.new:
            return [("on_shelf", "Place on Shelf", "info")]
        elif current_status == WorkOrderStatus.on_shelf:
            return [("shipped", "Mark Shipped", "success"), ("expired", "Mark Expired", "danger")]
        elif current_status in [WorkOrderStatus.shipped, WorkOrderStatus.expired]:
            return []
    
    else:  # manufacturing
        if current_status == WorkOrderStatus.new:
            return [("in_progress", "Start Work", "warning")]
        elif current_status == WorkOrderStatus.in_progress:
            return [("completed", "Mark Completed", "success"), ("rejected", "Mark Rejected", "danger")]
        elif current_status in [WorkOrderStatus.completed, WorkOrderStatus.rejected]:
            return []
    
    return []


# ---- Jinja filter ---- #

def pretty_enum(value):
    if isinstance(value, enum.Enum):
        raw = value.value
    else:
        raw = str(value)

    raw_lower = raw.lower()

    labels = {
        "procurement": "Procurement",
        "manufacturing": "Manufacturing",
        "qa": "Quality Assurance",
        "packaging": "Packaging",
        "inventory": "Inventory",
        "management": "Management",
        "new": "New",
        "in_progress": "In Progress",
        "procured": "Procured",
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
        "bulk": "Bulk",
        "instant": "Instant",
        "existing": "Existing",
        "raw": "Raw Material",
        "delivery": "Delivery Item",
    }

    return labels.get(raw_lower, raw.replace("_", " ").title())


templates.env.filters["pretty"] = pretty_enum


# ------------------ DB DEPENDENCY ------------------ #

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ------------------ AUTH ------------------ #

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


# ------------------ STAGE PROGRESSION ------------------ #

def is_completion_for_role(role: RoleEnum, status: WorkOrderStatus) -> bool:
    if role == RoleEnum.procurement and status == WorkOrderStatus.procured:
        return True
    if role == RoleEnum.manufacturing and status == WorkOrderStatus.completed:
        return True
    if role == RoleEnum.qa and status == WorkOrderStatus.completed:
        return True
    if role == RoleEnum.packaging and status == WorkOrderStatus.packed:
        return True
    return False


def apply_stage_progression(wo: WorkOrder, new_status: WorkOrderStatus):
    """Updated workflow: Procurement -> Inventory (raw), Manufacturing -> QA -> Packaging -> Inventory (delivery)"""
    wo.status = new_status

    if not is_completion_for_role(wo.assigned_role, new_status):
        return

    if wo.assigned_role == RoleEnum.procurement:
        # Procurement items go directly to Inventory as raw materials
        wo.assigned_role = RoleEnum.inventory
        wo.status = WorkOrderStatus.new
        wo.item_type = ItemType.raw
    elif wo.assigned_role == RoleEnum.manufacturing:
        # Manufacturing items are raw materials, go to QA
        wo.assigned_role = RoleEnum.qa
        wo.status = WorkOrderStatus.new
        wo.item_type = ItemType.raw
    elif wo.assigned_role == RoleEnum.qa:
        wo.assigned_role = RoleEnum.packaging
        wo.status = WorkOrderStatus.new
    elif wo.assigned_role == RoleEnum.packaging:
        # Packaging items become delivery items
        wo.assigned_role = RoleEnum.inventory
        wo.status = WorkOrderStatus.new
        wo.item_type = ItemType.delivery


# ------------------ API ENDPOINTS ------------------ #

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


# ------------------ AUTHENTICATION ROUTES ------------------ #

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str = None):
    """Display login page"""
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error
    })

@app.post("/login")
def login(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Process login"""
    # Find user
    user = db.query(User).filter(User.username == username).first()
    
    if not user or not verify_password(password, user.password):
        # Redirect back to login with error
        return RedirectResponse(
            url="/login?error=Invalid username or password",
            status_code=303
        )
    
    # Create session
    session_token = create_session_token()
    active_sessions[session_token] = user.id
    
    # Determine redirect URL based on role
    if user.role == RoleEnum.management:
        redirect_url = "/"  # Dashboard for management
    else:
        redirect_url = f"/role/{user.role.value}"  # Role-specific page
    
    # Set cookie and redirect
    response = RedirectResponse(url=redirect_url, status_code=303)
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        max_age=86400,  # 24 hours
        samesite="lax"
    )
    
    return response

@app.get("/logout")
def logout(
    session_token: Optional[str] = Cookie(None, alias="session_token")
):
    """Logout user"""
    # Remove session
    if session_token and session_token in active_sessions:
        del active_sessions[session_token]
    
    # Redirect to login
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("session_token")
    
    return response


# ------------------ WEB PAGES ------------------ #

@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    status: str | None = Query(default=None),
    current_user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    total = db.query(WorkOrder).count()
    new = db.query(WorkOrder).filter(WorkOrder.status == WorkOrderStatus.new).count()
    in_progress = db.query(WorkOrder).filter(WorkOrder.status == WorkOrderStatus.in_progress).count()
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
    recipes = db.query(Recipe).order_by(Recipe.name).all()

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
            "blocked": blocked,
            "completed": completed,
            "rejected": rejected,
        },
        "orders": orders,
        "selected_status": selected_status,
        "vendors": vendors,
        "recipes": recipes,
        "pending_reqs": pending_reqs,
    })


@app.post("/create-order")
def create_order_web(
    order_category: OrderCategory = Form(...),
    title: str = Form(default=""),
    description: str = Form(default=""),
    assigned_role: RoleEnum = Form(...),
    vendor_id: int | None = Form(default=None),
    quantity: int = Form(default=1),
    unit: str = Form(default="Count"),
    order_type: OrderType = Form(default=OrderType.instant),
    recipe_id: int | None = Form(default=None),
    packaging_size_gm: float = Form(default=50),
    # NEW: Procurement order type and packaging fields
    procurement_order_type: str = Form(default="raw_material"),
    packaging_type: str = Form(default=""),
    packaging_size: str = Form(default=""),
    db: Session = Depends(get_db),
):
    if vendor_id == 0:
        vendor_id = None
    if recipe_id == 0:
        recipe_id = None
    
    qty = max(1, quantity)
    
    # For existing orders, generate title from recipe if available
    final_title = title
    if order_category == OrderCategory.existing and recipe_id:
        recipe = db.query(Recipe).filter(Recipe.id == recipe_id).first()
        if recipe:
            final_title = recipe.name
    
    # For packaging procurement orders, set title
    if assigned_role == RoleEnum.procurement and procurement_order_type == "packaging":
        if not final_title or final_title == "":
            final_title = f"{packaging_type} - {packaging_size}"
    
    # Determine item_type based on assigned_role and procurement_order_type
    determined_item_type = ItemType.delivery  # Default
    if assigned_role == RoleEnum.procurement:
        if procurement_order_type == "packaging":
            determined_item_type = ItemType.packaging
        else:
            determined_item_type = ItemType.raw
    
    wo = WorkOrder(
        display_id=generate_display_id("dashboard"),
        title=final_title if final_title else "Untitled Order",
        description=description,
        assigned_role=assigned_role,
        status=WorkOrderStatus.new,
        vendor_id=vendor_id,
        quantity=qty,
        unit=unit or "Count",
        order_type=order_type,
        order_category=order_category,
        recipe_id=recipe_id,
        packaging_size_gm=packaging_size_gm,
        item_type=determined_item_type,
        procurement_order_type=procurement_order_type if assigned_role == RoleEnum.procurement else None,
        packaging_type=packaging_type if packaging_type else None,
        packaging_size=packaging_size if packaging_size else None,
    )
    db.add(wo)
    db.commit()
    return RedirectResponse(url="/", status_code=303)


# -------- Procurement Requests -------- #

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
            display_id=generate_display_id("dashboard"),
            title=req.title,
            description=desc,
            assigned_role=RoleEnum.procurement,
            status=WorkOrderStatus.new,
            vendor_id=vendor_id,
            quantity=req.quantity or 1,
            unit=req.unit or "Count",
            item_type=ItemType.raw,  # Procurement items are raw materials
        )
        db.add(wo)
        db.flush()

        req.procurement_workorder_id = wo.id

        if req.dependency_workorder_id:
            dep_wo = db.query(WorkOrder).filter(
                WorkOrder.id == req.dependency_workorder_id
            ).first()
            if dep_wo:
                dep_wo.status = WorkOrderStatus.blocked
                dep_wo.blocked_reason = f"Waiting for procurement task {wo.display_id}"

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


# -------- Vendors -------- #

VENDOR_PASSWORD = "Mrudu"
VENDOR_COOKIE_NAME = "vendor_auth"
VENDOR_COOKIE_MAX_AGE = 30 * 60


@app.get("/vendors", response_class=HTMLResponse)
def vendor_page(
    request: Request,
    current_user: User = Depends(require_auth),
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


# -------- Recipes -------- #

@app.get("/recipes", response_class=HTMLResponse)
def recipe_list(
    request: Request, 
    current_user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    recipes = db.query(Recipe).order_by(Recipe.name).all()
    return templates.TemplateResponse("recipe_list.html", {
        "request": request,
        "recipes": recipes,
    })


@app.post("/create-recipe")
def create_recipe(
    name: str = Form(...),
    description: str = Form(""),
    ingredients: str = Form(""),
    instructions: str = Form(""),
    db: Session = Depends(get_db),
):
    recipe = Recipe(
        name=name,
        description=description or None,
        ingredients=ingredients or None,
        instructions=instructions or None,
    )
    db.add(recipe)
    db.commit()
    return RedirectResponse(url="/recipes", status_code=303)


@app.post("/delete-recipe/{recipe_id}")
def delete_recipe(recipe_id: int, db: Session = Depends(get_db)):
    recipe = db.query(Recipe).filter(Recipe.id == recipe_id).first()
    if recipe:
        db.delete(recipe)
        db.commit()
    return RedirectResponse(url="/recipes", status_code=303)
    
# -------- Help -------- #

@app.get("/help/{page}", response_class=HTMLResponse)
def help_page(page: str, request: Request):
    """Dynamic help page based on current page context"""
    
    help_data = {
        "dashboard": {
            "title": "Dashboard Help",
            "icon": "📊",
            "sections": [
                {
                    "title": "Work Order Metrics",
                    "content": "These metric cards show you the status of all work orders at a glance. Click any metric to filter the work orders table below.",
                    "tips": [
                        "All Orders: Total number of orders in the system",
                        "New: Orders that haven't been started yet",
                        "In Progress: Currently being worked on",
                        "Blocked: Orders waiting for dependencies",
                        "Completed: Successfully finished orders",
                        "Rejected: Orders that didn't meet criteria"
                    ]
                },
                {
                    "title": "Create Work Order",
                    "content": "Use this form to create new work orders for any department.",
                    "tips": [
                        "Order Category: Choose 'Existing' for recipe-based orders or 'New' for custom orders",
                        "Order Type: Select 'Instant' for urgent orders or 'Bulk' for larger batches",
                        "Packaging Size: Set the package size in grams (10-1000 gm, steps of 5)",
                        "Assign To: Choose which department should handle this order"
                    ]
                },
                {
                    "title": "Procurement Requests",
                    "content": "Manufacturing can raise procurement requests when raw materials are needed. Management reviews and approves/rejects these requests.",
                    "tips": []
                }
            ]
        },
        "procurement": {
            "title": "Procurement Help",
            "icon": "🛒",
            "sections": [
                {
                    "title": "Procurement Workflow",
                    "content": "Procurement handles sourcing raw materials from vendors. Items go directly to Inventory as raw materials when marked as 'Procured'.",
                    "tips": [
                        "New: Order received, ready to start",
                        "In Progress: Actively sourcing materials",
                        "Procured: Materials acquired, moves to Inventory (Raw Materials)",
                        "Rejected: Order couldn't be fulfilled"
                    ]
                },
                {
                    "title": "Working with Vendors",
                    "content": "Each procurement order can be assigned to a specific vendor for tracking purposes.",
                    "tips": [
                        "Select vendor when creating the order or during processing",
                        "Vendor information helps track supplier performance",
                        "Manage vendors through the 'Manage Vendors' navigation link"
                    ]
                },
                {
                    "title": "Status Actions",
                    "content": "Use the action buttons to update order status:",
                    "tips": [
                        "'Start Work' (orange) - Begin procurement process",
                        "'Mark Procured' (green) - Materials acquired, sends to Inventory",
                        "'Mark Rejected' (red) - Order cannot be fulfilled",
                        "'Block' (red) - Temporarily halt order with reason"
                    ]
                }
            ]
        },
        "manufacturing": {
            "title": "Manufacturing Help",
            "icon": "⚙️",
            "sections": [
                {
                    "title": "Manufacturing Workflow",
                    "content": "Manufacturing produces raw material items that need QA testing. Completed items move to Quality Assurance.",
                    "tips": [
                        "New: Order received, ready to manufacture",
                        "In Progress: Currently in production",
                        "Completed: Production finished, moves to QA",
                        "Rejected: Production failed or cancelled"
                    ]
                },
                {
                    "title": "Using Recipes",
                    "content": "Manufacturing orders can be linked to recipes from the Recipe Bank for standardized production.",
                    "tips": [
                        "Existing orders automatically use recipe specifications",
                        "View recipe details in the Recipe Bank",
                        "Follow recipe instructions for consistent quality"
                    ]
                },
                {
                    "title": "Procurement Requests",
                    "content": "Request raw materials when needed:",
                    "tips": [
                        "Fill out the procurement request form",
                        "Optionally link to a manufacturing task that depends on it",
                        "Management will review and approve/reject",
                        "Track your requests in the 'My Procurement Requests' table"
                    ]
                }
            ]
        },
        "qa": {
            "title": "Quality Assurance Help",
            "icon": "🔍",
            "sections": [
                {
                    "title": "QA Workflow",
                    "content": "Quality Assurance tests products from Manufacturing before they proceed to Packaging.",
                    "tips": [
                        "New: Item received from Manufacturing, ready for testing",
                        "Testing: Currently inspecting product",
                        "Passed (Completed): QA approved, moves to Packaging",
                        "Failed: QA rejected, item doesn't meet standards"
                    ]
                },
                {
                    "title": "Testing Process",
                    "content": "Follow these steps for quality inspection:",
                    "tips": [
                        "Click 'Start Testing' to begin inspection",
                        "Verify product meets all quality standards",
                        "Use 'Mark Passed' if item passes all checks",
                        "Use 'Mark Failed' if item doesn't meet criteria",
                        "Document any defects in the description field"
                    ]
                },
                {
                    "title": "Quantity Handling",
                    "content": "When marking items as Passed or Failed:",
                    "tips": [
                        "Enter the quantity that passed/failed",
                        "Remaining quantity automatically creates a new task",
                        "This allows partial approvals in large batches"
                    ]
                }
            ]
        },
        "packaging": {
            "title": "Packaging Help",
            "icon": "📦",
            "sections": [
                {
                    "title": "Packaging Workflow",
                    "content": "Packaging handles final product preparation. Packed items move to Inventory as delivery items.",
                    "tips": [
                        "New: Item received from QA, ready to package",
                        "Packing: Currently packaging product",
                        "Packed: Packaging complete, moves to Inventory (Delivery Items)"
                    ]
                },
                {
                    "title": "Packaging Process",
                    "content": "Steps for packaging products:",
                    "tips": [
                        "Click 'Start Packing' to begin",
                        "Ensure proper packaging materials are used",
                        "Label packages clearly",
                        "Verify packaging size matches order specifications",
                        "Click 'Mark Packed' when complete"
                    ]
                },
                {
                    "title": "Packaging Size",
                    "content": "Each order has a specified packaging size in grams. This information is shown in the Inventory delivery items tab.",
                    "tips": []
                }
            ]
        },
        "inventory": {
            "title": "Inventory Help",
            "icon": "🏪",
            "sections": [
                {
                    "title": "Two Types of Inventory",
                    "content": "Inventory is divided into two categories with separate tabs:",
                    "tips": [
                        "Raw Materials: Items from Procurement and Manufacturing requests",
                        "Delivery Items: Finished products from Packaging ready for customers"
                    ]
                },
                {
                    "title": "Raw Materials Tab",
                    "content": "Manage raw materials and components:",
                    "tips": [
                        "Received (New): Material arrived from Procurement",
                        "On Shelf: Stored in warehouse",
                        "Shipped: Sent to production or other location",
                        "Expired: Material passed expiration date"
                    ]
                },
                {
                    "title": "Delivery Items Tab",
                    "content": "Manage finished products ready for delivery:",
                    "tips": [
                        "Received (New): Product arrived from Packaging",
                        "On Shelf: Stored and ready for shipment",
                        "Shipped: Delivered to customer",
                        "Expired: Product passed expiration date",
                        "Packaging size is displayed for each item"
                    ]
                },
                {
                    "title": "Status Actions",
                    "content": "Use action buttons to manage inventory:",
                    "tips": [
                        "'Place on Shelf' (blue) - Store item in warehouse",
                        "'Mark Shipped' (green) - Item delivered to customer",
                        "'Mark Expired' (red) - Item passed expiration"
                    ]
                }
            ]
        },
        "vendors": {
            "title": "Vendor Management Help",
            "icon": "🏢",
            "sections": [
                {
                    "title": "Managing Vendors",
                    "content": "The Vendor page helps you manage all supplier information in one place.",
                    "tips": [
                        "Vendor Name: Full company name (required)",
                        "Contact Person: Main point of contact",
                        "Phone & Email: Primary contact information",
                        "Address: Physical location for deliveries"
                    ]
                },
                {
                    "title": "Using Vendors",
                    "content": "When creating procurement orders, you can select a vendor from the dropdown. This helps track which suppliers provide which materials.",
                    "tips": []
                },
                {
                    "title": "Security",
                    "content": "The vendor page is password-protected. Your session lasts 30 minutes.",
                    "tips": []
                }
            ]
        },
        "recipes": {
            "title": "Recipe Bank Help",
            "icon": "📖",
            "sections": [
                {
                    "title": "Recipe Management",
                    "content": "The Recipe Bank stores standardized manufacturing processes that can be reused for consistent production.",
                    "tips": [
                        "Recipe Name: Unique identifier",
                        "Description: Brief overview of what this recipe produces",
                        "Ingredients/Materials: List all required raw materials and quantities",
                        "Instructions: Step-by-step manufacturing process"
                    ]
                },
                {
                    "title": "Using Recipes",
                    "content": "When creating a work order:",
                    "tips": [
                        "Select 'Existing' as the order category",
                        "Choose 'Manufacturing' as the assigned department",
                        "Pick a recipe from the dropdown",
                        "The order title will automatically use the recipe name"
                    ]
                },
                {
                    "title": "Best Practices",
                    "content": "Build a comprehensive recipe library to ensure consistent quality and speed up order creation for recurring products.",
                    "tips": []
                }
            ]
        }
    }
    
    page_help = help_data.get(page, help_data["dashboard"])
    
    return templates.TemplateResponse("help.html", {
        "request": request,
        "help": page_help,
        "page": page
    })

# -------- Role Pages -------- #

@app.get("/role/{role}", response_class=HTMLResponse)
def role_view(
    role: RoleEnum, 
    request: Request, 
    current_user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
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

    order_actions = {}
    for order in orders:
        order_actions[order.id] = get_next_status_buttons(role, order.status)

    # For inventory, separate into raw, delivery items, and packaging materials
    raw_items = []
    delivery_items = []
    packaging_items = []
    if role == RoleEnum.inventory:
        raw_items = [o for o in orders if o.item_type == ItemType.raw]
        delivery_items = [o for o in orders if o.item_type == ItemType.delivery]
        packaging_items = [o for o in orders if o.item_type == ItemType.packaging]

    return templates.TemplateResponse("role_view.html", {
        "request": request,
        "role": role,
        "orders": orders,
        "raw_items": raw_items,
        "delivery_items": delivery_items,
        "packaging_items": packaging_items,
        "manufacturing_reqs": manufacturing_reqs,
        "order_actions": order_actions,
    })


@app.post("/role/{role}/update-status")
def role_update_status(
    role: RoleEnum,
    order_id: int = Form(...),
    status: WorkOrderStatus = Form(...),
    qty_done: str = Form(default=""),
    blocked_reason: str = Form(default=""),
    db: Session = Depends(get_db),
):
    wo = db.query(WorkOrder).filter(WorkOrder.id == order_id).first()
    if not wo:
        return RedirectResponse(url=f"/role/{role.value}", status_code=303)

    total = wo.quantity or 1

    if status == WorkOrderStatus.blocked:
        wo.status = WorkOrderStatus.blocked
        wo.blocked_reason = blocked_reason or "No reason provided"
        wo.updated_at = datetime.utcnow()
        db.commit()
        return RedirectResponse(url=f"/role/{role.value}", status_code=303)

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
                order_type=wo.order_type,
                order_category=wo.order_category,
                recipe_id=wo.recipe_id,
                packaging_size_gm=wo.packaging_size_gm,
                item_type=wo.item_type,
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


# -------- CSV Import Endpoints -------- #

@app.post("/import-procurement")
async def import_procurement_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Import procurement orders from CSV"""
    try:
        contents = await file.read()
        decoded = contents.decode('utf-8')
        csv_reader = csv.DictReader(io.StringIO(decoded))
        
        count = 0
        for row in csv_reader:
            # Parse procurement order type
            proc_order_type = row.get('procurement_order_type', 'raw_material')
            
            # Determine item_type based on procurement_order_type
            if proc_order_type == 'packaging':
                item_type = ItemType.packaging
            else:
                item_type = ItemType.raw
            
            wo = WorkOrder(
                display_id=generate_display_id("dashboard"),
                title=row.get('title', 'Imported Order'),
                description=row.get('description', ''),
                assigned_role=RoleEnum.procurement,
                status=WorkOrderStatus(row.get('status', 'new')),
                quantity=int(row.get('quantity', 1)),
                unit=row.get('unit', 'Count'),
                order_type=OrderType(row.get('order_type', 'instant')),
                order_category=OrderCategory(row.get('order_category', 'new')),
                item_type=item_type,
                procurement_order_type=proc_order_type,
                packaging_type=row.get('packaging_type', None),
                packaging_size=row.get('packaging_size', None),
            )
            db.add(wo)
            count += 1
        
        db.commit()
        return RedirectResponse(url=f"/?import_success={count}_procurement", status_code=303)
    except Exception as e:
        return RedirectResponse(url=f"/?import_error={str(e)}", status_code=303)


@app.post("/import-recipes")
async def import_recipes_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Import recipes from CSV"""
    try:
        contents = await file.read()
        decoded = contents.decode('utf-8')
        csv_reader = csv.DictReader(io.StringIO(decoded))
        
        count = 0
        for row in csv_reader:
            # Check if recipe already exists
            existing = db.query(Recipe).filter(Recipe.name == row.get('name', '')).first()
            if existing:
                continue
                
            recipe = Recipe(
                name=row.get('name', f'Recipe {count+1}'),
                description=row.get('description', ''),
                ingredients=row.get('ingredients', ''),
                instructions=row.get('instructions', ''),
            )
            db.add(recipe)
            count += 1
        
        db.commit()
        return RedirectResponse(url=f"/recipes?import_success={count}", status_code=303)
    except Exception as e:
        return RedirectResponse(url=f"/recipes?import_error={str(e)}", status_code=303)


@app.post("/import-vendors")
async def import_vendors_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Import vendors from CSV"""
    try:
        contents = await file.read()
        decoded = contents.decode('utf-8')
        csv_reader = csv.DictReader(io.StringIO(decoded))
        
        count = 0
        for row in csv_reader:
            vendor = Vendor(
                name=row.get('name', f'Vendor {count+1}'),
                contact_person=row.get('contact_person', ''),
                phone=row.get('phone', ''),
                email=row.get('email', ''),
                address=row.get('address', ''),
                is_active=True,
            )
            db.add(vendor)
            count += 1
        
        db.commit()
        return RedirectResponse(url=f"/vendors?import_success={count}", status_code=303)
    except Exception as e:
        return RedirectResponse(url=f"/vendors?import_error={str(e)}", status_code=303)


@app.post("/import-manufacturing")
async def import_manufacturing_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Import manufacturing orders from CSV"""
    try:
        contents = await file.read()
        decoded = contents.decode('utf-8')
        csv_reader = csv.DictReader(io.StringIO(decoded))
        
        count = 0
        for row in csv_reader:
            wo = WorkOrder(
                display_id=generate_display_id("dashboard"),
                title=row.get('title', 'Imported Manufacturing Order'),
                description=row.get('description', ''),
                assigned_role=RoleEnum.manufacturing,
                status=WorkOrderStatus(row.get('status', 'new')),
                quantity=int(row.get('quantity', 1)),
                unit=row.get('unit', 'Count'),
                order_type=OrderType(row.get('order_type', 'instant')),
                order_category=OrderCategory(row.get('order_category', 'existing')),
                item_type=ItemType.delivery,
                packaging_size_gm=float(row.get('packaging_size_gm', 50)),
            )
            db.add(wo)
            count += 1
        
        db.commit()
        return RedirectResponse(url=f"/?import_success={count}_manufacturing", status_code=303)
    except Exception as e:
        return RedirectResponse(url=f"/?import_error={str(e)}", status_code=303)