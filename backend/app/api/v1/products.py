"""Products: named groups of assets (models/product.py)."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_scope, require
from app.models import Asset, Finding, Product, User
from app.models.enums import SEVERITY_ORDER, Role
from app.schemas.asset import ProductBody, ProductOut, ProductUpdate, SeverityCounts
from app.services import audit
from app.services.queries import ACTIVE
from app.services.scope import Scope

router = APIRouter(prefix="/products", tags=["products"])
manager = require(Role.manager, None)
_SEVERITIES = [s.value for s in SEVERITY_ORDER]


@router.get("", response_model=list[ProductOut])
def list_products(
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Every product, with how many of its assets you can see and what is open on them."""
    grouped = select(Asset.id, Asset.product_id).where(scope.assets(), Asset.product_id.is_not(None))
    visible = grouped.subquery()
    assets = dict(db.execute(select(visible.c.product_id, func.count()).group_by(visible.c.product_id)).all())
    counts: dict[int, dict[str, int]] = {}
    for product_id, severity, n in db.execute(
        select(visible.c.product_id, Finding.severity, func.count())
        .join(Finding, Finding.asset_id == visible.c.id)
        .where(Finding.status.in_(ACTIVE))
        .group_by(visible.c.product_id, Finding.severity)
    ):
        counts.setdefault(product_id, {})[severity] = n
    out = []
    for p in db.scalars(select(Product).order_by(func.lower(Product.name))):
        open_counts = SeverityCounts(**{s: counts.get(p.id, {}).get(s, 0) for s in _SEVERITIES})
        out.append(
            ProductOut(
                id=p.id,
                name=p.name,
                description=p.description,
                assets=assets.get(p.id, 0),
                open_total=sum(counts.get(p.id, {}).values()),
                open_counts=open_counts,
            )
        )
    return out


def _load(db: Session, product_id: int) -> Product:
    product = db.get(Product, product_id)
    if product is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Product not found")
    return product


def _ensure_unique(db: Session, name: str, product_id: int | None = None) -> None:
    """One product per name, whatever its case: "Checkout" and "checkout" would only confuse."""
    db.execute(select(func.pg_advisory_xact_lock(0x6770, func.hashtext(name.lower()))))
    same = select(Product.id).where(func.lower(Product.name) == name.lower(), Product.id != product_id)
    clash = db.scalar(same)
    if clash is not None:
        raise HTTPException(409, "A product with that name already exists")


def _commit(db: Session) -> None:
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A product with that name already exists")


@router.post("", response_model=ProductOut, status_code=status.HTTP_201_CREATED)
def create_product(
    body: ProductBody, request: Request, user: User = Depends(manager), db: Session = Depends(get_db)
):
    _ensure_unique(db, body.name.strip())
    product = Product(name=body.name.strip(), description=body.description)
    db.add(product)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A product with that name already exists")
    audit.record(db, "product.create", actor=user, request=request, target_type="product",
                 target_id=product.id, target_label=product.name)  # fmt: skip
    _commit(db)
    return ProductOut(id=product.id, name=product.name, description=product.description)


@router.patch("/{product_id}", response_model=ProductOut)
def update_product(
    product_id: int,
    body: ProductUpdate,
    request: Request,
    user: User = Depends(manager),
    db: Session = Depends(get_db),
):
    product = _load(db, product_id)
    before = audit.snapshot(product, ("name", "description"))
    if body.name is not None:
        _ensure_unique(db, body.name.strip(), product.id)
        product.name = body.name.strip()
    if body.description is not None:
        product.description = body.description
    if changes := audit.diff(before, product):
        audit.record(db, "product.update", actor=user, request=request, target_type="product",
                     target_id=product.id, target_label=product.name, changes=changes)  # fmt: skip
    _commit(db)
    return ProductOut(id=product.id, name=product.name, description=product.description)


@router.delete("/{product_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_product(
    product_id: int, request: Request, user: User = Depends(manager), db: Session = Depends(get_db)
):
    """The product goes; its assets stay, no longer grouped."""
    product = _load(db, product_id)
    audit.record(db, "product.delete", actor=user, request=request, target_type="product",
                 target_id=product.id, target_label=product.name)  # fmt: skip
    db.delete(product)
    db.commit()
