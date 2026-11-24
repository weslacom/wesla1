from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, Numeric, DateTime, ForeignKey, Text, UniqueConstraint, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base

def now(): return datetime.now(timezone.utc)
class User(Base):
    __tablename__='users'
    id: Mapped[int]=mapped_column(primary_key=True)
    name: Mapped[str]=mapped_column(String(120))
    email: Mapped[str]=mapped_column(String(190), unique=True, index=True)
    password_hash: Mapped[str]=mapped_column(String(256))
    role: Mapped[str]=mapped_column(String(20), default='customer')
    status: Mapped[str]=mapped_column(String(20), default='active')
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
class Application(Base):
    __tablename__='applications'
    id: Mapped[int]=mapped_column(primary_key=True)
    user_id: Mapped[int]=mapped_column(ForeignKey('users.id'))
    requested_role: Mapped[str]=mapped_column(String(20))
    details: Mapped[str]=mapped_column(Text, default='')
    status: Mapped[str]=mapped_column(String(20), default='pending')
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
class Product(Base):
    __tablename__='products'
    id: Mapped[int]=mapped_column(primary_key=True)
    merchant_id: Mapped[int]=mapped_column(ForeignKey('users.id'), index=True)
    title: Mapped[str]=mapped_column(String(180))
    description: Mapped[str]=mapped_column(Text, default='')
    price: Mapped[float]=mapped_column(Numeric(12,2))
    stock: Mapped[int]=mapped_column(Integer, default=0)
    affiliate_rate: Mapped[float]=mapped_column(Numeric(5,2), default=10.0)
    platform_rate: Mapped[float]=mapped_column(Numeric(5,2), default=5.0)
    status: Mapped[str]=mapped_column(String(20), default='active')
    product_type: Mapped[str]=mapped_column(String(40), default='other')
    size_system: Mapped[str]=mapped_column(String(20), default='none')
    has_variants: Mapped[bool]=mapped_column(default=False)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
class Link(Base):
    __tablename__='affiliate_links'
    id: Mapped[int]=mapped_column(primary_key=True)
    code: Mapped[str]=mapped_column(String(32), unique=True, index=True)
    affiliate_id: Mapped[int]=mapped_column(ForeignKey('users.id'), index=True)
    product_id: Mapped[int]=mapped_column(ForeignKey('products.id'), index=True)
    clicks: Mapped[int]=mapped_column(Integer, default=0)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
    __table_args__=(UniqueConstraint('affiliate_id','product_id'),)
class Order(Base):
    __tablename__='orders'
    id: Mapped[int]=mapped_column(primary_key=True)
    order_number: Mapped[str]=mapped_column(String(32), unique=True, index=True)
    customer_name: Mapped[str]=mapped_column(String(120))
    customer_phone: Mapped[str]=mapped_column(String(40))
    address: Mapped[str]=mapped_column(Text)
    product_id: Mapped[int]=mapped_column(ForeignKey('products.id'))
    merchant_id: Mapped[int]=mapped_column(ForeignKey('users.id'))
    affiliate_id: Mapped[int|None]=mapped_column(ForeignKey('users.id'), nullable=True)
    quantity: Mapped[int]=mapped_column(Integer)
    variant_id: Mapped[int|None]=mapped_column(ForeignKey('product_variants.id'), nullable=True)
    selected_color: Mapped[str|None]=mapped_column(String(80), nullable=True)
    selected_size: Mapped[str|None]=mapped_column(String(40), nullable=True)
    unit_price: Mapped[float]=mapped_column(Numeric(12,2))
    total: Mapped[float]=mapped_column(Numeric(12,2))
    affiliate_rate_snapshot: Mapped[float]=mapped_column(Numeric(5,2))
    platform_rate_snapshot: Mapped[float]=mapped_column(Numeric(5,2))
    affiliate_commission: Mapped[float]=mapped_column(Numeric(12,2), default=0)
    platform_commission: Mapped[float]=mapped_column(Numeric(12,2), default=0)
    status: Mapped[str]=mapped_column(String(20), default='pending')
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
class Payout(Base):
    __tablename__='payouts'
    id: Mapped[int]=mapped_column(primary_key=True)
    affiliate_id: Mapped[int]=mapped_column(ForeignKey('users.id'))
    amount: Mapped[float]=mapped_column(Numeric(12,2))
    method: Mapped[str]=mapped_column(String(40))
    destination: Mapped[str]=mapped_column(String(180))
    status: Mapped[str]=mapped_column(String(20), default='pending')
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class AuthSession(Base):
    __tablename__='auth_sessions'
    id: Mapped[int]=mapped_column(primary_key=True)
    token_hash: Mapped[str]=mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int]=mapped_column(ForeignKey('users.id'), index=True)
    expires_at: Mapped[datetime]=mapped_column(DateTime(timezone=True))


class Contract(Base):
    __tablename__='contracts'
    id: Mapped[int]=mapped_column(primary_key=True)
    contract_type: Mapped[str]=mapped_column(String(32), index=True)
    title: Mapped[str]=mapped_column(String(180))
    body: Mapped[str]=mapped_column(Text)
    merchant_id: Mapped[int|None]=mapped_column(ForeignKey('users.id'), nullable=True, index=True)
    affiliate_id: Mapped[int|None]=mapped_column(ForeignKey('users.id'), nullable=True, index=True)
    commission_rate: Mapped[float|None]=mapped_column(Numeric(5,2), nullable=True)
    penalty_terms: Mapped[str]=mapped_column(Text, default='')
    status: Mapped[str]=mapped_column(String(20), default='draft', index=True)
    contract_number: Mapped[str|None]=mapped_column(String(40), nullable=True, unique=True)
    starts_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True), nullable=True)
    ends_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True), nullable=True)
    approved_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int]=mapped_column(Integer, default=1)
    platform_signer_name: Mapped[str]=mapped_column(String(160), default='Wesla Platform')
    legal_entity_name: Mapped[str]=mapped_column(String(200), default='')
    commission_scope: Mapped[str]=mapped_column(String(20), default='contract')
    penalty_type: Mapped[str|None]=mapped_column(String(20), nullable=True)
    penalty_amount: Mapped[float|None]=mapped_column(Numeric(12,2), nullable=True)
    penalty_percent: Mapped[float|None]=mapped_column(Numeric(5,2), nullable=True)
    termination_terms: Mapped[str]=mapped_column(Text, default='')
    final_hash: Mapped[str|None]=mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class ContractAcceptance(Base):
    __tablename__='contract_acceptances'
    id: Mapped[int]=mapped_column(primary_key=True)
    contract_id: Mapped[int]=mapped_column(ForeignKey('contracts.id'), index=True)
    user_id: Mapped[int]=mapped_column(ForeignKey('users.id'), index=True)
    full_name: Mapped[str]=mapped_column(String(120))
    document_hash: Mapped[str]=mapped_column(String(64))
    accepted_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
    ip_address: Mapped[str]=mapped_column(String(64), default='')
    user_agent: Mapped[str]=mapped_column(String(500), default='')
    __table_args__=(UniqueConstraint('contract_id','user_id'),)


class ProductVariant(Base):
    __tablename__='product_variants'
    id: Mapped[int]=mapped_column(primary_key=True)
    product_id: Mapped[int]=mapped_column(ForeignKey('products.id', ondelete='CASCADE'), index=True)
    color: Mapped[str]=mapped_column(String(80), default='')
    size_label: Mapped[str]=mapped_column(String(40), default='')
    size_system: Mapped[str]=mapped_column(String(20), default='none')
    stock: Mapped[int]=mapped_column(Integer, default=0)
    price_override: Mapped[float|None]=mapped_column(Numeric(12,2), nullable=True)
    foot_length_cm: Mapped[float|None]=mapped_column(Numeric(5,2), nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class ProductSizeGuide(Base):
    __tablename__='product_size_guides'
    id: Mapped[int]=mapped_column(primary_key=True)
    product_id: Mapped[int]=mapped_column(ForeignKey('products.id', ondelete='CASCADE'), index=True)
    label: Mapped[str]=mapped_column(String(80))
    measurements: Mapped[dict]=mapped_column(JSON, default=dict)

class ProductImage(Base):
    __tablename__='product_images'
    id: Mapped[int]=mapped_column(primary_key=True)
    product_id: Mapped[int]=mapped_column(ForeignKey('products.id', ondelete='CASCADE'), index=True)
    storage_path: Mapped[str]=mapped_column(Text)
    is_primary: Mapped[bool]=mapped_column(default=False)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class ContractEvent(Base):
    __tablename__='contract_events'
    id: Mapped[int]=mapped_column(primary_key=True)
    contract_id: Mapped[int]=mapped_column(ForeignKey('contracts.id', ondelete='CASCADE'), index=True)
    actor_user_id: Mapped[int|None]=mapped_column(ForeignKey('users.id'), nullable=True)
    event_type: Mapped[str]=mapped_column(String(40))
    details: Mapped[dict]=mapped_column(JSON, default=dict)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class ContractTerminationRequest(Base):
    __tablename__='contract_termination_requests'
    id: Mapped[int]=mapped_column(primary_key=True)
    contract_id: Mapped[int]=mapped_column(ForeignKey('contracts.id', ondelete='CASCADE'), index=True)
    requester_user_id: Mapped[int]=mapped_column(ForeignKey('users.id'))
    reason: Mapped[str]=mapped_column(Text)
    evidence_paths: Mapped[str]=mapped_column(Text, default='[]')
    status: Mapped[str]=mapped_column(String(30), default='under_review')
    decision_reason: Mapped[str|None]=mapped_column(Text, nullable=True)
    decided_by: Mapped[int|None]=mapped_column(ForeignKey('users.id'), nullable=True)
    decided_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class CommissionChangeRequest(Base):
    __tablename__='commission_change_requests'
    id: Mapped[int]=mapped_column(primary_key=True)
    contract_id: Mapped[int|None]=mapped_column(ForeignKey('contracts.id'), nullable=True)
    product_id: Mapped[int|None]=mapped_column(ForeignKey('products.id'), nullable=True)
    merchant_id: Mapped[int|None]=mapped_column(ForeignKey('users.id'), nullable=True)
    affiliate_id: Mapped[int|None]=mapped_column(ForeignKey('users.id'), nullable=True)
    old_rate: Mapped[float]=mapped_column(Numeric(5,2))
    new_rate: Mapped[float]=mapped_column(Numeric(5,2))
    proposed_by: Mapped[int]=mapped_column(ForeignKey('users.id'))
    affected_user_id: Mapped[int]=mapped_column(ForeignKey('users.id'))
    status: Mapped[str]=mapped_column(String(30), default='pending')
    accepted_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
