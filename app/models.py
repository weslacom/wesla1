from datetime import datetime, timezone
from sqlalchemy import String, Integer, BigInteger, Float, Numeric, DateTime, ForeignKey, Text, UniqueConstraint, JSON, Boolean
from sqlalchemy.dialects.postgresql import JSONB
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
    contact_phone: Mapped[str|None]=mapped_column(String(40), nullable=True)
    contact_whatsapp: Mapped[str|None]=mapped_column(String(40), nullable=True)
    contact_public: Mapped[bool]=mapped_column(Boolean, default=False)
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
    deleted_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True), nullable=True)
    deleted_by: Mapped[int|None]=mapped_column(ForeignKey('users.id'), nullable=True)
    deleted_by_role: Mapped[str|None]=mapped_column(String(20), nullable=True)
    deleted_reason: Mapped[str]=mapped_column(Text, default='')
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
    customer_user_id: Mapped[int|None]=mapped_column(ForeignKey('users.id',ondelete='SET NULL'), nullable=True, index=True)
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
    coupon_code: Mapped[str|None]=mapped_column(String(40), nullable=True)
    discount_amount: Mapped[float]=mapped_column(Numeric(12,2), default=0)
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
    participant_ids: Mapped[list]=mapped_column(JSONB, default=list)
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
    brand_signature_snapshot: Mapped[str|None]=mapped_column(Text, nullable=True)
    brand_stamp_snapshot: Mapped[str|None]=mapped_column(Text, nullable=True)
    brand_assets_version: Mapped[int|None]=mapped_column(Integer, nullable=True)
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
    signature_data_url: Mapped[str|None]=mapped_column(Text, nullable=True)
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
    measurements: Mapped[dict]=mapped_column(JSON().with_variant(JSONB(), 'postgresql'), default=dict)

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
    details: Mapped[dict]=mapped_column(JSON().with_variant(JSONB(), 'postgresql'), default=dict)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class ContractTerminationRequest(Base):
    __tablename__='contract_termination_requests'
    id: Mapped[int]=mapped_column(primary_key=True)
    contract_id: Mapped[int]=mapped_column(ForeignKey('contracts.id', ondelete='CASCADE'), index=True)
    requester_user_id: Mapped[int]=mapped_column(ForeignKey('users.id'))
    reason: Mapped[str]=mapped_column(Text)
    evidence_paths: Mapped[list]=mapped_column(JSON().with_variant(JSONB(), 'postgresql'), default=list)
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


class AffiliateProductExclusion(Base):
    __tablename__='affiliate_product_exclusions'
    id: Mapped[int]=mapped_column(primary_key=True)
    affiliate_id: Mapped[int]=mapped_column(ForeignKey('users.id'), index=True)
    product_id: Mapped[int]=mapped_column(ForeignKey('products.id', ondelete='CASCADE'), index=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
    __table_args__=(UniqueConstraint('affiliate_id','product_id'),)

class ProductAuditEvent(Base):
    __tablename__='product_audit_events'
    id: Mapped[int]=mapped_column(primary_key=True)
    product_id: Mapped[int]=mapped_column(ForeignKey('products.id'), index=True)
    actor_user_id: Mapped[int|None]=mapped_column(ForeignKey('users.id'), nullable=True)
    action: Mapped[str]=mapped_column(String(40))
    details: Mapped[dict]=mapped_column(JSON().with_variant(JSONB(), 'postgresql'), default=dict)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class ContractRequest(Base):
    __tablename__='contract_requests'
    id: Mapped[int]=mapped_column(primary_key=True)
    user_id: Mapped[int]=mapped_column(ForeignKey('users.id'), index=True)
    requested_type: Mapped[str]=mapped_column(String(32))
    title: Mapped[str]=mapped_column(String(180))
    details: Mapped[str]=mapped_column(Text)
    desired_commission: Mapped[float|None]=mapped_column(Numeric(5,2), nullable=True)
    status: Mapped[str]=mapped_column(String(20), default='pending', index=True)
    admin_note: Mapped[str]=mapped_column(Text, default='')
    reviewed_by: Mapped[int|None]=mapped_column(ForeignKey('users.id'), nullable=True)
    reviewed_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class ContractNegotiation(Base):
    __tablename__='contract_negotiations'
    id: Mapped[int]=mapped_column(primary_key=True)
    contract_id: Mapped[int]=mapped_column(ForeignKey('contracts.id'), index=True)
    proposer_id: Mapped[int]=mapped_column(ForeignKey('users.id'), index=True)
    recipient_id: Mapped[int]=mapped_column(ForeignKey('users.id'), index=True)
    parent_id: Mapped[int|None]=mapped_column(ForeignKey('contract_negotiations.id'), nullable=True)
    proposal_text: Mapped[str]=mapped_column(Text)
    reason: Mapped[str]=mapped_column(Text, default='')
    response_text: Mapped[str]=mapped_column(Text, default='')
    status: Mapped[str]=mapped_column(String(20), default='pending', index=True)
    responded_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class Notification(Base):
    __tablename__='notifications'
    id: Mapped[int]=mapped_column(primary_key=True)
    user_id: Mapped[int]=mapped_column(ForeignKey('users.id'), index=True)
    title: Mapped[str]=mapped_column(String(180))
    body: Mapped[str]=mapped_column(Text, default='')
    target_url: Mapped[str]=mapped_column(String(500), default='')
    read_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)


class Announcement(Base):
    __tablename__='announcements'
    id: Mapped[int]=mapped_column(primary_key=True)
    title: Mapped[str]=mapped_column(String(180))
    body: Mapped[str]=mapped_column(Text, default='')
    audience: Mapped[str]=mapped_column(String(20), default='all')
    target_url: Mapped[str]=mapped_column(String(500), default='')
    button_label: Mapped[str]=mapped_column(String(60), default='')
    placement: Mapped[str]=mapped_column(String(30), default='top_banner')
    priority: Mapped[int]=mapped_column(Integer, default=0)
    is_active: Mapped[bool]=mapped_column(Boolean, default=True)
    is_sponsored: Mapped[bool]=mapped_column(Boolean, default=False)
    advertiser_name: Mapped[str]=mapped_column(String(180), default='')
    price_egp: Mapped[float]=mapped_column(Numeric(12,2), default=0)
    payment_status: Mapped[str]=mapped_column(String(20), default='not_required')
    payment_reference: Mapped[str]=mapped_column(String(120), default='')
    starts_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True), nullable=True)
    ends_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[int|None]=mapped_column(ForeignKey('users.id'), nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class AnnouncementEvent(Base):
    __tablename__='announcement_events'
    id: Mapped[int]=mapped_column(primary_key=True)
    announcement_id: Mapped[int]=mapped_column(ForeignKey('announcements.id', ondelete='CASCADE'), index=True)
    event_type: Mapped[str]=mapped_column(String(12))
    visitor_key: Mapped[str]=mapped_column(String(64), index=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)


class Favorite(Base):
    __tablename__='favorites'
    id: Mapped[int]=mapped_column(primary_key=True)
    user_id: Mapped[int]=mapped_column(ForeignKey('users.id',ondelete='CASCADE'),index=True)
    product_id: Mapped[int]=mapped_column(ForeignKey('products.id',ondelete='CASCADE'),index=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    __table_args__=(UniqueConstraint('user_id','product_id'),)

class Coupon(Base):
    __tablename__='coupons'
    id: Mapped[int]=mapped_column(primary_key=True)
    code: Mapped[str]=mapped_column(String(40),unique=True,index=True)
    discount_type: Mapped[str]=mapped_column(String(12))
    discount_value: Mapped[float]=mapped_column(Numeric(12,2))
    min_order_total: Mapped[float]=mapped_column(Numeric(12,2),default=0)
    max_discount: Mapped[float|None]=mapped_column(Numeric(12,2),nullable=True)
    usage_limit: Mapped[int|None]=mapped_column(Integer,nullable=True)
    used_count: Mapped[int]=mapped_column(Integer,default=0)
    starts_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    ends_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    is_active: Mapped[bool]=mapped_column(Boolean,default=True)
    created_by: Mapped[int|None]=mapped_column(ForeignKey('users.id',ondelete='SET NULL'),nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)

class CouponRedemption(Base):
    __tablename__='coupon_redemptions'
    id: Mapped[int]=mapped_column(primary_key=True)
    coupon_id: Mapped[int]=mapped_column(ForeignKey('coupons.id'))
    order_id: Mapped[int]=mapped_column(ForeignKey('orders.id'),unique=True)
    user_id: Mapped[int|None]=mapped_column(ForeignKey('users.id',ondelete='SET NULL'),nullable=True)
    discount_amount: Mapped[float]=mapped_column(Numeric(12,2))
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)

class SupportTicket(Base):
    __tablename__='support_tickets'
    id: Mapped[int]=mapped_column(primary_key=True)
    user_id: Mapped[int]=mapped_column(ForeignKey('users.id',ondelete='CASCADE'),index=True)
    subject: Mapped[str]=mapped_column(String(180))
    status: Mapped[str]=mapped_column(String(20),default='open')
    priority: Mapped[str]=mapped_column(String(12),default='normal')
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)

class SupportMessage(Base):
    __tablename__='support_messages'
    id: Mapped[int]=mapped_column(primary_key=True)
    ticket_id: Mapped[int]=mapped_column(ForeignKey('support_tickets.id',ondelete='CASCADE'),index=True)
    sender_user_id: Mapped[int|None]=mapped_column(ForeignKey('users.id',ondelete='SET NULL'),nullable=True)
    body: Mapped[str]=mapped_column(Text)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    read_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)

class WalletTransaction(Base):
    __tablename__='wallet_transactions'
    id: Mapped[int]=mapped_column(primary_key=True)
    user_id: Mapped[int]=mapped_column(ForeignKey('users.id',ondelete='CASCADE'),index=True)
    amount: Mapped[float]=mapped_column(Numeric(12,2))
    kind: Mapped[str]=mapped_column(String(24))
    reference_type: Mapped[str]=mapped_column(String(24))
    reference_id: Mapped[int]=mapped_column(BigInteger)
    description: Mapped[str]=mapped_column(String(240),default='')
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    __table_args__=(UniqueConstraint('user_id','kind','reference_type','reference_id'),)


class PasswordResetToken(Base):
    __tablename__='password_reset_tokens'
    id: Mapped[int]=mapped_column(primary_key=True)
    user_id: Mapped[int]=mapped_column(ForeignKey('users.id',ondelete='CASCADE'),index=True)
    token_hash: Mapped[str]=mapped_column(String(64),unique=True)
    expires_at: Mapped[datetime]=mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
