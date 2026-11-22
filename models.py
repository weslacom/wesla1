from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, Numeric, DateTime, ForeignKey, Text, UniqueConstraint
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
