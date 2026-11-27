import os, secrets, hashlib, hmac, json, base64, binascii, asyncio, re, urllib.request, urllib.error
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, HTTPException, Response, Request, Query
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import select, func, text
from .database import Base, engine, get_db, SessionLocal
from .event_hub import event_hub
from .models import User, Application, Product, Link, Order, Payout, AuthSession, Contract, ContractAcceptance, ProductVariant, ProductSizeGuide, ProductImage, ContractEvent, ContractTerminationRequest, CommissionChangeRequest, AffiliateProductExclusion, ProductAuditEvent, ContractRequest, ContractNegotiation, Notification, Announcement, AnnouncementEvent, Favorite, Coupon, CouponRedemption, SupportTicket, SupportMessage, WalletTransaction, PasswordResetToken

# Production schema is managed by Supabase migrations. Vercel instances are ephemeral.
# Keep automatic schema creation for local development and isolated tests only.
if os.getenv('VERCEL') != '1':
    Base.metadata.create_all(bind=engine)
app=FastAPI(title='Wesla Affiliate Platform', version='1.0.0')

# Normalize invisible bidirectional control characters accidentally appended
# when Arabic/RTL links are copied from chat or messaging apps.
_BIDI_URL_CONTROLS = {'\u200e', '\u200f', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068', '\u2069', '\ufeff'}

@app.middleware('http')
async def normalize_rtl_only_url_suffix(request: Request, call_next):
    raw_path = request.scope.get('path', '')
    normalized = ''.join(ch for ch in raw_path if ch not in _BIDI_URL_CONTROLS)
    if normalized == '/' and raw_path != '/':
        return RedirectResponse(url='/', status_code=307, headers={'Cache-Control': 'no-store'})
    return await call_next(request)

@app.on_event('startup')
def cleanup_temporary_data_every_15_days():
    # There is no Redis/in-memory cache in this application. Clean only expired
    # login sessions and already-read notifications; never delete orders/products.
    if engine.dialect.name != 'postgresql':
        return
    db=SessionLocal()
    try:
        last=db.execute(text("select value from site_settings where key='last_temporary_data_cleanup'")).scalar()
        now_utc=datetime.now(timezone.utc)
        if last:
            try:
                last_at=datetime.fromisoformat(str(last).replace('Z','+00:00'))
                if last_at.tzinfo is None: last_at=last_at.replace(tzinfo=timezone.utc)
                if now_utc-last_at < timedelta(days=15): return
            except (TypeError,ValueError):
                pass
        db.execute(text("delete from auth_sessions where expires_at < now()"))
        db.execute(text("delete from notifications where read_at is not null and read_at < now() - interval '15 days'"))
        db.execute(text("insert into site_settings(key,value,updated_at) values ('last_temporary_data_cleanup',:value,now()) on conflict(key) do update set value=excluded.value,updated_at=now()"),{'value':now_utc.isoformat()})
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
# Compress JSON and HTML responses to reduce bandwidth for mobile visitors.
app.add_middleware(GZipMiddleware, minimum_size=1000, compresslevel=5)
admin_origins=[x.strip().rstrip('/') for x in os.getenv('ADMIN_PORTAL_ORIGINS','').split(',') if x.strip()]
# The admin page is served from this same origin by default. Enable CORS only when
# an explicitly configured external admin origin is intentionally used.
if admin_origins:
    app.add_middleware(CORSMiddleware,allow_origins=admin_origins,allow_credentials=True,allow_methods=['GET','POST','PATCH','DELETE','OPTIONS'],allow_headers=['Content-Type'])

def set_session_cookie(response:Response,token:str,max_age:int):
    # Cross-origin admin fetch requires SameSite=None; browsers require Secure with None.
    cross_origin_admin=bool(admin_origins)
    response.set_cookie('wesla_session',token,httponly=True,samesite='none' if cross_origin_admin else 'lax',secure=True if cross_origin_admin else os.getenv('COOKIE_SECURE','0')=='1',max_age=max_age)
@app.get('/api/_portal/diagnostics')
def portal_diagnostics(db:Session=Depends(get_db)):
    # Safe same-origin readiness check for the administration page.
    db.execute(text('select 1'))
    required = ['/api/admin/password-login', '/api/admin/overview', '/api/admin/contracts',
                '/api/admin/contract-requests', '/api/admin/negotiations', '/api/admin/termination-requests', '/api/admin/accounts', '/api/admin/visitors', '/api/admin/pages', '/api/admin/referrals', '/api/admin/rewards/offers', '/api/advanced/rewards/offers', '/api/public/merchants', '/api/public/pages']
    paths = app.openapi().get('paths', {})
    routes = {path: path in paths for path in required}
    ready = all(routes.values())
    return {'ok': ready, 'api_reachable': True, 'database_ready': True,
            'database_status': 'ok', 'admin_routes': routes}

@app.get('/health')
def health(db:Session=Depends(get_db)):
    # Readiness probe: confirm the application process and PostgreSQL are both responsive.
    db.execute(text('select 1'))
    return {'ok':True,'status':'ok','database':'ok'}

app.mount('/static', StaticFiles(directory='app/static'), name='static')

# Passwords use PBKDF2; sessions are random opaque tokens stored only as hashes.
def hash_password(password:str)->str:
    salt=secrets.token_bytes(16); digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,240000)
    return salt.hex()+':'+digest.hex()
def verify_password(password:str, stored:str)->bool:
    try:
        salt_hex,digest_hex=stored.split(':'); digest=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt_hex),240000)
        return hmac.compare_digest(digest.hex(),digest_hex)
    except Exception: return False
def current_user(request:Request, db:Session=Depends(get_db)):
    token=request.cookies.get('wesla_session')
    if not token: raise HTTPException(401,'سجل الدخول أولاً')
    token_hash=hashlib.sha256(token.encode()).hexdigest(); session=db.scalar(select(AuthSession).where(AuthSession.token_hash==token_hash))
    if not session or (session.expires_at.replace(tzinfo=timezone.utc) if session.expires_at.tzinfo is None else session.expires_at) < datetime.now(timezone.utc): raise HTTPException(401,'انتهت الجلسة، سجل الدخول مرة أخرى')
    user=db.get(User,session.user_id)
    if not user or user.status!='active': raise HTTPException(403,'الحساب غير نشط')
    return user
def require_role(*roles):
    def dep(user:User=Depends(current_user)):
        if user.role not in roles: raise HTTPException(403,'ليس لديك صلاحية لهذا الإجراء')
        return user
    return dep


@app.middleware('http')
async def capture_admin_activity(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if path.startswith('/api/admin/') and request.method in ('POST','PATCH','PUT','DELETE'):
        db = SessionLocal()
        try:
            token = request.cookies.get('wesla_session')
            if token:
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                actor = db.scalar(select(User).join(AuthSession, AuthSession.user_id == User.id).where(
                    AuthSession.token_hash == token_hash, AuthSession.expires_at > datetime.now(timezone.utc),
                    User.role == 'admin', User.status == 'active'))
                enabled = db.execute(text("select is_enabled from wesla_feature_settings where feature_key='admin_activity_log'")).scalar()
                if actor and actor.role == 'admin' and enabled:
                    target_match = re.search(r'/([0-9]+)(?:/|$)', path)
                    db.execute(text("""
                      insert into wesla_admin_activity_log(actor_user_id,actor_name,action,request_path,target_id,status_code)
                      values (:actor,:name,:action,:path,:target,:status)
                    """), {'actor':actor.id,'name':actor.name,'action':request.method,'path':path,
                           'target':int(target_match.group(1)) if target_match else None,'status':response.status_code})
                    db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()
    return response

PUBLIC_EVENT_TABLES = {'products', 'product_variants', 'product_images', 'announcements', 'site_settings'}

def require_admin_stream_access(request: Request):
    # Validate once with a short-lived DB session; never hold a DB session open for an SSE connection.
    db = SessionLocal()
    try:
        user = current_user(request, db)
        if user.role != 'admin':
            raise HTTPException(403, 'ليس لديك صلاحية لمتابعة تحديثات الإدارة')
    finally:
        db.close()

async def stream_database_events(request: Request, admin_only: bool = False):
    queue = await event_hub.subscribe()
    async def event_generator():
        loop = asyncio.get_running_loop()
        started_at = loop.time()
        last_auth_check = started_at
        # Vercel serverless functions have a hard execution limit. Close each
        # SSE response cleanly after 25 seconds; EventSource reconnects itself.
        try:
            yield 'retry: 3000\n\n'
            while loop.time() - started_at < 25:
                if await request.is_disconnected():
                    break
                try:
                    raw = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    now = asyncio.get_running_loop().time()
                    if admin_only and now - last_auth_check >= 60:
                        try:
                            require_admin_stream_access(request)
                        except HTTPException:
                            yield 'event: auth_expired\ndata: {}\n\n'
                            break
                        last_auth_check = now
                    yield ': keep-alive\n\n'
                    continue
                try:
                    payload = json.loads(raw)
                except (TypeError, ValueError):
                    continue
                if not admin_only and payload.get('table') not in PUBLIC_EVENT_TABLES:
                    continue
                yield 'data: ' + json.dumps(payload, ensure_ascii=False, separators=(',', ':')) + '\n\n'
        finally:
            await event_hub.unsubscribe(queue)
    return StreamingResponse(
        event_generator(),
        media_type='text/event-stream',
        headers={'Cache-Control': 'no-cache, no-store', 'X-Accel-Buffering': 'no', 'Content-Encoding': 'identity'},
    )

@app.get('/api/public/events')
async def public_database_events(request: Request):
    return await stream_database_events(request, admin_only=False)

@app.get('/api/admin/events')
async def admin_database_events(request: Request):
    require_admin_stream_access(request)
    return await stream_database_events(request, admin_only=True)


def public_user(u): return {'id':u.id,'name':u.name,'email':u.email,'role':u.role,'status':u.status,'contact_phone':u.contact_phone,'contact_whatsapp':u.contact_whatsapp,'contact_public':u.contact_public}
def products_out(rows,db):
    """Serialize a page of products with a fixed number of queries (not N+1 queries)."""
    if not rows: return []
    product_ids=[p.id for p in rows]
    merchant_ids={p.merchant_id for p in rows}
    merchants={u.id:u for u in db.scalars(select(User).where(User.id.in_(merchant_ids))).all()} if merchant_ids else {}
    variants_by={pid:[] for pid in product_ids}
    for v in db.scalars(select(ProductVariant).where(ProductVariant.product_id.in_(product_ids)).order_by(ProductVariant.product_id,ProductVariant.color,ProductVariant.size_label)).all():
        variants_by[v.product_id].append(v)
    images_by={pid:[] for pid in product_ids}
    for im in db.scalars(select(ProductImage).where(ProductImage.product_id.in_(product_ids)).order_by(ProductImage.product_id,ProductImage.is_primary.desc(),ProductImage.id)).all():
        images_by[im.product_id].append(im)
    guides_by={pid:[] for pid in product_ids}
    for g in db.scalars(select(ProductSizeGuide).where(ProductSizeGuide.product_id.in_(product_ids))).all():  # .all() belongs to ScalarResult, not Select
        guides_by[g.product_id].append(g)
    result=[]
    for p in rows:
        merchant=merchants.get(p.merchant_id)
        result.append({'id':p.id,'title':p.title,'description':p.description,'price':p.price,'stock':p.stock,'affiliate_rate':p.affiliate_rate,'platform_rate':p.platform_rate,'status':p.status,'merchant':merchant.name if merchant else '',
          'product_type':p.product_type,'size_system':p.size_system,'has_variants':p.has_variants,
          'variants':[{'id':v.id,'color':v.color,'size':v.size_label,'size_system':v.size_system,'stock':v.stock,'price':v.price_override,'foot_length_cm':v.foot_length_cm} for v in variants_by[p.id]],
          'images':[{'id':im.id,'path':f'/api/public/product-images/{im.id}','primary':im.is_primary} for im in images_by[p.id]],
          'size_guide':[{'label':g.label,'measurements':g.measurements if isinstance(g.measurements,dict) else json.loads(g.measurements or '{}')} for g in guides_by[p.id]]})
    return result

def product_out(p,db):
    return products_out([p],db)[0]

def save_product_images(product_id:int,images:list[str],db:Session):
    if len(images)>4: raise HTTPException(400,'يمكن رفع 4 صور كحد أقصى للمنتج')
    existing=db.scalar(select(func.count(ProductImage.id)).where(ProductImage.product_id==product_id)) or 0
    if existing+len(images)>4: raise HTTPException(400,'الحد الأقصى 4 صور للمنتج')
    for index,data_url in enumerate(images):
        if not isinstance(data_url,str) or len(data_url)>1_500_000: raise HTTPException(413,'حجم الصورة كبير؛ اختر صورة أصغر')
        try:
            header,payload=data_url.split(',',1)
            mime=header.removeprefix('data:').removesuffix(';base64')
            if mime not in ('image/jpeg','image/png','image/webp'): raise ValueError('unsupported image')
            raw=base64.b64decode(payload,validate=True)
            if not raw or len(raw)>1_000_000: raise ValueError('image too large')
        except (ValueError,binascii.Error): raise HTTPException(400,'صيغة الصورة غير مدعومة أو حجمها أكبر من 1 ميجابايت')
        db.add(ProductImage(product_id=product_id,storage_path=data_url,is_primary=(existing==0 and index==0)))
class AnnouncementIn(BaseModel):
    title: str = Field(min_length=3, max_length=180)
    body: str = Field(min_length=1, max_length=5000)
    audience: str = Field(default='all', max_length=20)
    target_url: str = Field(default='', max_length=500)
    button_label: str = Field(default='', max_length=60)
    placement: str = Field(default='top_banner', max_length=30)
    priority: int = Field(default=0, ge=0, le=1000)
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    is_sponsored: bool = False
    advertiser_name: str = Field(default='', max_length=180)
    price_egp: Decimal = Field(default=Decimal('0'), ge=0, max_digits=12, decimal_places=2)
    payment_status: str = Field(default='not_required', max_length=20)
    payment_reference: str = Field(default='', max_length=120)

class AnnouncementUpdateIn(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=180)
    body: str | None = Field(default=None, min_length=1, max_length=5000)
    audience: str | None = Field(default=None, max_length=20)
    target_url: str | None = Field(default=None, max_length=500)
    button_label: str | None = Field(default=None, max_length=60)
    placement: str | None = Field(default=None, max_length=30)
    priority: int | None = Field(default=None, ge=0, le=1000)
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    is_active: bool | None = None
    is_sponsored: bool | None = None
    advertiser_name: str | None = Field(default=None, max_length=180)
    price_egp: Decimal | None = Field(default=None, ge=0, max_digits=12, decimal_places=2)
    payment_status: str | None = Field(default=None, max_length=20)
    payment_reference: str | None = Field(default=None, max_length=120)

class AnnouncementEventIn(BaseModel):
    event_type: str
    visitor_key: str = Field(min_length=24, max_length=64)

class ForgotPasswordIn(BaseModel):
    email: str = Field(min_length=5,max_length=190)

class ResetPasswordIn(BaseModel):
    email: str = Field(min_length=5,max_length=190)
    code: str = Field(min_length=32,max_length=64)
    new_password: str = Field(min_length=10,max_length=128)

class FavoriteIn(BaseModel):
    product_id: int

class SupportTicketIn(BaseModel):
    subject: str = Field(min_length=4,max_length=180)
    message: str = Field(min_length=10,max_length=5000)

class SupportMessageIn(BaseModel):
    body: str = Field(min_length=2,max_length=5000)

class SupportTicketUpdateIn(BaseModel):
    status: str | None = None
    priority: str | None = None

class CouponIn(BaseModel):
    code: str = Field(min_length=3,max_length=40)
    discount_type: str
    discount_value: Decimal = Field(gt=0)
    min_order_total: Decimal = Field(default=Decimal('0'),ge=0)
    max_discount: Decimal | None = Field(default=None,gt=0)
    usage_limit: int | None = Field(default=None,ge=1)
    starts_at: datetime | None = None
    ends_at: datetime | None = None

class CouponUpdateIn(BaseModel):
    is_active: bool | None = None
    usage_limit: int | None = Field(default=None,ge=1)
    ends_at: datetime | None = None


class RegisterIn(BaseModel): name:str=Field(min_length=2,max_length=120); email:str; password:str=Field(min_length=8,max_length=128); referral_code:str|None=Field(default=None,max_length=32)
class LoginIn(BaseModel): email:str; password:str
class AdminPasswordLogin(BaseModel): password:str=Field(min_length=10,max_length=128)
class AdminPasswordChange(BaseModel): current_password:str; new_password:str=Field(min_length=10,max_length=128)
class ApplicationIn(BaseModel): role:str; details:str=''
class VariantIn(BaseModel):
    id:int|None=None
    color:str=''
    size:str=''
    size_system:str='none'
    stock:int=Field(ge=0)
    price:float|None=Field(default=None,gt=0)
    foot_length_cm:float|None=Field(default=None,gt=0)
class ProductIn(BaseModel):
    title:str=Field(min_length=2,max_length=180); description:str=''; price:float=Field(gt=0); stock:int=Field(ge=0)
    affiliate_rate:float=Field(ge=0,le=80); platform_rate:float=Field(ge=0,le=30)
    product_type:str='other'; size_system:str='none'; variants:list[VariantIn]=[]
    size_guide:dict={}; images:list[str]=Field(default_factory=list,max_length=4)
class OrderIn(BaseModel):
    product_id:int; quantity:int=Field(ge=1,le=20); customer_name:str; customer_phone:str; address:str
    referral_code:str|None=None; variant_id:int|None=None; coupon_code:str|None=Field(default=None,max_length=40)
class OrderTrackIn(BaseModel):
    order_number:str=Field(min_length=6,max_length=32)
    customer_phone:str=Field(min_length=5,max_length=40)
class PayoutIn(BaseModel): amount:float=Field(gt=0); method:str; destination:str
class ContactIn(BaseModel):
    contact_phone:str|None=Field(default=None,max_length=40)
    contact_whatsapp:str|None=Field(default=None,max_length=40)
    contact_public:bool=False
class ProfileUpdateIn(BaseModel):
    name:str|None=Field(default=None,min_length=2,max_length=120)
    email:str|None=Field(default=None,min_length=5,max_length=190)
    current_password:str|None=None
    new_password:str|None=Field(default=None,min_length=10,max_length=128)
class ContractRequestIn(BaseModel):
    title:str=Field(min_length=3,max_length=180)
    details:str=Field(min_length=20,max_length=5000)
    desired_commission:float|None=Field(default=None,ge=0,le=100)
class ContractRequestDecision(BaseModel):
    decision:str
    admin_note:str=Field(default='',max_length=2000)
class ContractNegotiationIn(BaseModel):
    proposal_text:str=Field(min_length=5,max_length=5000)
    reason:str=Field(default='',max_length=2000)
    recipient_user_id:int|None=None
class ContractNegotiationResponseIn(BaseModel):
    decision:str
    response_text:str=Field(default='',max_length=5000)

@app.get('/')
def home():
    # Never cache the public shell: it contains the current client-side application code.
    return FileResponse('app/static/index.html',headers={'Cache-Control':'no-store, no-cache, must-revalidate, max-age=0','Pragma':'no-cache','Expires':'0'})
@app.get('/control')
def control_page():
    # On Railway, keep administration on its independent service even when the
    # optional override was not configured. Local development retains the local page.
    admin_url=os.getenv('ADMIN_PORTAL_URL','').strip()
    if not admin_url and (os.getenv('RAILWAY_PROJECT_ID') or os.getenv('RAILWAY_SERVICE_ID')):
        admin_url='https://wesla-admin-production.up.railway.app'
    if admin_url:
        return RedirectResponse(admin_url,status_code=307,headers={'Cache-Control':'no-store'})
    return FileResponse('app/static/control.html',headers={'Cache-Control':'no-store, no-cache, must-revalidate, max-age=0','Pragma':'no-cache','Expires':'0'})

@app.post('/api/register')
def register(data:RegisterIn,db:Session=Depends(get_db)):
    email=str(data.email).lower()
    if db.scalar(select(User).where(User.email==email)): raise HTTPException(409,'البريد الإلكتروني مسجل بالفعل')
    referrer=None
    referral_code=(data.referral_code or '').strip().upper()
    if referral_code:
        if not wesla_feature_enabled(db, 'referrals', True): raise HTTPException(409,'برنامج دعوة الأصدقاء متوقف مؤقتًا')
        referrer=db.execute(text("select user_id from wesla_referral_codes where upper(code)=:code"),{'code':referral_code}).first()
        if not referrer: raise HTTPException(400,'كود الدعوة غير صحيح')
    u=User(name=data.name.strip(),email=email,password_hash=hash_password(data.password),role='customer')
    db.add(u)
    db.flush()
    if referrer and int(referrer.user_id)!=u.id:
        db.execute(text("insert into wesla_referrals(referrer_user_id,referred_user_id,referral_code,status) values (:referrer,:referred,:code,'registered') on conflict(referred_user_id) do nothing"),{'referrer':int(referrer.user_id),'referred':u.id,'code':referral_code})
    db.commit()
    db.refresh(u)
    return {'message':'تم إنشاء الحساب. يمكنك التقديم كتاجر أو مسوق.','user':public_user(u)}
@app.post('/api/login')
def login(data:LoginIn,response:Response,db:Session=Depends(get_db)):
    u=db.scalar(select(User).where(User.email==str(data.email).lower()))
    if not u or not verify_password(data.password,u.password_hash): raise HTTPException(401,'بيانات الدخول غير صحيحة')
    if u.status!='active': raise HTTPException(403,'الحساب غير نشط')
    token=secrets.token_urlsafe(32); db.add(AuthSession(token_hash=hashlib.sha256(token.encode()).hexdigest(),user_id=u.id,expires_at=datetime.now(timezone.utc)+timedelta(days=7))); db.commit()
    set_session_cookie(response,token,60*60*24*7)
    return {'user':public_user(u)}
def send_password_reset_email(email,code):
    api_key=os.getenv('RESEND_API_KEY','').strip()
    sender=os.getenv('RESEND_FROM_EMAIL','').strip()
    if not api_key or not sender:
        return False
    payload=json.dumps({'from':sender,'to':[email],'subject':'رمز إعادة تعيين كلمة المرور - وصلة',
        'text':f'رمز إعادة تعيين كلمة المرور لحسابك في وصلة هو: {code}\\nصلاحية الرمز 15 دقيقة، ولا تشاركه مع أي شخص.'}).encode()
    req=urllib.request.Request('https://api.resend.com/emails',data=payload,
        headers={'Authorization':'Bearer '+api_key,'Content-Type':'application/json'},method='POST')
    try:
        with urllib.request.urlopen(req,timeout=10) as response:
            return 200 <= response.status < 300
    except (urllib.error.URLError,TimeoutError):
        return False

@app.post('/api/password/forgot')
def forgot_password(data:ForgotPasswordIn,db:Session=Depends(get_db)):
    generic={'message':'لو البريد الإلكتروني مسجل ومزود البريد مفعل، هيوصلك رمز صالح لمدة 15 دقيقة.'}
    email=data.email.strip().lower()
    user=db.scalar(select(User).where(User.email==email,User.status=='active'))
    if not user: return generic
    code=secrets.token_urlsafe(24)
    token_hash=hashlib.sha256(code.encode()).hexdigest()
    now_utc=datetime.now(timezone.utc)
    try:
        sent=send_password_reset_email(email,code)
        if not sent: return generic
        for old in db.scalars(select(PasswordResetToken).where(PasswordResetToken.user_id==user.id,PasswordResetToken.consumed_at.is_(None))).all():
            old.consumed_at=now_utc
        db.add(PasswordResetToken(user_id=user.id,token_hash=token_hash,expires_at=now_utc+timedelta(minutes=15)))
        db.commit()
    except Exception:
        db.rollback()
    return generic

@app.post('/api/password/reset')
def reset_password(data:ResetPasswordIn,db:Session=Depends(get_db)):
    email=data.email.strip().lower()
    user=db.scalar(select(User).where(User.email==email,User.status=='active'))
    if not user: raise HTTPException(400,'رمز إعادة التعيين غير صحيح أو منتهي الصلاحية')
    token_hash=hashlib.sha256(data.code.encode()).hexdigest()
    now_utc=datetime.now(timezone.utc)
    token=db.scalar(select(PasswordResetToken).where(PasswordResetToken.user_id==user.id,
        PasswordResetToken.token_hash==token_hash,PasswordResetToken.consumed_at.is_(None),
        PasswordResetToken.expires_at>now_utc).order_by(PasswordResetToken.created_at.desc()).with_for_update())
    if not token: raise HTTPException(400,'رمز إعادة التعيين غير صحيح أو منتهي الصلاحية')
    user.password_hash=hash_password(data.new_password)
    token.consumed_at=now_utc
    db.commit()
    return {'message':'تم تغيير كلمة المرور بنجاح. يمكنك تسجيل الدخول بكلمة المرور الجديدة.'}

@app.post('/api/admin/password-login')
def admin_password_login(data:AdminPasswordLogin,response:Response,db:Session=Depends(get_db)):
    admins=db.scalars(select(User).where(User.role=='admin',User.status=='active').order_by(User.id.asc())).all()
    admin=next((u for u in admins if verify_password(data.password,u.password_hash)),None)
    if not admin: raise HTTPException(401,'كلمة مرور الإدارة غير صحيحة')
    token=secrets.token_urlsafe(32)
    db.add(AuthSession(token_hash=hashlib.sha256(token.encode()).hexdigest(),user_id=admin.id,expires_at=datetime.now(timezone.utc)+timedelta(hours=12)))
    db.commit()
    set_session_cookie(response,token,60*60*12)
    return {'user':public_user(admin)}

@app.post('/api/admin/change-password')
def admin_change_password(data:AdminPasswordChange,request:Request,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    if not verify_password(data.current_password,user.password_hash):
        raise HTTPException(401,'كلمة المرور الحالية غير صحيحة')
    user.password_hash=hash_password(data.new_password)
    token=request.cookies.get('wesla_session')
    current_hash=hashlib.sha256(token.encode()).hexdigest() if token else None
    sessions=db.scalars(select(AuthSession).where(AuthSession.user_id==user.id)).all()
    for session in sessions:
        if session.token_hash!=current_hash:
            db.delete(session)
    db.commit()
    return {'message':'تم تغيير كلمة مرور الإدارة بنجاح'}

@app.post('/api/logout')
def logout(response:Response,request:Request,db:Session=Depends(get_db)):
    token=request.cookies.get('wesla_session')
    if token:
        session=db.scalar(select(AuthSession).where(AuthSession.token_hash==hashlib.sha256(token.encode()).hexdigest()))
        if session: db.delete(session); db.commit()
    response.delete_cookie('wesla_session'); return {'ok':True}
@app.get('/api/me')
def me(user:User=Depends(current_user)): return {'user':public_user(user)}

@app.patch('/api/me/contact')
def update_contact(data:ContactIn,user:User=Depends(current_user),db:Session=Depends(get_db)):
    phone=(data.contact_phone or '').strip() or None
    whatsapp=(data.contact_whatsapp or '').strip() or None
    if data.contact_public and not (phone or whatsapp):
        raise HTTPException(400,'أضف رقم هاتف أو واتساب قبل إظهار بيانات التواصل')
    user.contact_phone=phone; user.contact_whatsapp=whatsapp; user.contact_public=data.contact_public
    db.commit(); db.refresh(user)
    return {'message':'تم حفظ بيانات التواصل','user':public_user(user)}

@app.patch('/api/me/profile')
def update_profile(data:ProfileUpdateIn,request:Request,user:User=Depends(current_user),db:Session=Depends(get_db)):
    if data.name is not None:
        name=data.name.strip()
        if len(name)<2: raise HTTPException(400,'الاسم يجب ألا يقل عن حرفين')
        user.name=name
    if data.email is not None:
        email=data.email.strip().lower()
        if '@' not in email or '.' not in email.split('@')[-1]:
            raise HTTPException(400,'البريد الإلكتروني غير صحيح')
        existing=db.scalar(select(User).where(User.email==email,User.id!=user.id))
        if existing: raise HTTPException(409,'البريد الإلكتروني مستخدم بالفعل')
        user.email=email
    if data.new_password is not None:
        if not data.current_password or not verify_password(data.current_password,user.password_hash):
            raise HTTPException(401,'كلمة المرور الحالية غير صحيحة')
        user.password_hash=hash_password(data.new_password)
        token=request.cookies.get('wesla_session')
        current_hash=hashlib.sha256(token.encode()).hexdigest() if token else None
        for session in db.scalars(select(AuthSession).where(AuthSession.user_id==user.id)).all():
            if session.token_hash!=current_hash: db.delete(session)
    elif data.current_password:
        raise HTTPException(400,'أدخل كلمة المرور الجديدة أيضًا')
    db.commit(); db.refresh(user)
    return {'message':'تم تحديث بيانات الحساب بنجاح','user':public_user(user)}

def notify_user(db,user_id,title,body='',target_url=''):
    db.add(Notification(user_id=user_id,title=title,body=body,target_url=target_url))

@app.get('/api/notifications/my')
def my_notifications(limit:int=Query(default=30,ge=1,le=100),user:User=Depends(current_user),db:Session=Depends(get_db)):
    rows=db.scalars(select(Notification).where(Notification.user_id==user.id).order_by(Notification.created_at.desc()).limit(limit)).all()
    unread=db.scalar(select(func.count(Notification.id)).where(Notification.user_id==user.id,Notification.read_at.is_(None))) or 0
    return {'unread':unread,'items':[{'id':n.id,'title':n.title,'body':n.body,'target_url':n.target_url,'read':n.read_at is not None,'created_at':n.created_at.isoformat()} for n in rows]}

@app.post('/api/notifications/{notification_id}/read')
def read_notification(notification_id:int,user:User=Depends(current_user),db:Session=Depends(get_db)):
    n=db.get(Notification,notification_id)
    if not n or n.user_id!=user.id: raise HTTPException(404,'الإشعار غير موجود')
    if n.read_at is None: n.read_at=datetime.now(timezone.utc); db.commit()
    return {'ok':True}
@app.post('/api/applications')
def apply(data:ApplicationIn,user:User=Depends(current_user),db:Session=Depends(get_db)):
    if data.role not in ('merchant','affiliate'): raise HTTPException(400,'نوع الحساب غير صحيح')
    if user.role in ('admin',data.role): raise HTTPException(409,'حسابك لديه هذه الصلاحية بالفعل')
    old=db.scalar(select(Application).where(Application.user_id==user.id,Application.requested_role==data.role,Application.status=='pending'))
    if old: raise HTTPException(409,'لديك طلب قيد المراجعة بالفعل')
    a=Application(user_id=user.id,requested_role=data.role,details=data.details); db.add(a); db.commit(); return {'message':'تم إرسال طلبك للإدارة للمراجعة'}
@app.get('/api/products')
def products(response:Response,limit:int=Query(default=48,ge=1,le=100),offset:int=Query(default=0,ge=0),db:Session=Depends(get_db)):
    rows=db.scalars(select(Product).join(User, User.id==Product.merchant_id).where(Product.status=='active', User.status=='active', User.role=='merchant').order_by(Product.created_at.desc(),Product.id.desc()).limit(limit).offset(offset)).all()
    # Public catalogue returns only buyer-facing product data, never internal commission settings.
    public=products_out(rows,db)
    for item in public:
        item.pop('affiliate_rate',None)
        item.pop('platform_rate',None)
        item.pop('status',None)
    response.headers['Cache-Control']='public, max-age=10, stale-while-revalidate=30'
    return public
@app.get('/api/public/product-images/{image_id}')
def public_product_image(image_id:int,db:Session=Depends(get_db)):
    image_row=db.get(ProductImage,image_id)
    if not image_row: raise HTTPException(404,'الصورة غير موجودة')
    try:
        header,payload=image_row.storage_path.split(',',1)
        mime=header.removeprefix('data:').removesuffix(';base64')
        if mime not in ('image/jpeg','image/png','image/webp'): raise ValueError('invalid mime')
        raw=base64.b64decode(payload,validate=True)
    except Exception: raise HTTPException(404,'ملف الصورة غير صالح')
    return Response(content=raw,media_type=mime,headers={'Cache-Control':'public, max-age=31536000, immutable'})

@app.post('/api/merchant/products')
def add_product(data:ProductIn,user:User=Depends(require_role('merchant','admin')),db:Session=Depends(get_db)):
    platform_rate=data.platform_rate if user.role=='admin' else float(os.getenv('PLATFORM_RATE_DEFAULT','5'))
    if data.product_type not in ('mens_clothing','womens_clothing','kids_clothing','mens_shoes','womens_shoes','kids_shoes','other'): raise HTTPException(400,'نوع المنتج غير صحيح')
    if data.variants and data.product_type=='other': raise HTTPException(400,'المنتجات الأخرى لا تحتاج إلى مقاسات')
    p=Product(merchant_id=user.id,title=data.title,description=data.description,price=data.price,stock=sum(v.stock for v in data.variants) if data.variants else data.stock,affiliate_rate=data.affiliate_rate,platform_rate=platform_rate,product_type=data.product_type,size_system=data.size_system,has_variants=bool(data.variants))
    db.add(p); db.flush()
    for v in data.variants:
        db.add(ProductVariant(product_id=p.id,color=v.color.strip(),size_label=v.size.strip(),size_system=v.size_system,stock=v.stock,price_override=v.price,foot_length_cm=v.foot_length_cm))
    if data.size_guide: db.add(ProductSizeGuide(product_id=p.id,label='دليل المقاسات',measurements=data.size_guide))
    save_product_images(p.id,data.images,db)
    db.commit(); db.refresh(p); return product_out(p,db)
@app.get('/api/merchant/products')
def my_products(limit:int=Query(default=100,ge=1,le=200),offset:int=Query(default=0,ge=0),user:User=Depends(require_role('merchant','admin')),db:Session=Depends(get_db)):
    rows=db.scalars(select(Product).where(Product.merchant_id==user.id).order_by(Product.created_at.desc(),Product.id.desc()).limit(limit).offset(offset)).all()
    return products_out(rows,db)
@app.patch('/api/merchant/products/{product_id}/variants')
def update_product_variants(product_id:int,variants:list[VariantIn],user:User=Depends(require_role('merchant','admin')),db:Session=Depends(get_db)):
    p=db.get(Product,product_id)
    if not p or (user.role!='admin' and p.merchant_id!=user.id): raise HTTPException(404,'المنتج غير موجود')
    existing=db.scalars(select(ProductVariant).where(ProductVariant.product_id==p.id)).all()
    keep=set()
    for data in variants:
        v=db.get(ProductVariant,data.id) if data.id else None
        if v and v.product_id!=p.id: raise HTTPException(400,'تركيبة المخزون لا تتبع هذا المنتج')
        if not v: v=ProductVariant(product_id=p.id); db.add(v)
        v.color=data.color.strip(); v.size_label=data.size.strip(); v.size_system=data.size_system
        v.stock=data.stock; v.price_override=data.price; v.foot_length_cm=data.foot_length_cm
        db.flush(); keep.add(v.id)
    for v in existing:
        if v.id not in keep: v.stock=0
    p.has_variants=bool(variants); p.stock=sum(v.stock for v in db.scalars(select(ProductVariant).where(ProductVariant.product_id==p.id)).all())
    # Restore sold-out products automatically when the merchant adds stock again.
    p.status='active' if p.stock>0 else 'sold_out'
    db.commit(); return product_out(p,db)

@app.get('/api/merchant/products/{product_id}')
def merchant_product_detail(product_id:int,user:User=Depends(require_role('merchant','admin')),db:Session=Depends(get_db)):
    p=db.get(Product,product_id)
    if not p or (user.role!='admin' and p.merchant_id!=user.id): raise HTTPException(404,'المنتج غير موجود')
    return product_out(p,db)

@app.get('/api/public/stores/{user_id}')
def public_store(user_id:int,response:Response,limit:int=Query(default=48,ge=1,le=100),offset:int=Query(default=0,ge=0),db:Session=Depends(get_db)):
    owner=db.get(User,user_id)
    if not owner or owner.role!='merchant' or owner.status!='active': raise HTTPException(404,'المتجر غير موجود')
    rows=db.scalars(select(Product).join(User, User.id==Product.merchant_id).where(Product.merchant_id==owner.id,Product.status=='active',User.status=='active').order_by(Product.created_at.desc(),Product.id.desc()).limit(limit).offset(offset)).all()
    items=products_out(rows,db)
    for item in items:
        item.pop('affiliate_rate',None); item.pop('platform_rate',None); item.pop('status',None)
    response.headers['Cache-Control']='public, max-age=30, stale-while-revalidate=120'
    return {'id':owner.id,'name':owner.name,'products':items,'contact_phone':owner.contact_phone if owner.contact_public else None,'contact_whatsapp':owner.contact_whatsapp if owner.contact_public else None}

@app.get('/api/public/marketers/{user_id}')
def public_marketer(user_id:int,response:Response,limit:int=Query(default=48,ge=1,le=100),offset:int=Query(default=0,ge=0),db:Session=Depends(get_db)):
    owner=db.get(User,user_id)
    if not owner or owner.role!='affiliate' or owner.status!='active': raise HTTPException(404,'صفحة المسوق غير موجودة')
    excluded=select(AffiliateProductExclusion.product_id).where(AffiliateProductExclusion.affiliate_id==owner.id)
    rows=db.execute(select(Link,Product).join(Product,Product.id==Link.product_id).where(Link.affiliate_id==owner.id,Product.status=='active',Product.id.not_in(excluded)).order_by(Link.created_at.desc()).limit(limit).offset(offset)).all()
    products=products_out([p for _,p in rows],db)
    for item in products:
        item.pop('affiliate_rate',None); item.pop('platform_rate',None); item.pop('status',None)
    links_by_product={link.product_id:link for link,_ in rows}
    for item in products:
        link=links_by_product[item['id']]
        item['referral_url']=f"/r/{link.code}"; item['clicks']=link.clicks
    response.headers['Cache-Control']='public, max-age=30, stale-while-revalidate=120'
    return {'id':owner.id,'name':owner.name,'products':products,'contact_phone':owner.contact_phone if owner.contact_public else None,'contact_whatsapp':owner.contact_whatsapp if owner.contact_public else None}

@app.get('/store/{user_id}')
def store_page(user_id:int): return FileResponse('app/static/index.html')
@app.get('/marketer/{user_id}')
def marketer_page(user_id:int): return FileResponse('app/static/index.html')
@app.get('/p/{product_id}')
def product_share_page(product_id:int): return RedirectResponse(url=f'/?product={product_id}',status_code=302)

def soft_delete_product(product:Product,actor:User,db:Session,reason:str=''):
    if product.status=='deleted': raise HTTPException(409,'المنتج محذوف بالفعل')
    active_order=db.scalar(select(Order.id).where(Order.product_id==product.id,Order.status.in_(['pending','confirmed','shipped'])).limit(1))
    if active_order: raise HTTPException(409,'لا يمكن حذف المنتج لوجود طلبات نشطة مرتبطة به')
    product.status='deleted'; product.deleted_at=datetime.now(timezone.utc)
    product.deleted_by=actor.id; product.deleted_by_role=actor.role; product.deleted_reason=reason[:2000]
    db.add(ProductAuditEvent(product_id=product.id,actor_user_id=actor.id,action='soft_deleted',details={'role':actor.role,'reason':reason[:2000]}))

@app.delete('/api/merchant/products/{product_id}')
def merchant_delete_product(product_id:int,user:User=Depends(require_role('merchant')),db:Session=Depends(get_db)):
    product=db.get(Product,product_id)
    if not product or product.merchant_id!=user.id: raise HTTPException(404,'المنتج غير موجود')
    soft_delete_product(product,user,db,'حذف بواسطة التاجر')
    db.commit(); return {'message':'تم نقل المنتج إلى المحذوفات المؤقتة'}

@app.post('/api/merchant/products/{product_id}/restore')
def merchant_restore_product(product_id:int,user:User=Depends(require_role('merchant')),db:Session=Depends(get_db)):
    product=db.get(Product,product_id)
    if not product or product.merchant_id!=user.id or product.status!='deleted':
        raise HTTPException(404,'المنتج المحذوف غير موجود')
    if product.stock<=0: raise HTTPException(409,'أضف مخزونًا قبل استعادة المنتج')
    product.status='active'; product.deleted_at=None; product.deleted_by=None; product.deleted_by_role=None; product.deleted_reason=''
    db.add(ProductAuditEvent(product_id=product.id,actor_user_id=user.id,action='restored',details={'role':user.role}))
    db.commit(); return {'message':'تمت استعادة المنتج ونشره من جديد'}

@app.delete('/api/admin/products/{product_id}')
def admin_delete_product(product_id:int,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    product=db.get(Product,product_id)
    if not product: raise HTTPException(404,'المنتج غير موجود')
    soft_delete_product(product,user,db,'حذف إداري')
    db.commit(); return {'message':'تم إخفاء المنتج وتسجيل العملية في سجل المراجعة'}

@app.post('/api/admin/products/{product_id}/restore')
def admin_restore_product(product_id:int,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    product=db.get(Product,product_id)
    if not product or product.status!='deleted': raise HTTPException(404,'المنتج المحذوف غير موجود')
    product.status='active'; product.deleted_at=None; product.deleted_by=None; product.deleted_by_role=None; product.deleted_reason=''
    db.add(ProductAuditEvent(product_id=product.id,actor_user_id=user.id,action='restored',details={}))
    db.commit(); return {'message':'تمت استعادة المنتج'}

@app.get('/api/admin/products')
def admin_products(limit:int=Query(default=100,ge=1,le=200),offset:int=Query(default=0,ge=0),user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    rows=db.scalars(select(Product).order_by(Product.created_at.desc(),Product.id.desc()).limit(limit).offset(offset)).all()
    items=products_out(rows,db)
    product_by_id={p.id:p for p in rows}
    for item in items:
        product=product_by_id[item['id']]
        item['deleted_at']=product.deleted_at.isoformat() if product.deleted_at else None
        item['deleted_by_role']=product.deleted_by_role
    return items

@app.delete('/api/affiliate/products/{product_id}')
def affiliate_hide_product(product_id:int,user:User=Depends(require_role('affiliate')),db:Session=Depends(get_db)):
    product=db.get(Product,product_id)
    if not product or product.status!='active': raise HTTPException(404,'المنتج غير موجود')
    old=db.scalar(select(AffiliateProductExclusion).where(AffiliateProductExclusion.affiliate_id==user.id,AffiliateProductExclusion.product_id==product.id))
    if not old:
        db.add(AffiliateProductExclusion(affiliate_id=user.id,product_id=product.id))
        db.add(ProductAuditEvent(product_id=product.id,actor_user_id=user.id,action='hidden_by_affiliate',details={'affiliate_id':user.id}))
    db.commit(); return {'message':'تمت إزالة المنتج من قائمتك التسويقية فقط، ولم يُحذف من متجر التاجر'}

@app.get('/api/affiliate/products')
def affiliate_available_products(limit:int=Query(default=48,ge=1,le=100),offset:int=Query(default=0,ge=0),user:User=Depends(require_role('affiliate')),db:Session=Depends(get_db)):
    excluded=select(AffiliateProductExclusion.product_id).where(AffiliateProductExclusion.affiliate_id==user.id)
    rows=db.scalars(select(Product).where(Product.status=='active',Product.id.not_in(excluded)).order_by(Product.created_at.desc(),Product.id.desc()).limit(limit).offset(offset)).all()
    items=products_out(rows,db)
    for item in items:
        item.pop('affiliate_rate',None); item.pop('platform_rate',None); item.pop('status',None)
    return items

@app.post('/api/affiliate/links/{product_id}')
def create_link(product_id:int,user:User=Depends(require_role('affiliate','admin')),db:Session=Depends(get_db)):
    p=db.get(Product,product_id)
    if not p or p.status!='active': raise HTTPException(404,'المنتج غير موجود')
    hidden=db.scalar(select(AffiliateProductExclusion).where(AffiliateProductExclusion.affiliate_id==user.id,AffiliateProductExclusion.product_id==product_id))
    if hidden: db.delete(hidden)
    link=db.scalar(select(Link).where(Link.affiliate_id==user.id,Link.product_id==product_id))
    if not link:
        link=Link(code=secrets.token_urlsafe(8),affiliate_id=user.id,product_id=product_id); db.add(link); db.commit(); db.refresh(link)
    return {'code':link.code,'url':f"/r/{link.code}",'clicks':link.clicks}
@app.get('/r/{code}')
def track(code:str,request:Request,db:Session=Depends(get_db)):
    link=db.scalar(select(Link).where(Link.code==code));
    if not link: raise HTTPException(404,'رابط الإحالة غير صحيح')
    link.clicks+=1; db.commit()
    response=RedirectResponse(url=f'/?product={link.product_id}',status_code=302)
    response.set_cookie('wesla_ref',code,httponly=True,samesite='lax',max_age=60*60*24*30)
    return response
@app.post('/api/orders')
def create_order(data:OrderIn,request:Request,db:Session=Depends(get_db)):
    p=db.scalar(select(Product).where(Product.id==data.product_id).with_for_update())
    if not p or p.status!='active': raise HTTPException(404,'المنتج غير متاح')
    variant=None
    if p.has_variants:
        if not data.variant_id: raise HTTPException(400,'اختر اللون والمقاس أولاً')
        variant=db.scalar(select(ProductVariant).where(ProductVariant.id==data.variant_id,ProductVariant.product_id==p.id).with_for_update())
        if not variant or variant.product_id!=p.id: raise HTTPException(400,'اختيار المقاس غير صحيح')
        if variant.stock<data.quantity: raise HTTPException(409,'الكمية غير متاحة لهذا اللون والمقاس')
    elif p.stock<data.quantity: raise HTTPException(409,'الكمية المطلوبة غير متاحة حالياً')
    code=data.referral_code or request.cookies.get('wesla_ref'); link=db.scalar(select(Link).where(Link.code==code)) if code else None
    affiliate_id=link.affiliate_id if link and link.product_id==p.id else None
    customer_user_id=None
    session_token=request.cookies.get('wesla_session')
    if session_token:
        active_session=db.scalar(select(AuthSession).where(AuthSession.token_hash==hashlib.sha256(session_token.encode()).hexdigest()))
        if active_session:
            customer=db.get(User,active_session.user_id)
            if customer and customer.status=='active' and customer.role=='customer':
                customer_user_id=customer.id
    chosen_price=variant.price_override if variant and variant.price_override is not None else p.price
    subtotal=(Decimal(chosen_price)*data.quantity).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    coupon=None; discount=Decimal('0.00')
    if data.coupon_code and data.coupon_code.strip():
        coupon=db.scalar(select(Coupon).where(Coupon.code==data.coupon_code.strip().upper()).with_for_update())
        now_utc=datetime.now(timezone.utc)
        if not coupon or not coupon.is_active or (coupon.starts_at and coupon.starts_at>now_utc) or (coupon.ends_at and coupon.ends_at<=now_utc):
            raise HTTPException(400,'كود الخصم غير صالح أو غير نشط')
        if coupon.usage_limit is not None and coupon.used_count>=coupon.usage_limit:
            raise HTTPException(400,'انتهى عدد مرات استخدام كود الخصم')
        if subtotal<Decimal(coupon.min_order_total):
            raise HTTPException(400,f'الحد الأدنى للطلب لاستخدام الكود هو {coupon.min_order_total} جنيه')
        discount=(subtotal*Decimal(coupon.discount_value)/Decimal(100)).quantize(Decimal('0.01'),rounding=ROUND_HALF_UP) if coupon.discount_type=='percent' else Decimal(coupon.discount_value)
        if coupon.max_discount is not None: discount=min(discount,Decimal(coupon.max_discount))
        discount=min(discount,subtotal)
    total=(subtotal-discount).quantize(Decimal('0.01'),rounding=ROUND_HALF_UP)
    ac=(total*Decimal(p.affiliate_rate)/Decimal(100)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP) if affiliate_id else Decimal('0.00')
    pc=(total*Decimal(p.platform_rate)/Decimal(100)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    order=Order(order_number='WS'+secrets.token_hex(5).upper(),customer_name=data.customer_name,customer_phone=data.customer_phone,address=data.address,product_id=p.id,merchant_id=p.merchant_id,affiliate_id=affiliate_id,customer_user_id=customer_user_id,quantity=data.quantity,variant_id=variant.id if variant else None,selected_color=variant.color if variant else None,selected_size=variant.size_label if variant else None,unit_price=chosen_price,total=total,coupon_code=coupon.code if coupon else None,discount_amount=discount,affiliate_rate_snapshot=p.affiliate_rate,platform_rate_snapshot=p.platform_rate,affiliate_commission=ac,platform_commission=pc)
    if variant: variant.stock-=data.quantity
    p.stock-=data.quantity
    # Hide the product from all public catalogues as soon as its total stock reaches zero.
    # Keep the product/order history in the database; it can be republished by restocking.
    if p.stock<=0: p.status='sold_out'
    db.add(order)
    db.flush()
    if wesla_feature_enabled(db, 'advanced_order_tracking', False):
        db.execute(text("insert into wesla_order_status_history(order_id,status,actor_role,note) values (:oid,:status,'system','تم استلام الطلب')"), {'oid':order.id,'status':order.status})
    if coupon:
        db.flush(); coupon.used_count+=1
        db.add(CouponRedemption(coupon_id=coupon.id,order_id=order.id,user_id=customer_user_id,discount_amount=discount))
    notify_user(db,p.merchant_id,'طلب جديد على منتجك',f'رقم الطلب {order.order_number} — إجمالي {total} جنيه','/dashboard')
    if affiliate_id:
        notify_user(db,affiliate_id,'طلب جديد من رابطك التسويقي',f'رقم الطلب {order.order_number}. ستظهر عمولتك بعد تأكيد التسليم.','/dashboard')
    db.commit(); db.refresh(order)
    return {'order_number':order.order_number,'status':order.status,'subtotal':subtotal,'discount':discount,'coupon_code':coupon.code if coupon else None,'total':total,'message':'تم تسجيل الطلب. سيتواصل معك التاجر لتأكيده.'}
@app.post('/api/orders/track')
def track_order(data:OrderTrackIn,db:Session=Depends(get_db)):
    row=db.execute(select(Order,Product.title).join(Product,Product.id==Order.product_id).where(Order.order_number==data.order_number.strip().upper(),Order.customer_phone==data.customer_phone.strip())).first()
    if not row: raise HTTPException(404,'بيانات الطلب غير صحيحة. راجع رقم الطلب ورقم الهاتف.')
    order,title=row
    labels={'pending':'تم استلام الطلب','confirmed':'تم تأكيد الطلب','shipped':'الطلب في الطريق إليك','delivered':'تم تسليم الطلب','cancelled':'تم إلغاء الطلب','returned':'تم إرجاع الطلب'}
    timeline=[]
    if wesla_feature_enabled(db, 'advanced_order_tracking', False):
        events=db.execute(text("select status,actor_role,note,created_at from wesla_order_status_history where order_id=:oid order by created_at asc,id asc"), {'oid':order.id}).mappings().all()
        timeline=[{'status':x['status'],'status_label':labels.get(x['status'],x['status']),'actor_role':x['actor_role'],'note':x['note'],'created_at':x['created_at']} for x in events]
    return {'order_number':order.order_number,'product':title,'quantity':order.quantity,'total':float(order.total),'status':order.status,'status_label':labels.get(order.status,order.status),'created_at':order.created_at.isoformat(),'timeline':timeline}

@app.get('/api/affiliate/links')
def affiliate_links(user:User=Depends(require_role('affiliate','admin')),limit:int=Query(default=100,ge=1,le=200),offset:int=Query(default=0,ge=0),db:Session=Depends(get_db)):
    excluded=select(AffiliateProductExclusion.product_id).where(AffiliateProductExclusion.affiliate_id==user.id)
    rows=db.execute(select(Link.code,Link.product_id,Product.title,Link.clicks).join(Product,Product.id==Link.product_id).where(Link.affiliate_id==user.id,Product.id.not_in(excluded)).order_by(Link.created_at.desc()).limit(limit).offset(offset)).all()
    return [{'code':r.code,'product_id':r.product_id,'product':r.title,'clicks':r.clicks} for r in rows]
@app.get('/api/affiliate/dashboard')
def affiliate_dashboard(user:User=Depends(require_role('affiliate','admin')),db:Session=Depends(get_db)):
    excluded=select(AffiliateProductExclusion.product_id).where(AffiliateProductExclusion.affiliate_id==user.id)
    links=db.execute(select(Link.code,Link.product_id,Product.title,Link.clicks).join(Product,Product.id==Link.product_id).where(Link.affiliate_id==user.id,Product.id.not_in(excluded)).order_by(Link.created_at.desc()).limit(100)).all()
    orders=db.scalars(select(Order).where(Order.affiliate_id==user.id).order_by(Order.created_at.desc()).limit(100)).all()
    pending=db.scalar(select(func.coalesce(func.sum(Order.affiliate_commission),0)).where(Order.affiliate_id==user.id,Order.status.in_(['pending','confirmed','shipped']))) or 0
    approved=db.scalar(select(func.coalesce(func.sum(Order.affiliate_commission),0)).where(Order.affiliate_id==user.id,Order.status=='delivered')) or 0
    return {'links':[{'code':r.code,'product_id':r.product_id,'product':r.title,'clicks':r.clicks} for r in links],'orders':[{'order_number':o.order_number,'total':o.total,'commission':o.affiliate_commission,'status':o.status} for o in orders],'pending':round(float(pending),2),'approved':round(float(approved),2)}
@app.post('/api/affiliate/payouts')
def payout(data:PayoutIn,user:User=Depends(require_role('affiliate','admin')),db:Session=Depends(get_db)):
    earned=db.scalar(select(func.coalesce(func.sum(Order.affiliate_commission),0)).where(Order.affiliate_id==user.id,Order.status=='delivered')) or 0
    paid=db.scalar(select(func.coalesce(func.sum(Payout.amount),0)).where(Payout.affiliate_id==user.id,Payout.status.in_(['approved','paid']))) or 0
    pending=db.scalar(select(func.coalesce(func.sum(Payout.amount),0)).where(Payout.affiliate_id==user.id,Payout.status=='pending')) or 0
    if Decimal(str(data.amount))>Decimal(str(earned))-Decimal(str(paid))-Decimal(str(pending)): raise HTTPException(400,'المبلغ يتجاوز رصيدك القابل للسحب')
    p=Payout(affiliate_id=user.id,amount=Decimal(str(data.amount)),method=data.method,destination=data.destination); db.add(p); db.flush(); db.add(WalletTransaction(user_id=user.id,amount=-Decimal(str(data.amount)),kind='payout_reserve',reference_type='payout',reference_id=p.id,description='حجز مبلغ طلب السحب')); db.commit(); return {'message':'تم إرسال طلب السحب للإدارة'}
@app.get('/api/merchant/orders')
def merchant_orders(limit:int=Query(default=100,ge=1,le=200),offset:int=Query(default=0,ge=0),user:User=Depends(require_role('merchant','admin')),db:Session=Depends(get_db)):
    rows=db.execute(select(Order,Product.title).join(Product,Product.id==Order.product_id).where(Order.merchant_id==user.id).order_by(Order.created_at.desc()).limit(limit).offset(offset)).all()
    return [{'order_number':o.order_number,'customer_name':o.customer_name,'customer_phone':o.customer_phone,'address':o.address,'product':title,'quantity':o.quantity,'color':o.selected_color,'size':o.selected_size,'total':o.total,'status':o.status,'affiliate_commission':float(o.affiliate_commission or 0) if o.status=='delivered' else None,'platform_commission':float(o.platform_commission or 0) if o.status=='delivered' else None,'merchant_net':round(float(o.total or 0)-float(o.affiliate_commission or 0)-float(o.platform_commission or 0),2) if o.status=='delivered' else None} for o,title in rows]
@app.get('/api/merchant/orders/{order_number}/history')
def merchant_order_history(order_number: str, user: User = Depends(require_role('merchant','admin')), db: Session = Depends(get_db)):
    query = select(Order).where(Order.order_number == order_number)
    if user.role != 'admin':
        query = query.where(Order.merchant_id == user.id)
    order = db.scalar(query)
    if not order:
        raise HTTPException(404, 'الطلب غير موجود')
    if not wesla_feature_enabled(db, 'advanced_order_tracking', False):
        return []
    rows = db.execute(text("select status,actor_role,note,created_at from wesla_order_status_history where order_id=:oid order by created_at asc,id asc"), {'oid':order.id}).mappings().all()
    labels = {'pending':'تم استلام الطلب','confirmed':'تم تأكيد الطلب','shipped':'الطلب في الطريق إليك','delivered':'تم تسليم الطلب','cancelled':'تم إلغاء الطلب','returned':'تم إرجاع الطلب'}
    return [{'status':x['status'],'status_label':labels.get(x['status'],x['status']),'actor_role':x['actor_role'],'note':x['note'],'created_at':x['created_at']} for x in rows]

@app.post('/api/merchant/orders/{order_number}/status')
def update_order(order_number:str,status:str,user:User=Depends(require_role('merchant','admin')),db:Session=Depends(get_db)):
    if status not in ('confirmed','shipped','delivered','cancelled','returned'): raise HTTPException(400,'حالة الطلب غير صحيحة')
    order_query=select(Order).where(Order.order_number==order_number)
    if user.role!='admin': order_query=order_query.where(Order.merchant_id==user.id)
    o=db.scalar(order_query)
    if not o: raise HTTPException(404,'الطلب غير موجود')
    if o.status in ('cancelled','returned','delivered'): raise HTTPException(409,'لا يمكن تغيير حالة هذا الطلب')
    o.status=status
    if wesla_feature_enabled(db, 'advanced_order_tracking', False):
        db.execute(text("insert into wesla_order_status_history(order_id,status,changed_by_user_id,actor_role,note) values (:oid,:status,:actor,:role,'تحديث حالة الطلب')"), {'oid':o.id,'status':status,'actor':user.id,'role':user.role})
    if status in ('cancelled','returned'):
        p=db.get(Product,o.product_id); p.stock+=o.quantity
        if o.variant_id:
            v=db.get(ProductVariant,o.variant_id)
            if v: v.stock+=o.quantity
        o.affiliate_commission=0; o.platform_commission=0
        notify_user(db,o.merchant_id,'تم إلغاء/إرجاع الطلب',f'الطلب {o.order_number} — تم إلغاء احتساب العمولات.')
        if o.affiliate_id: notify_user(db,o.affiliate_id,'تم إلغاء عمولة طلب',f'الطلب {o.order_number} لم يكتمل، لذلك لن تُحتسب عمولة.')
    elif status=='delivered':
        notify_user(db,o.merchant_id,'تم تسليم الطلب',f'الطلب {o.order_number} تم تسليمه بنجاح. صافي قيمة البيع {round(float(o.total)-float(o.affiliate_commission or 0)-float(o.platform_commission or 0),2)} جنيه.')
        if o.affiliate_id:
            notify_user(db,o.affiliate_id,'عمولتك أصبحت مستحقة',f'تم تسليم الطلب {o.order_number}. عمولتك {o.affiliate_commission} جنيه.')
            if Decimal(str(o.affiliate_commission or 0))>0:
                db.add(WalletTransaction(user_id=o.affiliate_id,amount=Decimal(str(o.affiliate_commission)),kind='commission',reference_type='order',reference_id=o.id,description=f'عمولة الطلب {o.order_number}'))
        if o.customer_user_id:
            reward_cfg=db.execute(text("select config,is_enabled from wesla_feature_settings where feature_key='rewards'")).mappings().first()
            points_per_100=int(((reward_cfg or {}).get('config') or {}).get('purchase_points_per_100_egp',0))
            earned_points=(int(Decimal(str(o.total)) // Decimal('100')) * points_per_100) if reward_cfg and reward_cfg['is_enabled'] else 0
            if earned_points>0:
                db.execute(text("insert into wesla_reward_accounts(user_id) values (:uid) on conflict(user_id) do nothing"),{'uid':o.customer_user_id})
                earned=db.execute(text("""
                  insert into wesla_reward_ledger(user_id,delta,status,event_key,source_type,source_id,description)
                  values (:uid,:points,'posted',:event,'purchase',:order_id,'نقاط شراء بعد تسليم الطلب')
                  on conflict(event_key) do nothing returning id
                """),{'uid':o.customer_user_id,'points':earned_points,'event':'purchase:'+str(o.id),'order_id':o.id}).first()
                if earned:
                    db.execute(text("""
                      update wesla_reward_accounts
                      set points_available=points_available+:points,lifetime_earned=lifetime_earned+:points,
                          tier=case when lifetime_earned+:points>=3000 then 'platinum'
                                    when lifetime_earned+:points>=1500 then 'gold'
                                    when lifetime_earned+:points>=500 then 'silver' else 'basic' end,
                          updated_at=now()
                      where user_id=:uid
                    """),{'uid':o.customer_user_id,'points':earned_points})
                    notify_user(db,o.customer_user_id,'نقاط مكافأة جديدة',f'حصلت على {earned_points} نقطة بعد تسليم الطلب {o.order_number}.')
            # Referral rewards are posted automatically after the invited customer
            # completes their first delivered order. The event key makes this idempotent.
            if wesla_feature_enabled(db, 'referrals', False):
                referral=db.execute(text("""
                  select id,referrer_user_id,status from wesla_referrals
                  where referred_user_id=:uid and status='registered'
                  for update
                """),{'uid':o.customer_user_id}).mappings().first()
                if referral:
                    referral_cfg=db.execute(text("select config,is_enabled from wesla_feature_settings where feature_key='referrals'")).mappings().first()
                    referral_points=int(((referral_cfg or {}).get('config') or {}).get('referral_reward_points',0))
                    if referral_cfg and referral_cfg['is_enabled'] and referral_points>0:
                        referrer_id=int(referral['referrer_user_id'])
                        db.execute(text("insert into wesla_reward_accounts(user_id) values (:uid) on conflict(user_id) do nothing"),{'uid':referrer_id})
                        referral_event='referral:'+str(referral['id'])
                        awarded=db.execute(text("""
                          insert into wesla_reward_ledger(user_id,delta,status,event_key,source_type,source_id,description)
                          values (:uid,:points,'posted',:event,'referral',:rid,'مكافأة دعوة صديق بعد إتمام أول طلب')
                          on conflict(event_key) do nothing returning id
                        """),{'uid':referrer_id,'points':referral_points,'event':referral_event,'rid':referral['id']}).first()
                        if awarded:
                            db.execute(text("""
                              update wesla_reward_accounts
                              set points_available=points_available+:points,lifetime_earned=lifetime_earned+:points,
                                  tier=case when lifetime_earned+:points>=3000 then 'platinum'
                                            when lifetime_earned+:points>=1500 then 'gold'
                                            when lifetime_earned+:points>=500 then 'silver' else 'basic' end,
                                  updated_at=now()
                              where user_id=:uid
                            """),{'points':referral_points,'uid':referrer_id})
                            db.execute(text("update wesla_referrals set status='qualified',reward_points=:points,qualified_at=now() where id=:id"),{'points':referral_points,'id':referral['id']})
                            notify_user(db,referrer_id,'تم احتساب مكافأة دعوة صديق',f'حصلت على {referral_points} نقطة بعد إتمام أول طلب للعميل المدعو.')
        for admin_user in db.scalars(select(User).where(User.role=='admin',User.status=='active')).all():
            notify_user(db,admin_user.id,'عمولة منصة جديدة',f'اكتمل بيع الطلب {o.order_number}. عمولة وصلة {o.platform_commission} جنيه'+(f'، وعمولة المسوق {o.affiliate_commission} جنيه.' if o.affiliate_id else '.'),'/control')
    db.commit(); return {'message':'تم تحديث حالة الطلب. تم تحديث العمولات والإشعارات فورًا.'}
@app.get('/api/admin/users')
def admin_users(limit:int=Query(default=200,ge=1,le=500),offset:int=Query(default=0,ge=0),user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    rows=db.scalars(select(User).where(User.status=='active').order_by(User.name.asc()).limit(limit).offset(offset)).all()
    return [{'id':u.id,'name':u.name,'email':u.email,'role':u.role,'status':u.status} for u in rows]

@app.get('/api/admin/overview')
def admin_overview(user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    delivered=Order.status=='delivered'
    return {'users':db.scalar(select(func.count(User.id))),'products':db.scalar(select(func.count(Product.id)).where(Product.status!='deleted')),'orders':db.scalar(select(func.count(Order.id))),'sales':db.scalar(select(func.coalesce(func.sum(Order.total),0)).where(delivered)),'platform_commission':db.scalar(select(func.coalesce(func.sum(Order.platform_commission),0)).where(delivered)),'affiliate_commission':db.scalar(select(func.coalesce(func.sum(Order.affiliate_commission),0)).where(delivered)),'delivered_orders':db.scalar(select(func.count(Order.id)).where(delivered)),'applications':db.scalar(select(func.count(Application.id)).where(Application.status=='pending')),'payouts':db.scalar(select(func.count(Payout.id)).where(Payout.status=='pending'))}
@app.get('/api/admin/applications')
def admin_applications(user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    rows=db.execute(select(Application,User).join(User,User.id==Application.user_id).where(Application.status=='pending').order_by(Application.created_at.desc()).limit(200)).all()
    return [{'id':a.id,'name':owner.name,'email':owner.email,'role':a.requested_role,'details':a.details,'status':a.status} for a,owner in rows]
@app.post('/api/admin/applications/{app_id}/{decision}')
def decide_application(app_id:int,decision:str,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    if decision not in ('approve','reject'): raise HTTPException(400,'القرار غير صحيح')
    a=db.get(Application,app_id)
    if not a or a.status!='pending': raise HTTPException(404,'الطلب غير موجود أو تمت مراجعته')
    a.status='approved' if decision=='approve' else 'rejected'
    if decision=='approve': db.get(User,a.user_id).role=a.requested_role
    db.commit(); return {'message':'تمت مراجعة الطلب'}
@app.get('/api/admin/orders')
def admin_orders(limit:int=Query(default=200,ge=1,le=500),offset:int=Query(default=0,ge=0),user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    rows=db.scalars(select(Order).order_by(Order.created_at.desc()).limit(limit).offset(offset)).all()
    return [{'order_number':o.order_number,'customer':o.customer_name,'total':float(o.total),'affiliate_commission':float(o.affiliate_commission or 0) if o.status=='delivered' else None,'platform_commission':float(o.platform_commission or 0) if o.status=='delivered' else None,'status':o.status,'commission_status':'مستحقة' if o.status=='delivered' else 'تظهر بعد التسليم'} for o in rows]
@app.get('/api/admin/payouts')
def admin_payouts(limit:int=Query(default=200,ge=1,le=500),offset:int=Query(default=0,ge=0),user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    rows=db.execute(select(Payout,User.name).join(User,User.id==Payout.affiliate_id).where(Payout.status=='pending').order_by(Payout.created_at.desc()).limit(limit).offset(offset)).all()
    return [{'id':p.id,'affiliate':name,'amount':p.amount,'method':p.method,'destination':p.destination,'status':p.status} for p,name in rows]
@app.post('/api/admin/payouts/{payout_id}/{decision}')
def decide_payout(payout_id:int,decision:str,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    if decision not in ('approve','reject','paid'): raise HTTPException(400,'القرار غير صحيح')
    p=db.get(Payout,payout_id)
    if not p or p.status not in ('pending','approved'): raise HTTPException(404,'طلب السحب غير موجود أو تمت مراجعته')
    if decision=='approve' and p.status!='pending': raise HTTPException(409,'تم اعتماد طلب السحب بالفعل')
    if decision=='reject' and p.status not in ('pending','approved'): raise HTTPException(409,'لا يمكن رفض هذا الطلب الآن')
    p.status={'approve':'approved','reject':'rejected','paid':'paid'}[decision]
    if decision=='reject':
        db.add(WalletTransaction(user_id=p.affiliate_id,amount=Decimal(str(p.amount)),kind='payout_refund',reference_type='payout',reference_id=p.id,description='إعادة مبلغ طلب السحب المرفوض'))
    db.commit(); return {'message':'تم تحديث طلب السحب'}


# Electronic agreements. Visual platform marks are not a government certificate or accredited e-signature.
class ContractBrandAssetsIn(BaseModel):
    signature_data_url: str | None = None
    stamp_data_url: str | None = None
    is_active: bool = True
    signature_enabled: bool = True
    stamp_enabled: bool = True
    contract_types: list[str] = Field(default_factory=lambda: ['platform_merchant','platform_affiliate','merchant_affiliate'])

def validate_brand_png(value: str | None, label: str):
    if value is None or value == '':
        return None
    if not isinstance(value,str) or not value.startswith('data:image/png;base64,') or len(value)>2_000_000:
        raise HTTPException(400, f'{label}: ارفع صورة PNG بخلفية شفافة وحجم مناسب')
    try:
        raw=base64.b64decode(value.split(',',1)[1],validate=True)
    except (ValueError,binascii.Error):
        raise HTTPException(400, f'{label}: ملف الصورة غير صالح')
    if not raw.startswith(bytes.fromhex('89504e470d0a1a0a')) or len(raw)>1_500_000:
        raise HTTPException(400, f'{label}: ملف PNG غير صالح أو أكبر من 1.5 ميجابايت')
    return value

class ContractIn(BaseModel):
    contract_type:str
    title:str=Field(min_length=3,max_length=180)
    body:str=Field(min_length=20,max_length=1800)
    merchant_id:int|None=None
    affiliate_id:int|None=None
    participant_ids:list[int]=Field(default_factory=list)
    commission_rate:float|None=Field(default=None,ge=0,le=100)
    penalty_terms:str=Field(default='',max_length=400)
    starts_at:datetime|None=None
    ends_at:datetime|None=None
    legal_entity_name:str=''
    commission_scope:str='contract'
    penalty_type:str|None=None
    penalty_amount:float|None=Field(default=None,ge=0)
    penalty_percent:float|None=Field(default=None,ge=0,le=100)
    termination_terms:str=Field(default='',max_length=400)

class ContractDecision(BaseModel):
    full_name:str=Field(min_length=3,max_length=120)
    accepted:bool
    signature_data_url:str|None=Field(default=None,max_length=2000000)

class AdminContractApproval(BaseModel):
    accepted:bool

class TerminationIn(BaseModel):
    reason:str=Field(min_length=10,max_length=4000)
    evidence_paths:list[str]=[]

class TerminationDecision(BaseModel):
    decision:str
    reason:str=Field(min_length=5,max_length=2000)

class CommissionChangeIn(BaseModel):
    contract_id:int|None=None
    product_id:int|None=None
    new_rate:float=Field(ge=0,le=100)
    affected_user_id:int

def contract_event(db,c,actor,event,details=None):
    db.add(ContractEvent(contract_id=c.id,actor_user_id=actor.id if actor else None,event_type=event,details=details or {}))

def contract_snapshot_data(c):
    return {
        'number':c.contract_number,'version':c.version,'type':c.contract_type,'title':c.title,'body':c.body,
        'merchant_id':c.merchant_id,'affiliate_id':c.affiliate_id,'participant_ids':list(c.participant_ids or []),
        'commission_rate':str(c.commission_rate) if c.commission_rate is not None else None,
        'commission_scope':c.commission_scope,'penalty_terms':c.penalty_terms,
        'penalty_type':c.penalty_type,'penalty_amount':str(c.penalty_amount) if c.penalty_amount is not None else None,
        'penalty_percent':str(c.penalty_percent) if c.penalty_percent is not None else None,
        'termination_terms':c.termination_terms,'legal_entity_name':c.legal_entity_name,
        'platform_signer_name':c.platform_signer_name,
        'brand_signature_snapshot':c.brand_signature_snapshot,
        'brand_stamp_snapshot':c.brand_stamp_snapshot,
        'brand_assets_version':c.brand_assets_version,
        'starts_at':c.starts_at.isoformat() if c.starts_at else None,
        'ends_at':c.ends_at.isoformat() if c.ends_at else None,
        'created_at':c.created_at.isoformat() if c.created_at else None,
    }

def stable_contract_json(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))

def acceptance_evidence_hash(snapshot_hash,user,full_name,accepted_at,ip_address,user_agent,session_fingerprint,signature_hash=''):
    evidence={
        'snapshot_hash':snapshot_hash,'user_id':user.id,'account_email':user.email,
        'account_name':user.name,'accepted_name':full_name,'accepted_at':accepted_at.isoformat(),
        'ip_address':ip_address,'user_agent':user_agent,'session_fingerprint':session_fingerprint,
        'method':'authenticated_explicit_consent','signature_hash':signature_hash,
    }
    return hashlib.sha256(stable_contract_json(evidence).encode()).hexdigest(),evidence

def finalize_contract(db,c,actor):
    snapshot=contract_snapshot_data(c)
    snapshot_json=stable_contract_json(snapshot)
    snapshot_hash=hashlib.sha256(snapshot_json.encode()).hexdigest()
    acceptances=db.scalars(select(ContractAcceptance).where(ContractAcceptance.contract_id==c.id).order_by(ContractAcceptance.user_id)).all()
    hashes=sorted(a.document_hash for a in acceptances)
    c.status='signed'
    c.approved_at=datetime.now(timezone.utc)
    c.final_hash=hashlib.sha256((snapshot_json+'|'+'|'.join(hashes)).encode()).hexdigest()
    contract_event(db,c,actor,'contract_finalized',{
        'snapshot':snapshot,'snapshot_hash':snapshot_hash,'acceptance_hashes':hashes,
        'final_hash':c.final_hash,'version':c.version,'method':'authenticated_explicit_consent',
    })

def contract_party_ids(c):
    ids=[]
    if c.contract_type in ('platform_merchant','merchant_affiliate') and c.merchant_id: ids.append(c.merchant_id)
    if c.contract_type in ('platform_affiliate','merchant_affiliate') and c.affiliate_id: ids.append(c.affiliate_id)
    ids.extend(int(x) for x in (c.participant_ids or []) if str(x).isdigit())
    return list(dict.fromkeys(ids))

def can_view_contract(c,user):
    return user.role=='admin' or user.id in contract_party_ids(c)

def contract_out(c,db):
    merchant=db.get(User,c.merchant_id) if c.merchant_id else None
    affiliate=db.get(User,c.affiliate_id) if c.affiliate_id else None
    accepts=db.scalars(select(ContractAcceptance).where(ContractAcceptance.contract_id==c.id)).all()
    events=db.scalars(select(ContractEvent).where(ContractEvent.contract_id==c.id).order_by(ContractEvent.created_at)).all()
    return {'id':c.id,'contract_number':c.contract_number,'version':c.version,'contract_type':c.contract_type,'title':c.title,'body':c.body,
      'merchant_id':c.merchant_id,'merchant_name':merchant.name if merchant else None,
      'affiliate_id':c.affiliate_id,'affiliate_name':affiliate.name if affiliate else None,
      'participant_ids':list(c.participant_ids or []),'participants':[{'id':uid,'name':db.get(User,uid).name,'email':db.get(User,uid).email,'role':db.get(User,uid).role} for uid in contract_party_ids(c) if db.get(User,uid)],
      'commission_rate':c.commission_rate,'commission_scope':c.commission_scope,'penalty_terms':c.penalty_terms,
      'penalty_type':c.penalty_type,'penalty_amount':c.penalty_amount,'penalty_percent':c.penalty_percent,
      'termination_terms':c.termination_terms,'legal_entity_name':c.legal_entity_name,
      'starts_at':c.starts_at.isoformat() if c.starts_at else None,'ends_at':c.ends_at.isoformat() if c.ends_at else None,
      'approved_at':c.approved_at.isoformat() if c.approved_at else None,'platform_signer_name':c.platform_signer_name,
      'final_hash':c.final_hash,'status':c.status,'created_at':c.created_at.isoformat(),
      'acceptances':[{'user_id':a.user_id,'full_name':a.full_name,'accepted_at':a.accepted_at.isoformat(),'document_hash':a.document_hash,'ip_address':a.ip_address,'user_agent':a.user_agent,'account_email':(db.get(User,a.user_id).email if db.get(User,a.user_id) else None),'role':(db.get(User,a.user_id).role if db.get(User,a.user_id) else None)} for a in accepts],
      'events':[{'event':e.event_type,'details':e.details if isinstance(e.details,dict) else (json.loads(e.details) if isinstance(e.details,str) and e.details else {}),'created_at':e.created_at.isoformat()} for e in events]}

CONTRACT_ACKNOWLEDGEMENT="""إقرار وموافقة الأطراف
يقرّ كل طرف وارد اسمه في هذه الاتفاقية بأنه قرأ جميع بنودها قراءةً كاملة، وراجع بياناتها ونِسَبها والتزاماته وحقوقه، وفهم مضمونها وآثارها، ووافق عليها بإرادته الحرة دون إكراه، ويتعهد بتنفيذ ما يخصه منها.
وتُسجّل الموافقة من الحساب الشخصي للطرف بعد إظهار نص الاتفاقية كاملًا، ويُحفظ وقتها واسم صاحب الحساب وبصمة النسخة وسجل الإجراء. ولا يُعد ختم وصلة البصري وحده شهادة تصديق أو توقيعًا رقميًا معتمدًا.
(والله شاهدٌ علينا، وهو خير الشاهدين)"""

CONTRACT_STANDARD_TERMS="""أحكام التعامل والتسوية: يلتزم التاجر بصحة وصف المنتج وسلامته ومخزونه وتجهيزه وشحنه وخدمة ما بعد البيع ومعالجة الاستبدال والاسترجاع ورد المبالغ وفق السياسة المعلنة والقانون. ويلتزم المسوق بصحة الإعلان وعدم التضليل أو إساءة استخدام الروابط أو بيانات العملاء. لا تستحق عمولة المسوق أو المنصة عن الطلب الملغي أو المرتجع، وتُسوّى العمولة عن الطلب الذي تم تسليمه والتحقق منه وفق سجلات المنصة. يلتزم كل طرف بحماية بيانات العملاء وعدم استخدامها خارج غرض تنفيذ الطلب. وصلة وسيط تقني وتسويقي لتنظيم العرض والإحالة والتوثيق، وليست بائعًا للمنتج ولا تضمن التزام طرف آخر. لا تُفرض غرامة أو خصم تلقائي؛ ولا يُنظر في شرط جزائي إلا عند تحديد المخالفة وإثباتها ومراجعة الاعتراض وصدور قرار موثق وفق القانون. يكون الإلغاء أو الفسخ بطلب مسبب، مع تسوية الطلبات والحقوق والعمولات المستحقة حتى تاريخ الإنهاء، دون إسقاط حقوق العملاء أو الحقوق المالية الثابتة. وأي تعديل بعد التوقيع يكون بملحق أو إصدار جديد يوافق عليه الأطراف."""

def ensure_contract_ack(body:str)->str:
    text=(body or '').strip()
    if 'أحكام التعامل والتسوية:' not in text:
        text += chr(10)+chr(10)+CONTRACT_STANDARD_TERMS
    if 'إقرار وموافقة الأطراف' not in text:
        text += chr(10)+chr(10)+CONTRACT_ACKNOWLEDGEMENT
    return text

def contract_request_out(row,owner):
    return {'id':row.id,'requested_type':row.requested_type,'title':row.title,'details':row.details,'desired_commission':row.desired_commission,'status':row.status,'admin_note':row.admin_note,'created_at':row.created_at.isoformat(),'user_id':owner.id,'user_name':owner.name,'user_email':owner.email}

@app.post('/api/contracts/request')
def request_platform_contract(data:ContractRequestIn,user:User=Depends(current_user),db:Session=Depends(get_db)):
    if user.role not in ('merchant','affiliate'):
        raise HTTPException(403,'طلب التعاقد مع المنصة متاح للتاجر والمسوق فقط')
    requested_type='platform_merchant' if user.role=='merchant' else 'platform_affiliate'
    pending=db.scalar(select(ContractRequest).where(ContractRequest.user_id==user.id,ContractRequest.status=='pending'))
    if pending: raise HTTPException(409,'لديك طلب تعاقد قيد المراجعة بالفعل')
    row=ContractRequest(user_id=user.id,requested_type=requested_type,title=data.title.strip(),details=data.details.strip(),desired_commission=data.desired_commission)
    db.add(row)
    admins=db.scalars(select(User).where(User.role=='admin',User.status=='active')).all()
    for admin in admins: notify_user(db,admin.id,'طلب تعاقد جديد',f'{user.name} أرسل طلب تعاقد: {data.title}','/control')
    db.commit()
    return {'message':'تم إرسال طلب التعاقد إلى إدارة وصلة','request_id':row.id}

@app.get('/api/contracts/requests/my')
def my_contract_requests(user:User=Depends(current_user),db:Session=Depends(get_db)):
    rows=db.scalars(select(ContractRequest).where(ContractRequest.user_id==user.id).order_by(ContractRequest.created_at.desc()).limit(50)).all()
    return [{'id':x.id,'title':x.title,'status':x.status,'admin_note':x.admin_note,'created_at':x.created_at.isoformat()} for x in rows]

@app.get('/api/admin/contract-requests')
def admin_contract_requests(user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    rows=db.execute(select(ContractRequest,User).join(User,User.id==ContractRequest.user_id).order_by(ContractRequest.created_at.desc()).limit(200)).all()
    return [contract_request_out(row,owner) for row,owner in rows]

@app.post('/api/admin/contract-requests/{request_id}/decision')
def decide_contract_request(request_id:int,data:ContractRequestDecision,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    row=db.get(ContractRequest,request_id)
    if not row or row.status!='pending': raise HTTPException(404,'طلب التعاقد غير موجود أو تمت مراجعته')
    if data.decision not in ('approve','reject'): raise HTTPException(400,'القرار غير صحيح')
    owner=db.get(User,row.user_id)
    row.status='approved' if data.decision=='approve' else 'rejected'
    row.admin_note=data.admin_note.strip(); row.reviewed_by=user.id; row.reviewed_at=datetime.now(timezone.utc)
    contract_id=None
    if data.decision=='approve':
        contract=Contract(contract_type=row.requested_type,title=row.title,body=ensure_contract_ack(row.details),merchant_id=owner.id if owner.role=='merchant' else None,affiliate_id=owner.id if owner.role=='affiliate' else None,commission_rate=row.desired_commission,status='draft',contract_number='WS-'+datetime.now(timezone.utc).strftime('%Y%m%d')+'-'+secrets.token_hex(3).upper(),legal_entity_name=owner.name,commission_scope='contract',platform_signer_name='WESLA | المنصة')
        db.add(contract); db.flush(); contract_event(db,contract,user,'created_from_request',{'request_id':row.id}); contract_id=contract.id
    notify_user(db,owner.id,'تحديث طلب التعاقد',('تمت الموافقة على طلبك وإنشاء مسودة اتفاقية' if data.decision=='approve' else 'تم رفض طلب التعاقد')+ (': '+row.admin_note if row.admin_note else ''),'/')
    db.commit()
    return {'message':'تمت مراجعة طلب التعاقد','status':row.status,'contract_id':contract_id}

@app.post('/api/contracts/{contract_id}/negotiations')
def create_contract_negotiation(contract_id:int,data:ContractNegotiationIn,user:User=Depends(current_user),db:Session=Depends(get_db)):
    contract=db.get(Contract,contract_id)
    if not contract or not can_view_contract(contract,user) or contract.status in ('archived','terminated'):
        raise HTTPException(404,'الاتفاقية غير متاحة للتفاوض')
    if user.role=='admin':
        recipient_id=data.recipient_user_id
        if not recipient_id or recipient_id not in contract_party_ids(contract): raise HTTPException(400,'حدد الطرف المستلم للمقترح')
    elif contract.contract_type=='merchant_affiliate':
        recipient_id=contract.affiliate_id if user.id==contract.merchant_id else contract.merchant_id
    else:
        recipient_id=db.scalar(select(User.id).where(User.role=='admin',User.status=='active').order_by(User.id).limit(1))
    if not recipient_id or recipient_id==user.id: raise HTTPException(400,'تعذر تحديد الطرف الآخر في الاتفاقية')
    recipient=db.get(User,recipient_id)
    if not recipient: raise HTTPException(404,'الطرف المستلم غير موجود')
    negotiation=ContractNegotiation(contract_id=contract.id,proposer_id=user.id,recipient_id=recipient.id,proposal_text=data.proposal_text.strip(),reason=data.reason.strip())
    db.add(negotiation)
    notify_user(db,recipient.id,'مقترح تفاوض على اتفاقية',f'{user.name} أرسل مقترحًا على الاتفاقية {contract.contract_number}',f'/')
    db.commit(); db.refresh(negotiation)
    return {'message':'تم إرسال المقترح للطرف الآخر','negotiation_id':negotiation.id,'status':negotiation.status}

@app.get('/api/contracts/{contract_id}/negotiations')
def list_contract_negotiations(contract_id:int,user:User=Depends(current_user),db:Session=Depends(get_db)):
    contract=db.get(Contract,contract_id)
    if not contract or not can_view_contract(contract,user): raise HTTPException(404,'الاتفاقية غير موجودة')
    rows=db.scalars(select(ContractNegotiation).where(ContractNegotiation.contract_id==contract.id).order_by(ContractNegotiation.created_at.asc()).limit(200)).all()
    return [{'id':n.id,'proposer_id':n.proposer_id,'recipient_id':n.recipient_id,'proposal_text':n.proposal_text,'reason':n.reason,'response_text':n.response_text,'status':n.status,'parent_id':n.parent_id,'created_at':n.created_at.isoformat()} for n in rows]

@app.post('/api/contract-negotiations/{negotiation_id}/respond')
def respond_contract_negotiation(negotiation_id:int,data:ContractNegotiationResponseIn,user:User=Depends(current_user),db:Session=Depends(get_db)):
    row=db.get(ContractNegotiation,negotiation_id)
    if not row or row.status!='pending': raise HTTPException(404,'مقترح التفاوض غير موجود أو تمت مراجعته')
    if user.id!=row.recipient_id and user.role!='admin': raise HTTPException(403,'هذا المقترح ليس موجّهًا لحسابك')
    if data.decision not in ('accept','reject','counter'): raise HTTPException(400,'قرار التفاوض غير صحيح')
    if data.decision in ('reject','counter') and len(data.response_text.strip())<5: raise HTTPException(400,'اكتب ردًا أو صياغة بديلة واضحة')
    row.response_text=data.response_text.strip(); row.status={'accept':'accepted','reject':'rejected','counter':'countered'}[data.decision]; row.responded_at=datetime.now(timezone.utc)
    new_contract_id=None
    if data.decision=='counter':
        counter=ContractNegotiation(contract_id=row.contract_id,proposer_id=user.id,recipient_id=row.proposer_id,parent_id=row.id,proposal_text=data.response_text.strip(),reason='صياغة بديلة مقدمة ردًا على المقترح')
        db.add(counter); notify_user(db,row.proposer_id,'تم تقديم صياغة تفاوضية بديلة',f'يوجد رد بديل على المقترح رقم {row.id}','/')
    elif data.decision=='accept':
        original=db.get(Contract,row.contract_id)
        next_version=original.version+1
        revised_body=ensure_contract_ack(original.body+chr(10)+chr(10)+'بند مضاف نتيجة التفاوض'+chr(10)+row.proposal_text)
        revised=Contract(contract_type=original.contract_type,title=f'{original.title} — الإصدار {next_version}',body=revised_body,merchant_id=original.merchant_id,affiliate_id=original.affiliate_id,commission_rate=original.commission_rate,penalty_terms=original.penalty_terms,status='draft',contract_number=None,starts_at=original.starts_at,ends_at=original.ends_at,version=next_version,platform_signer_name=original.platform_signer_name,legal_entity_name=original.legal_entity_name,commission_scope=original.commission_scope,penalty_type=original.penalty_type,penalty_amount=original.penalty_amount,penalty_percent=original.penalty_percent,termination_terms=original.termination_terms)
        db.add(revised); db.flush(); new_contract_id=revised.id
        revised.contract_number=f'W-{revised.id}-V{next_version}'
        contract_event(db,original,user,'negotiation_accepted_new_version',{'negotiation_id':row.id,'new_contract_id':new_contract_id,'version':next_version})
        contract_event(db,revised,user,'created_from_negotiation',{'source_contract_id':original.id,'negotiation_id':row.id})
        for party_id in contract_party_ids(original): notify_user(db,party_id,'تم قبول مقترح التفاوض','تم إنشاء إصدار جديد كمسودة، ويجب على الأطراف مراجعته وتوقيعه من جديد','/')
    else:
        notify_user(db,row.proposer_id,'تم رفض مقترح التفاوض',data.response_text.strip(),'/')
    db.commit()
    return {'message':'تم تسجيل الرد على المقترح','status':row.status,'new_contract_id':new_contract_id}

@app.get('/api/contracts/negotiations/my')
def my_contract_negotiations(user:User=Depends(current_user),db:Session=Depends(get_db)):
    rows=db.scalars(select(ContractNegotiation).where((ContractNegotiation.proposer_id==user.id)|(ContractNegotiation.recipient_id==user.id)).order_by(ContractNegotiation.created_at.desc()).limit(100)).all()
    return [{'id':n.id,'contract_id':n.contract_id,'proposer_id':n.proposer_id,'recipient_id':n.recipient_id,'proposal_text':n.proposal_text,'response_text':n.response_text,'status':n.status,'created_at':n.created_at.isoformat()} for n in rows]

@app.get('/api/contracts/my')
def my_contracts(user:User=Depends(current_user),db:Session=Depends(get_db)):
    rows=db.scalars(select(Contract).order_by(Contract.created_at.desc())).all()
    result=[]
    for c in rows:
        if can_view_contract(c,user):
            item=contract_out(c,db)
            item['accepted_by_me']=any(a['user_id']==user.id for a in item['acceptances'])
            result.append(item)
    return result

@app.post('/api/contracts/{contract_id}/accept')
def accept_contract(contract_id:int,data:ContractDecision,request:Request,user:User=Depends(current_user),db:Session=Depends(get_db)):
    if not data.accepted: raise HTTPException(400,'يجب تأكيد الموافقة على نص الاتفاقية')
    c=db.get(Contract,contract_id)
    if not c or c.status!='active': raise HTTPException(404,'الاتفاقية غير متاحة للموافقة')
    if not can_view_contract(c,user) or user.role=='admin': raise HTTPException(403,'هذه الاتفاقية ليست موجهة لحسابك')
    old=db.scalar(select(ContractAcceptance).where(ContractAcceptance.contract_id==c.id,ContractAcceptance.user_id==user.id))
    if old: raise HTTPException(409,'تم تسجيل موافقتك من قبل')
    accepted_at=datetime.now(timezone.utc)
    snapshot=contract_snapshot_data(c)
    snapshot_json=stable_contract_json(snapshot)
    snapshot_hash=hashlib.sha256(snapshot_json.encode()).hexdigest()
    ip_address=(request.headers.get('x-forwarded-for') or (request.client.host if request.client else '')).split(',')[0].strip()[:64]
    user_agent=request.headers.get('user-agent','')[:500]
    token=request.cookies.get('wesla_session','')
    session_fingerprint=hashlib.sha256(token.encode()).hexdigest() if token else ''
    full_name=data.full_name.strip()
    signature_data=validate_brand_png(data.signature_data_url,'توقيع الطرف') if data.signature_data_url else None
    signature_hash=hashlib.sha256(signature_data.encode()).hexdigest() if signature_data else ''
    digest,evidence=acceptance_evidence_hash(snapshot_hash,user,full_name,accepted_at,ip_address,user_agent,session_fingerprint,signature_hash)
    db.add(ContractAcceptance(contract_id=c.id,user_id=user.id,full_name=full_name,document_hash=digest,accepted_at=accepted_at,ip_address=ip_address,user_agent=user_agent,signature_data_url=signature_data))
    contract_event(db,c,user,'party_accepted',{'name':full_name,'document_hash':digest,'snapshot_hash':snapshot_hash,'signature_hash':signature_hash,'evidence':evidence})
    db.flush()
    signed=db.scalars(select(ContractAcceptance).where(ContractAcceptance.contract_id==c.id)).all()
    required=contract_party_ids(c)
    all_parties_signed=bool(required) and all(any(a.user_id==uid for a in signed) for uid in required)
    if all_parties_signed and c.contract_type in ('merchant_affiliate','multi_party'):
        finalize_contract(db,c,user)
    elif all_parties_signed and c.contract_type in ('platform_merchant','platform_affiliate'):
        contract_event(db,c,user,'parties_signed_waiting_admin',{'snapshot_hash':snapshot_hash,'party_ids':required})
    db.commit()
    message='تم تسجيل موافقتك الإلكترونية. بانتظار اعتماد ممثل الإدارة.' if all_parties_signed and c.contract_type in ('platform_merchant','platform_affiliate') else 'تم تسجيل موافقتك الإلكترونية.'
    return {'message':message,'status':c.status,'document_hash':digest,'snapshot_hash':snapshot_hash}


@app.get('/api/contracts/{contract_id}/document')
def contract_document(contract_id:int,user:User=Depends(current_user),db:Session=Depends(get_db)):
    c=db.get(Contract,contract_id)
    if not c or not can_view_contract(c,user): raise HTTPException(404,'العقد غير موجود')
    if c.status not in ('signed','termination_review','terminated'): raise HTTPException(409,'لا تتوفر النسخة النهائية قبل اكتمال موافقات الأطراف واعتماد الإدارة عند انطباقه')
    from fastapi.responses import HTMLResponse
    safe=lambda x: str(x or '').replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;').replace("'","&#39;")
    acceptances=db.scalars(select(ContractAcceptance).where(ContractAcceptance.contract_id==c.id).order_by(ContractAcceptance.accepted_at)).all()
    users_by_id={a.user_id:db.get(User,a.user_id) for a in acceptances}
    merchant=db.get(User,c.merchant_id) if c.merchant_id else None
    affiliate=db.get(User,c.affiliate_id) if c.affiliate_id else None
    admin_acceptance=next((a for a in acceptances if users_by_id.get(a.user_id) and users_by_id[a.user_id].role=='admin'),None)
    final_event=db.scalars(select(ContractEvent).where(ContractEvent.contract_id==c.id,ContractEvent.event_type=='contract_finalized').order_by(ContractEvent.created_at.desc())).first()
    final_details=final_event.details if final_event and isinstance(final_event.details,dict) else {}
    snapshot=final_details.get('snapshot') if final_details else None
    verified=False
    if snapshot and c.final_hash:
        snapshot_json=stable_contract_json(snapshot)
        hashes=sorted(a.document_hash for a in acceptances)
        expected=hashlib.sha256((snapshot_json+'|'+'|'.join(hashes)).encode()).hexdigest()
        expected_snapshot_hash=hashlib.sha256(snapshot_json.encode()).hexdigest()
        verified=(hmac.compare_digest(expected,c.final_hash)
            and final_details.get('final_hash')==c.final_hash
            and final_details.get('snapshot_hash')==expected_snapshot_hash
            and final_details.get('acceptance_hashes')==hashes)
    penalty_type_labels={'fixed':'مبلغ ثابت','percentage':'نسبة مئوية','percent':'نسبة مئوية','both':'مبلغ ثابت ونسبة مئوية'}
    penalty_type_label=penalty_type_labels.get(c.penalty_type,c.penalty_type or 'غير محدد')
    penalty_amount_text=(f'{safe((snapshot or {}).get('penalty_amount',c.penalty_amount))} جنيه مصري' if c.penalty_amount is not None else 'غير محدد')
    penalty_percent_text=(f'{safe((snapshot or {}).get('penalty_percent',c.penalty_percent))}%' if c.penalty_percent is not None else 'غير محددة')
    signature_cards=[]
    parties=[]
    role_labels={'merchant':'التاجر','affiliate':'المسوق','customer':'العميل'}
    for uid in contract_party_ids(c):
        account=db.get(User,uid)
        if account: parties.append((role_labels.get(account.role,'الطرف المتعاقد'),account,uid))
    for role,account,uid in parties:
        if not account: continue
        accepted=next((a for a in acceptances if a.user_id==uid),None)
        if accepted:
            signature_image=(f'<img class="party-signature-image" src="{safe(accepted.signature_data_url)}" alt="توقيع {safe(role)}">' if accepted.signature_data_url else '<div class="no-signature">موافقة إلكترونية مسجلة دون صورة توقيع</div>')
            signature_cards.append(f'<section class="signature-card"><div class="party-role">{safe(role)}</div>{signature_image}<div class="signature-name">{safe(accepted.full_name)}</div><div class="meta-row"><b>حساب الطرف:</b> {safe(account.name)} — {safe(account.email)} — #{safe(account.id)}</div><div class="meta-row"><b>وقت الموافقة:</b> {safe(accepted.accepted_at.isoformat())}</div><div class="meta-row"><b>وسيلة الإثبات:</b> موافقة صريحة من جلسة حساب مسجل</div><div class="meta-row"><b>عنوان الاتصال المسجل:</b> {safe(accepted.ip_address or 'غير متاح')}</div><div class="meta-row"><b>بيئة المتصفح:</b> {safe(accepted.user_agent or 'غير متاحة')}</div><div class="meta-row"><b>بصمة الموافقة SHA-256:</b><span class="hash">{safe(accepted.document_hash)}</span></div><div class="signed-status">موافقة إلكترونية مسجلة</div></section>')
        else:
            signature_cards.append(f'<section class="signature-card"><div class="party-role">{safe(role)}</div><div class="signature-name">بانتظار الموافقة</div><div class="meta-row">لا يوجد سجل موافقة لهذا الطرف</div></section>')
    if c.contract_type in ('platform_merchant','platform_affiliate'):
        if admin_acceptance and users_by_id.get(admin_acceptance.user_id):
            admin_account=users_by_id[admin_acceptance.user_id]
            signature_cards.append(f'<section class="signature-card"><div class="party-role">الإدارة</div><div class="signature-name">WESLA</div><div class="meta-row"><b>ممثل الإدارة المسجل:</b> {safe(admin_acceptance.full_name)} — {safe(admin_account.email)} — #{safe(admin_account.id)}</div><div class="meta-row"><b>وقت الاعتماد:</b> {safe(admin_acceptance.accepted_at.isoformat())}</div><div class="meta-row"><b>عنوان الاتصال المسجل:</b> {safe(admin_acceptance.ip_address or 'غير متاح')}</div><div class="meta-row"><b>بيئة المتصفح:</b> {safe(admin_acceptance.user_agent or 'غير متاحة')}</div><div class="meta-row"><b>بصمة موافقة الإدارة SHA-256:</b><span class="hash">{safe(admin_acceptance.document_hash)}</span></div><div class="signed-status">اعتماد إلكتروني مسجل من حساب الإدارة</div></section>')
        else:
            signature_cards.append('<section class="signature-card"><div class="party-role">الإدارة</div><div class="signature-name">WESLA</div><div class="meta-row">لا يوجد سجل موافقة مستقل لممثل الإدارة في هذه النسخة التاريخية؛ لا يُعرض هذا الرمز كتوقيع شخصي.</div><div class="signed-status">اعتماد ممثل الإدارة غير موثق في سجل الموافقات</div></section>')
    brand_visual=''
    if c.brand_signature_snapshot or c.brand_stamp_snapshot:
        brand_visual='<div class="brand-identity">'
        if c.brand_signature_snapshot:
            brand_visual+=f'<img class="brand-signature-image" src="{safe(c.brand_signature_snapshot)}" alt="توقيع وصلة">'
        if c.brand_stamp_snapshot:
            brand_visual+=f'<img class="brand-stamp-image" src="{safe(c.brand_stamp_snapshot)}" alt="ختم وصلة">'
        brand_visual+='</div>'
    if c.contract_type=='merchant_affiliate':
        signature_cards.append('<section class="signature-card"><div class="party-role">منصة وصلة</div>'+brand_visual+'<div class="meta-row">هوية بصرية للمنصة ضمن نسخة العقد؛ لا تُعد وحدها شهادة تصديق أو توقيعًا إلكترونيًا معتمدًا.</div></section>')
    elif c.contract_type in ('platform_merchant','platform_affiliate') and brand_visual:
        for card_index, card_html in enumerate(signature_cards):
            if 'party-role">الإدارة' in card_html:
                signature_cards[card_index]=card_html.replace('</section>',brand_visual+'</section>')
                break
    signatures=''.join(signature_cards)
    verification_text='تم التحقق من تطابق بصمة النسخة النهائية مع لقطة الإصدار وبصمات الموافقات المسجلة' if verified else 'هذه نسخة تاريخية لا يتوفر لها سجل لقطة نهائية مستقل يسمح بالتحقق الآلي الكامل من تطابق المحتوى'
    verification_class='verified' if verified else 'unverified'
    snapshot_hash=final_details.get('snapshot_hash','') if final_details else ''
    party_summary=' — '.join(f'{role}: {account.name}' for role,account,uid in parties) or 'غير محدد'
    html=f"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>محضر الاتفاقية {safe(c.contract_number)}</title>
    <style>
    @page{{size:A4 portrait;margin:5mm}}*{{box-sizing:border-box}}html,body{{margin:0;padding:0;background:#fff}}body{{font:8px/1.24 Tahoma,Arial,sans-serif;color:#202938}}.paper{{width:100%;min-height:287mm;padding:9mm;border:3px double #c69b42;background:linear-gradient(145deg,#fff 0%,#f7f9ff 100%)}}.brand{{display:flex;align-items:center;justify-content:center;margin:0 0 3px}}.brand-signature{{display:block;width:86px;height:32px}}.brand-signature svg{{width:100%;height:100%;display:block}}.heading{{border-bottom:2px solid #d0a64c;padding:8px 0;margin-bottom:10px;text-align:center}}h1{{font-size:20px;color:#0d2d5b;margin:0}}h2{{font-size:12px;color:#243d62;margin:4px 0 0}}h3{{font-size:11px;color:#fff;background:linear-gradient(90deg,#0d2d5b,#174d86);border-radius:16px;padding:5px 12px;margin:10px 0 5px;text-align:center}}.grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:6px}}.cell{{background:#f4f6fb;border:1px solid #d2dbea;padding:7px 9px;border-radius:8px;overflow-wrap:anywhere}}.cell b{{display:block;color:#173b6b;font-size:9px}}.body{{white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid #e6d9b7;padding:4px 6px;background:#fff;border-radius:3px;font-size:7.4px;line-height:1.22}}.clauses{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:5px}}.penalty{{background:#fff7f0;border:1px solid #c67b48;padding:6px 8px;border-radius:4px}}.signature-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:7px}}.party-signature-image{{display:block;max-width:90%;width:auto;height:58px;object-fit:contain;margin:6px auto;border-bottom:1px solid #b9c7dc}}.no-signature{{font-size:7px;color:#7b8798;padding:8px 0}}.brand-identity{{display:flex;align-items:center;justify-content:space-around;gap:8px;margin:4px 0}}.brand-signature-image{{max-width:68%;max-height:48px;object-fit:contain}}.brand-stamp-image{{width:62px;height:62px;object-fit:contain}}.signature-card{{border:1px solid #d7c18e;border-radius:3px;padding:4px;background:#fff;break-inside:avoid;overflow-wrap:anywhere}}.party-role{{font-weight:bold;color:#80601f;font-size:10px}}.signature-name{{font-family:Tahoma,Arial,sans-serif;font-size:13px;font-weight:bold;color:#203b5b;margin:3px 0 5px;min-height:18px}}.meta-row{{font-size:6.5px;margin:1px 0;color:#4b5563;overflow-wrap:anywhere}}.hash{{direction:ltr;display:block;font:8px monospace;overflow-wrap:anywhere}}.signed-status{{font-size:9px;font-weight:bold;color:#28734b;margin-top:4px}}.verified{{background:#e8f6ed;border:1px solid #78b68c;padding:7px;border-radius:4px;color:#17613a;font-weight:bold}}.unverified{{background:#fff4df;border:1px solid #d8a84e;padding:7px;border-radius:4px;color:#81520c;font-weight:bold}}.notice{{border:1px solid #c9d2df;background:#f5f7fa;padding:4px 6px;border-radius:3px;font-size:6.8px;line-height:1.2}}.closing{{text-align:center;font-weight:bold;color:#80601f;border-top:1px solid #d8c28c;margin:4px 0 0;padding-top:3px;font-size:9px}}button{{margin-top:5px;padding:5px 10px;border:0;border-radius:4px;background:#8d6a24;color:white;font:inherit}}@media(max-width:560px){{.grid{{grid-template-columns:repeat(2,minmax(0,1fr))}}.signature-grid,.clauses{{grid-template-columns:1fr}}.paper{{padding:8px}}}}@media print{{button{{display:none!important}}.paper{{break-inside:auto}}.signature-card,.cell,.penalty{{break-inside:avoid}}*{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}}}
    </style></head><body><main class="paper">
    <header class="brand"><span class="brand-signature"><svg viewBox="0 0 520 195" role="img" aria-label="توقيع وصلة" xmlns="http://www.w3.org/2000/svg"><path fill="#b34bdc" fill-rule="evenodd" d="M0,65 L0,79 L13,126 L29,159 L30,165 L36,172 L44,172 L54,163 L79,128 L88,147 L103,162 L112,163 L119,157 L127,141 L135,111 L137,109 L149,121 L154,114 L160,114 L160,112 L149,102 L139,86 L139,82 L133,78 L128,79 L124,86 L123,108 L116,132 L107,147 L99,139 L90,120 L87,108 L86,91 L81,86 L77,86 L72,91 L70,112 L65,125 L42,154 L30,135 L24,120 L13,69 L8,62 L3,62Z M480,50 L472,50 L467,54 L458,48 L451,48 L440,56 L434,68 L432,90 L435,100 L446,110 L457,113 L454,120 L451,122 L456,131 L455,134 L449,138 L450,141 L465,128 L472,116 L475,104 L485,94 L487,85 L495,94 L508,103 L516,103 L519,100 L518,92 L504,84 L498,78 L486,56Z M442,133 L439,132 L433,135 L421,133 L412,127 L400,113 L388,81 L371,8 L366,0 L358,0 L355,7 L365,37 L371,63 L371,84 L368,100 L359,126 L350,142 L330,161 L314,170 L312,169 L318,160 L324,143 L324,128 L321,113 L312,101 L296,96 L293,80 L281,87 L282,97 L273,97 L256,92 L264,84 L272,80 L273,76 L284,68 L279,65 L268,66 L254,75 L241,90 L241,99 L248,105 L258,108 L281,110 L278,125 L266,145 L255,160 L246,167 L234,164 L221,155 L211,145 L203,132 L217,116 L226,91 L228,79 L226,60 L217,52 L206,55 L195,72 L187,97 L187,122 L179,123 L173,120 L168,123 L164,122 L165,123 L160,127 L160,129 L173,135 L191,136 L200,152 L215,167 L228,175 L242,180 L254,180 L266,169 L290,130 L294,111 L303,112 L307,116 L310,126 L311,139 L307,151 L301,159 L298,167 L279,184 L281,191 L286,194 L298,194 L304,192 L337,172 L356,155 L370,132 L381,97 L393,125 L407,140 L415,145 L424,148 L437,147 L435,138Z"/></svg></span></header>
    <header class="heading"><h1>عقد اتفاق شامل</h1><h2>{safe((snapshot or {}).get('title',c.title))} — مستخرج من سجل منصة وصلة</h2></header>
    <div class="grid"><div class="cell"><b>رقم الاتفاقية</b>{safe(c.contract_number)}</div><div class="cell"><b>الإصدار</b>{safe(c.version)}</div><div class="cell"><b>الحالة الحالية</b>{safe(c.status)}</div><div class="cell"><b>تاريخ الإنشاء</b>{safe(c.created_at.isoformat() if c.created_at else '—')}</div><div class="cell"><b>تاريخ اكتمال الموافقات</b>{safe(c.approved_at.isoformat() if c.approved_at else '—')}</div><div class="cell"><b>الكيان القانوني المسجل</b>{safe((snapshot or {}).get('legal_entity_name') or 'غير محدد')}</div><div class="cell"><b>الأطراف المتعاقدة</b>{safe(party_summary)}</div><div class="cell"><b>التاجر</b>{safe(merchant.name if merchant else 'غير منطبق')}</div><div class="cell"><b>المسوق</b>{safe(affiliate.name if affiliate else 'غير منطبق')}</div><div class="cell"><b>مدة الاتفاقية</b>من {safe(c.starts_at.isoformat() if c.starts_at else 'غير محدد')} إلى {safe(c.ends_at.isoformat() if c.ends_at else 'غير محدد')}</div></div>
    <h3>النص الكامل للاتفاقية</h3><article class="body">{safe((snapshot or {}).get('body',c.body))}</article>
    <div class="clauses"><section><h3>العمولات</h3><div class="cell"><b>النسبة</b>{safe((snapshot or {}).get('commission_rate',c.commission_rate))}%<br><b>النطاق</b>{safe((snapshot or {}).get('commission_scope',c.commission_scope))}</div></section><section><h3>الشروط الجزائية</h3><div class="penalty"><b>النوع:</b> {safe(penalty_type_label)}<br><b>المبلغ:</b> {penalty_amount_text}<br><b>النسبة:</b> {penalty_percent_text}<br><b>التفاصيل:</b><div class="body">{safe((snapshot or {}).get('penalty_terms') or 'لا توجد تفاصيل إضافية مسجلة')}</div></div></section></div>
    <h3>شروط الإنهاء والفسخ</h3><div class="body">{safe((snapshot or {}).get('termination_terms') or 'لا توجد شروط إضافية مسجلة')}</div>
    <h3>سجل الموافقات الإلكترونية والأطراف</h3><div class="signature-grid">{signatures}</div>
    <h3>التحقق من سلامة سجل الاتفاقية</h3><div class="{verification_class}">{verification_text}</div>
    <div class="cell" style="margin-top:5px"><b>بصمة لقطة الإصدار SHA-256</b><span class="hash">{safe(snapshot_hash or 'غير متاحة في السجل التاريخي')}</span><b>بصمة النسخة النهائية SHA-256</b><span class="hash">{safe(c.final_hash or 'غير مسجلة')}</span></div>
    <div class="notice" style="margin-top:4px"><b>تنبيه قانوني وإثباتي:</b> هذا المحضر مستخرج من سجل منصة وصلة، ويعرض بيانات الحسابات وإجراءات الموافقة والبصمات الرقمية التي سجلها النظام. لا يُعد بذاته شهادة تصديق إلكتروني أو شهادة توقيع رقمي صادرة من جهة مرخصة، ولا يثبت الهوية المدنية وحده. تخضع حجية المحررات والتوقيعات الإلكترونية للقانون رقم 15 لسنة 2004 ولائحته التنفيذية والضوابط الفنية ذات الصلة. عند اشتراط توقيع رقمي معتمد أو ختم إلكتروني، يجب إتمامه عبر مقدم خدمات مرخص من ITIDA وحفظ النسخة الإلكترونية الأصلية وسجلها.</div>
    <p class="closing">والله شاهدٌ علينا، وهو خيرُ الشاهدين.</p><button onclick="window.print()">طباعة / حفظ PDF</button></main></body></html>"""
    return HTMLResponse(html,headers={"Cache-Control":"no-store"})

@app.post('/api/contracts/{contract_id}/termination')
def request_termination(contract_id:int,data:TerminationIn,user:User=Depends(current_user),db:Session=Depends(get_db)):
    c=db.get(Contract,contract_id)
    if not c or not can_view_contract(c,user) or c.status!='signed': raise HTTPException(404,'العقد غير متاح لطلب الفسخ')
    req=ContractTerminationRequest(contract_id=c.id,requester_user_id=user.id,reason=data.reason,evidence_paths=data.evidence_paths)
    db.add(req); c.status='termination_review'; contract_event(db,c,user,'termination_requested',{'reason':data.reason})
    db.commit(); return {'message':'تم تسجيل طلب الفسخ وإرساله للمراجعة'}

@app.get('/api/admin/termination-requests')
def admin_termination_requests(user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    rows=db.scalars(select(ContractTerminationRequest).order_by(ContractTerminationRequest.created_at.desc())).all()
    return [{'id':x.id,'contract_id':x.contract_id,'contract_number':db.get(Contract,x.contract_id).contract_number,'requester':db.get(User,x.requester_user_id).name,'reason':x.reason,'status':x.status} for x in rows]

@app.post('/api/admin/termination-requests/{request_id}/decision')
def decide_termination(request_id:int,data:TerminationDecision,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    req=db.get(ContractTerminationRequest,request_id)
    if not req or req.status!='under_review': raise HTTPException(404,'طلب الفسخ غير موجود')
    if data.decision not in ('accept','reject'): raise HTTPException(400,'قرار غير صحيح')
    c=db.get(Contract,req.contract_id); req.status='accepted' if data.decision=='accept' else 'rejected'
    req.decision_reason=data.reason; req.decided_by=user.id; req.decided_at=datetime.now(timezone.utc)
    c.status='terminated' if data.decision=='accept' else 'signed'
    contract_event(db,c,user,'termination_'+data.decision,{'reason':data.reason,'request_id':req.id})
    db.commit(); return {'message':'تم حفظ قرار طلب الفسخ','status':c.status}

@app.post('/api/admin/commission-changes')
def propose_commission_change(data:CommissionChangeIn,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    c=db.get(Contract,data.contract_id) if data.contract_id else None
    p=db.get(Product,data.product_id) if data.product_id else None
    if not c and not p: raise HTTPException(400,'حدد عقدًا أو منتجًا')
    affected=db.get(User,data.affected_user_id)
    if not affected or affected.role not in ('merchant','affiliate'): raise HTTPException(400,'الطرف المتأثر غير صحيح')
    old=float(c.commission_rate if c and c.commission_rate is not None else (p.affiliate_rate if p else 0))
    req=CommissionChangeRequest(contract_id=c.id if c else None,product_id=p.id if p else None,merchant_id=p.merchant_id if p else (c.merchant_id if c else None),affiliate_id=affected.id if affected.role=='affiliate' else None,old_rate=old,new_rate=data.new_rate,proposed_by=user.id,affected_user_id=affected.id)
    db.add(req); db.commit(); return {'message':'تم إرسال مقترح تغيير العمولة للطرف المتأثر','request_id':req.id}

@app.get('/api/commission-changes/my')
def my_commission_changes(user:User=Depends(current_user),db:Session=Depends(get_db)):
    rows=db.scalars(select(CommissionChangeRequest).where(CommissionChangeRequest.affected_user_id==user.id).order_by(CommissionChangeRequest.created_at.desc())).all()
    return [{'id':x.id,'old_rate':x.old_rate,'new_rate':x.new_rate,'status':x.status,'created_at':x.created_at.isoformat()} for x in rows]

@app.post('/api/commission-changes/{request_id}/accept')
def accept_commission_change(request_id:int,user:User=Depends(current_user),db:Session=Depends(get_db)):
    x=db.get(CommissionChangeRequest,request_id)
    if not x or x.affected_user_id!=user.id or x.status!='pending': raise HTTPException(404,'مقترح العمولة غير موجود')
    if x.contract_id:
        c=db.get(Contract,x.contract_id)
        if c.status=='signed': raise HTTPException(409,'العقد الموقع لا يتغير؛ أنشئ ملحقًا تعاقديًا جديدًا')
        c.commission_rate=x.new_rate
    elif x.product_id:
        p=db.get(Product,x.product_id)
        if not p or p.merchant_id!=user.id: raise HTTPException(403,'لا يمكن تعديل هذا المنتج')
        p.affiliate_rate=x.new_rate
    x.status='accepted'; x.accepted_at=datetime.now(timezone.utc)
    db.commit(); return {'message':'تمت الموافقة وتفعيل النسبة الجديدة للعمليات القادمة فقط'}

@app.get('/api/admin/negotiations')
def admin_negotiations(user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    rows=db.scalars(select(ContractNegotiation).order_by(ContractNegotiation.created_at.desc()).limit(200)).all()
    result=[]
    for n in rows:
        c=db.get(Contract,n.contract_id); proposer=db.get(User,n.proposer_id); recipient=db.get(User,n.recipient_id)
        result.append({'id':n.id,'contract_number':c.contract_number if c else '', 'contract_title':c.title if c else '', 'proposer':proposer.name if proposer else '', 'recipient':recipient.name if recipient else '', 'proposal_text':n.proposal_text,'reason':n.reason,'response_text':n.response_text,'status':n.status,'created_at':n.created_at.isoformat()})
    return result

@app.get('/api/admin/contract-brand-assets')
def admin_get_contract_brand_assets(user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    row=db.execute(text("select signature_data_url,stamp_data_url,is_active,signature_enabled,stamp_enabled,contract_types,version,updated_at,updated_by from wesla_contract_brand_assets where id=1")).mappings().first()
    history=db.execute(text("select v.version,v.is_active,v.signature_enabled,v.stamp_enabled,v.contract_types,v.created_at,u.name as changed_by from wesla_contract_brand_asset_versions v left join users u on u.id=v.changed_by order by v.version desc limit 20")).mappings().all()
    primary_id=db.execute(text("select value from site_settings where key='primary_admin_user_id'")).scalar() or '2'
    return {'is_primary_admin':str(user.id)==str(primary_id),'assets':dict(row) if row else None,'history':[dict(x) for x in history]}

@app.put('/api/admin/contract-brand-assets')
def admin_update_contract_brand_assets(data:ContractBrandAssetsIn,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    primary_id=str(db.execute(text("select value from site_settings where key='primary_admin_user_id'")).scalar() or '2')
    if str(user.id)!=primary_id:
        raise HTTPException(403,'اعتماد التوقيع والختم متاح للمدير الرئيسي فقط')
    allowed={'platform_merchant','platform_affiliate','merchant_affiliate'}
    if not data.contract_types or any(x not in allowed for x in data.contract_types):
        raise HTTPException(400,'حدد نوع اتفاقية واحدًا على الأقل من الأنواع المتاحة')
    signature=validate_brand_png(data.signature_data_url,'توقيع وصلة')
    stamp=validate_brand_png(data.stamp_data_url,'ختم وصلة')
    current=db.execute(text("select version from wesla_contract_brand_assets where id=1 for update")).scalar()
    version=int(current or 0)+1
    db.execute(text("""
      insert into wesla_contract_brand_asset_versions(version,signature_data_url,stamp_data_url,is_active,signature_enabled,stamp_enabled,contract_types,changed_by)
      values (:version,:signature,:stamp,:active,:signature_enabled,:stamp_enabled,:types,:actor)
    """),{'version':version,'signature':signature,'stamp':stamp,'active':data.is_active,'signature_enabled':data.signature_enabled,'stamp_enabled':data.stamp_enabled,'types':data.contract_types,'actor':user.id})
    db.execute(text("""
      insert into wesla_contract_brand_assets(id,signature_data_url,stamp_data_url,is_active,signature_enabled,stamp_enabled,contract_types,version,updated_by,updated_at)
      values (1,:signature,:stamp,:active,:signature_enabled,:stamp_enabled,:types,:version,:actor,now())
      on conflict(id) do update set signature_data_url=excluded.signature_data_url,stamp_data_url=excluded.stamp_data_url,
        is_active=excluded.is_active,signature_enabled=excluded.signature_enabled,stamp_enabled=excluded.stamp_enabled,contract_types=excluded.contract_types,version=excluded.version,updated_by=excluded.updated_by,updated_at=now()
    """),{'signature':signature,'stamp':stamp,'active':data.is_active,'signature_enabled':data.signature_enabled,'stamp_enabled':data.stamp_enabled,'types':data.contract_types,'version':version,'actor':user.id})
    db.commit()
    return {'ok':True,'version':version,'message':'تم حفظ هوية توقيع وختم وصلة. سيُطبق التحديث على العقود الجديدة فقط.'}

@app.get('/api/admin/contracts')
def admin_contracts(user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    return [contract_out(c,db) for c in db.scalars(select(Contract).order_by(Contract.created_at.desc())).all()]

@app.post('/api/admin/contracts')
def create_contract(data:ContractIn,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    if data.contract_type not in ('platform_merchant','platform_affiliate','merchant_affiliate','multi_party'):
        raise HTTPException(400,'نوع الاتفاقية غير صحيح')
    if data.contract_type in ('platform_merchant','merchant_affiliate'):
        if not data.merchant_id or not db.get(User,data.merchant_id) or db.get(User,data.merchant_id).role!='merchant': raise HTTPException(400,'اختر حساب تاجر صحيح')
    if data.contract_type in ('platform_affiliate','merchant_affiliate'):
        if not data.affiliate_id or not db.get(User,data.affiliate_id) or db.get(User,data.affiliate_id).role!='affiliate': raise HTTPException(400,'اختر حساب مسوق صحيح')
    if data.contract_type=='multi_party':
        ids=list(dict.fromkeys(data.participant_ids or []))
        if len(ids)<2: raise HTTPException(400,'يجب تحديد طرفين على الأقل للاتفاقية متعددة الأطراف')
        if any(not db.get(User,uid) or db.get(User,uid).role=='admin' for uid in ids): raise HTTPException(400,'تأكد من اختيار حسابات أطراف صحيحة')
        data.participant_ids=ids
    if data.commission_scope not in ('contract','all_products','product'): raise HTTPException(400,'نطاق العمولة غير صحيح')
    c=Contract(contract_type=data.contract_type,title=data.title.strip(),body=ensure_contract_ack(data.body),merchant_id=data.merchant_id,affiliate_id=data.affiliate_id,participant_ids=data.participant_ids,commission_rate=data.commission_rate,penalty_terms=data.penalty_terms,status='draft',contract_number='WS-'+datetime.now(timezone.utc).strftime('%Y%m%d')+'-'+secrets.token_hex(3).upper(),starts_at=data.starts_at,ends_at=data.ends_at,legal_entity_name=data.legal_entity_name,commission_scope=data.commission_scope,penalty_type=data.penalty_type,penalty_amount=data.penalty_amount,penalty_percent=data.penalty_percent,termination_terms=data.termination_terms,platform_signer_name='WESLA | المنصة')
    db.add(c); db.flush(); contract_event(db,c,user,'created',{'number':c.contract_number})
    db.commit(); db.refresh(c); return contract_out(c,db)

@app.post('/api/admin/contracts/{contract_id}/reissue-numbered')
def reissue_unnumbered_contract(contract_id:int,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    c=db.get(Contract,contract_id)
    if not c or c.status not in ('draft','active'): raise HTTPException(404,'الاتفاقية غير متاحة لإعادة الإصدار')
    if c.contract_number: raise HTTPException(409,'الاتفاقية لديها رقم بالفعل')
    acceptances=db.scalars(select(ContractAcceptance).where(ContractAcceptance.contract_id==c.id)).all()
    new_number='WS-'+datetime.now(timezone.utc).strftime('%Y%m%d')+'-'+secrets.token_hex(3).upper()
    if not acceptances:
        c.contract_number=new_number
        contract_event(db,c,user,'contract_number_assigned',{'contract_number':new_number,'reason':'Assigned before any party acceptance.'})
        db.commit()
        return {'message':'تم تخصيص رقم رسمي للاتفاقية دون تغيير نصها؛ لم تكن هناك موافقات سابقة.','contract_id':c.id,'contract_number':new_number,'status':c.status}
    if c.status!='active':
        raise HTTPException(409,'لا يمكن إعادة إصدار نسخة سبق إقفالها إلا بعد مراجعة حالتها أولًا')
    revised=Contract(
        contract_type=c.contract_type,title=c.title,body=c.body,merchant_id=c.merchant_id,affiliate_id=c.affiliate_id,
        commission_rate=c.commission_rate,penalty_terms=c.penalty_terms,participant_ids=list(c.participant_ids or []),status='draft',contract_number=new_number,
        starts_at=c.starts_at,ends_at=c.ends_at,version=(c.version or 1)+1,
        platform_signer_name=c.platform_signer_name,legal_entity_name=c.legal_entity_name,
        commission_scope=c.commission_scope,penalty_type=c.penalty_type,penalty_amount=c.penalty_amount,
        penalty_percent=c.penalty_percent,termination_terms=c.termination_terms,
    )
    db.add(revised)
    db.flush()
    c.status='archived'
    contract_event(db,c,user,'reissued_as_numbered_version',{'new_contract_id':revised.id,'new_contract_number':new_number,'old_acceptances_preserved':len(acceptances)})
    contract_event(db,revised,user,'reissued_from_legacy_contract',{'source_contract_id':c.id,'source_contract_number':None})
    db.commit()
    db.refresh(revised)
    return {'message':'أُنشئت نسخة جديدة مرقمة كمسودة. أُرشفت النسخة القديمة مع الاحتفاظ بموافقاتها وسجلها، ويجب إعادة إرسال النسخة الجديدة للأطراف.','contract_id':revised.id,'contract_number':new_number,'status':revised.status}


@app.post('/api/admin/contracts/{contract_id}/reopen-for-platform-approval')
def reopen_legacy_platform_contract(contract_id:int,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    c=db.get(Contract,contract_id)
    if not c or c.status!='signed': raise HTTPException(404,'الاتفاقية غير متاحة لإعادة المراجعة')
    if c.contract_type not in ('platform_merchant','platform_affiliate'):
        raise HTTPException(409,'إعادة الاعتماد متاحة لاتفاقيات المنصة فقط')
    acceptances=db.scalars(select(ContractAcceptance).where(ContractAcceptance.contract_id==c.id)).all()
    if any((db.get(User,a.user_id) and db.get(User,a.user_id).role=='admin') for a in acceptances):
        raise HTTPException(409,'يوجد اعتماد مستقل مسجل من ممثل الإدارة بالفعل')
    required=contract_party_ids(c)
    if not required or not all(any(a.user_id==uid for a in acceptances) for uid in required):
        raise HTTPException(409,'لا توجد موافقات مكتملة من الأطراف لإعادة فتح الاعتماد')
    previous_hash=c.final_hash
    previous_approved_at=c.approved_at.isoformat() if c.approved_at else None
    c.status='active'
    c.approved_at=None
    c.final_hash=None
    contract_event(db,c,user,'legacy_auto_approval_reopened',{
        'reason':'Historical platform status had been marked signed without a separate administration acceptance record.',
        'previous_final_hash':previous_hash,
        'previous_approved_at':previous_approved_at,
    })
    db.commit()
    return {'message':'أعيدت الاتفاقية إلى انتظار اعتماد ممثل الإدارة. تم الاحتفاظ بالبصمة التاريخية في سجل الأحداث.','status':c.status}


@app.post('/api/admin/contracts/{contract_id}/approve')
def approve_platform_contract(contract_id:int,data:AdminContractApproval,request:Request,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    if not data.accepted: raise HTTPException(400,'يجب تأكيد اعتماد الإدارة')
    c=db.get(Contract,contract_id)
    if not c or c.status!='active': raise HTTPException(404,'الاتفاقية غير متاحة لاعتماد الإدارة')
    if c.contract_type not in ('platform_merchant','platform_affiliate'):
        raise HTTPException(409,'هذا النوع من الاتفاقيات لا يتطلب اعتمادًا منفصلًا من الإدارة')
    required=contract_party_ids(c)
    acceptances=db.scalars(select(ContractAcceptance).where(ContractAcceptance.contract_id==c.id)).all()
    if not required or not all(any(a.user_id==uid for a in acceptances) for uid in required):
        raise HTTPException(409,'يجب اكتمال موافقات الأطراف أولًا')
    if any(a.user_id==user.id for a in acceptances):
        raise HTTPException(409,'تم تسجيل اعتماد هذا الممثل من قبل')
    accepted_at=datetime.now(timezone.utc)
    snapshot=contract_snapshot_data(c)
    snapshot_hash=hashlib.sha256(stable_contract_json(snapshot).encode()).hexdigest()
    ip_address=(request.headers.get('x-forwarded-for') or (request.client.host if request.client else '')).split(',')[0].strip()[:64]
    user_agent=request.headers.get('user-agent','')[:500]
    token=request.cookies.get('wesla_session','')
    session_fingerprint=hashlib.sha256(token.encode()).hexdigest() if token else ''
    digest,evidence=acceptance_evidence_hash(snapshot_hash,user,user.name,accepted_at,ip_address,user_agent,session_fingerprint)
    db.add(ContractAcceptance(contract_id=c.id,user_id=user.id,full_name=user.name,document_hash=digest,accepted_at=accepted_at,ip_address=ip_address,user_agent=user_agent))
    contract_event(db,c,user,'platform_representative_accepted',{'name':user.name,'document_hash':digest,'snapshot_hash':snapshot_hash,'evidence':evidence})
    db.flush()
    finalize_contract(db,c,user)
    db.commit()
    return {'message':'تم تسجيل اعتماد ممثل الإدارة وإقفال سجل الاتفاقية','status':c.status,'final_hash':c.final_hash}

@app.post('/api/admin/contracts/{contract_id}/{action}')
def contract_action(contract_id:int,action:str,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    c=db.get(Contract,contract_id)
    if not c: raise HTTPException(404,'الاتفاقية غير موجودة')
    if action=='activate':
        if c.status!='draft': raise HTTPException(409,'لا يمكن إرسال هذه النسخة في حالتها الحالية')
        assets=db.execute(text("select signature_data_url,stamp_data_url,is_active,signature_enabled,stamp_enabled,contract_types,version from wesla_contract_brand_assets where id=1")).mappings().first()
        if assets and assets['is_active'] and c.contract_type in (assets['contract_types'] or []):
            c.brand_signature_snapshot=assets['signature_data_url'] if assets['signature_enabled'] else None
            c.brand_stamp_snapshot=assets['stamp_data_url'] if assets['stamp_enabled'] else None
            c.brand_assets_version=assets['version']
        c.status='active'; contract_event(db,c,user,'sent_for_signature',{'brand_assets_version':c.brand_assets_version})
    elif action=='archive':
        if c.status=='signed': raise HTTPException(409,'العقد الموقع لا يُحذف أو يُؤرشف؛ استخدم طلب فسخ')
        c.status='archived'; contract_event(db,c,user,'archived')
    elif action=='draft':
        if c.status=='signed': raise HTTPException(409,'لا يمكن تعديل نسخة موقعة؛ أنشئ إصدارًا أو ملحقًا جديدًا')
        c.status='draft'; contract_event(db,c,user,'returned_to_draft')
    else: raise HTTPException(400,'الإجراء غير صحيح')
    db.commit(); return {'message':'تم تحديث حالة الاتفاقية','status':c.status}


def announcement_out(item, views=0, clicks=0):
    return {'id':item.id,'title':item.title,'body':item.body,'audience':item.audience,
        'target_url':item.target_url,'button_label':item.button_label,'placement':item.placement,
        'priority':item.priority,'is_active':item.is_active,'is_sponsored':item.is_sponsored,
        'advertiser_name':item.advertiser_name,'price_egp':float(item.price_egp or 0),
        'payment_status':item.payment_status,'payment_reference':item.payment_reference,
        'views':views,'clicks':clicks,'ctr':round((clicks/views*100),2) if views else 0,
        'starts_at':item.starts_at.isoformat() if item.starts_at else None,
        'ends_at':item.ends_at.isoformat() if item.ends_at else None,
        'created_at':item.created_at.isoformat() if item.created_at else None}

def announcement_event_totals(db, ids):
    if not ids: return {}
    rows=db.execute(select(AnnouncementEvent.announcement_id,AnnouncementEvent.event_type,func.count(AnnouncementEvent.id))
        .where(AnnouncementEvent.announcement_id.in_(ids))
        .group_by(AnnouncementEvent.announcement_id,AnnouncementEvent.event_type)).all()
    totals={i:{'view':0,'click':0} for i in ids}
    for aid,kind,count in rows:
        totals.setdefault(aid,{'view':0,'click':0})[kind]=int(count)
    return totals

@app.get('/api/announcements/active')
def active_announcements(request:Request,db:Session=Depends(get_db)):
    role=None
    token=request.cookies.get('wesla_session')
    if token:
        token_hash=hashlib.sha256(token.encode()).hexdigest()
        session=db.scalar(select(AuthSession).where(AuthSession.token_hash==token_hash))
        if session:
            expires=session.expires_at.replace(tzinfo=timezone.utc) if session.expires_at.tzinfo is None else session.expires_at
            if expires > datetime.now(timezone.utc):
                user=db.get(User,session.user_id)
                if user and user.status=='active' and user.role in ('customer','merchant','affiliate'):
                    role=user.role
    now_utc=datetime.now(timezone.utc)
    audience_values=['all',role] if role else ['all','visitor']
    rows=db.scalars(select(Announcement).where(
        Announcement.is_active.is_(True),
        Announcement.audience.in_(audience_values),
        ((Announcement.is_sponsored.is_(False)) | (Announcement.payment_status == 'paid')),
        (Announcement.starts_at.is_(None) | (Announcement.starts_at <= now_utc)),
        (Announcement.ends_at.is_(None) | (Announcement.ends_at > now_utc))
    ).order_by(Announcement.priority.desc(),Announcement.created_at.desc(),Announcement.id.desc()).limit(30)).all()
    return [announcement_out(x) for x in rows]

@app.post('/api/announcements/{announcement_id}/event')
def record_announcement_event(announcement_id:int,data:AnnouncementEventIn,db:Session=Depends(get_db)):
    if data.event_type not in ('view','click'):
        raise HTTPException(400,'نوع الحدث غير صحيح')
    if not re.fullmatch(r'[A-Za-z0-9_-]{24,64}',data.visitor_key):
        raise HTTPException(400,'معرّف المتصفح غير صالح')
    item=db.get(Announcement,announcement_id)
    now_utc=datetime.now(timezone.utc)
    if not item or not item.is_active or (item.starts_at and item.starts_at>now_utc) or (item.ends_at and item.ends_at<=now_utc):
        raise HTTPException(404,'الإعلان غير متاح')
    if data.event_type=='view':
        recent=db.scalar(select(AnnouncementEvent.id).where(
            AnnouncementEvent.announcement_id==announcement_id,
            AnnouncementEvent.visitor_key==data.visitor_key,
            AnnouncementEvent.event_type=='view',
            AnnouncementEvent.created_at>=now_utc-timedelta(hours=24)).limit(1))
        if recent: return {'ok':True,'recorded':False}
    db.add(AnnouncementEvent(announcement_id=announcement_id,event_type=data.event_type,visitor_key=data.visitor_key))
    db.commit()
    return {'ok':True,'recorded':True}

@app.get('/api/admin/announcements')
def admin_announcements(user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    rows=db.scalars(select(Announcement).order_by(Announcement.priority.desc(),Announcement.created_at.desc(),Announcement.id.desc()).limit(200)).all()
    totals=announcement_event_totals(db,[x.id for x in rows])
    return [announcement_out(x,totals.get(x.id,{}).get('view',0),totals.get(x.id,{}).get('click',0)) for x in rows]

@app.post('/api/admin/announcements')
def create_announcement(data:AnnouncementIn,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    if data.audience not in ('all','visitor','customer','merchant','affiliate'):
        raise HTTPException(400,'الفئة المستهدفة غير صحيحة')
    if data.payment_status not in ('not_required','pending','paid'):
        raise HTTPException(400,'حالة الدفع غير صحيحة')
    if data.is_sponsored and (not data.advertiser_name.strip() or data.price_egp <= 0):
        raise HTTPException(400,'الإعلان الممول يتطلب اسم المعلن وسعراً أكبر من صفر')
    if data.is_sponsored and data.payment_status == 'not_required':
        raise HTTPException(400,'حدد حالة سداد الإعلان الممول')
    if not data.is_sponsored:
        data.payment_status='not_required'; data.price_egp=Decimal('0'); data.payment_reference=''
    if data.placement not in ('top_banner','home_feed','product_feed'):
        raise HTTPException(400,'مكان ظهور الإعلان غير صحيح')
    target=data.target_url.strip()
    if target and not ((target.startswith('/') and not target.startswith('//')) or target.startswith('https://')):
        raise HTTPException(400,'الرابط يجب أن يكون مسارًا داخليًا أو رابط HTTPS')
    if data.starts_at and data.ends_at and data.ends_at <= data.starts_at:
        raise HTTPException(400,'موعد انتهاء الإعلان يجب أن يكون بعد موعد بدايته')
    item=Announcement(title=data.title.strip(),body=data.body.strip(),audience=data.audience,
        target_url=target,button_label=data.button_label.strip(),placement=data.placement,priority=data.priority,
        is_active=True,is_sponsored=data.is_sponsored,advertiser_name=data.advertiser_name.strip(),
        price_egp=data.price_egp,payment_status=data.payment_status,payment_reference=data.payment_reference.strip(),
        starts_at=data.starts_at,ends_at=data.ends_at,created_by=user.id)
    db.add(item); db.commit(); db.refresh(item)
    return announcement_out(item)

@app.patch('/api/admin/announcements/{announcement_id}')
def update_announcement(announcement_id:int,data:AnnouncementUpdateIn,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    item=db.get(Announcement,announcement_id)
    if not item: raise HTTPException(404,'الإعلان غير موجود')
    changes=data.model_dump(exclude_unset=True)
    if 'audience' in changes and changes['audience'] not in ('all','visitor','customer','merchant','affiliate'):
        raise HTTPException(400,'الفئة المستهدفة غير صحيحة')
    if 'payment_status' in changes and changes['payment_status'] not in ('not_required','pending','paid'):
        raise HTTPException(400,'حالة الدفع غير صحيحة')
    if 'placement' in changes and changes['placement'] not in ('top_banner','home_feed','product_feed'):
        raise HTTPException(400,'مكان ظهور الإعلان غير صحيح')
    if 'target_url' in changes:
        target=(changes['target_url'] or '').strip()
        if target and not ((target.startswith('/') and not target.startswith('//')) or target.startswith('https://')):
            raise HTTPException(400,'الرابط يجب أن يكون مسارًا داخليًا أو رابط HTTPS')
        changes['target_url']=target
    sponsor=changes.get('is_sponsored',item.is_sponsored)
    advertiser=changes.get('advertiser_name',item.advertiser_name) or ''
    price=changes.get('price_egp',item.price_egp)
    payment=changes.get('payment_status',item.payment_status)
    if sponsor and (not advertiser.strip() or Decimal(str(price or 0)) <= 0):
        raise HTTPException(400,'الإعلان الممول يتطلب اسم المعلن وسعراً أكبر من صفر')
    if sponsor and payment == 'not_required':
        raise HTTPException(400,'حدد حالة سداد الإعلان الممول')
    if not sponsor:
        changes.update({'payment_status':'not_required','price_egp':Decimal('0'),'payment_reference':''})
    start=changes.get('starts_at',item.starts_at)
    end=changes.get('ends_at',item.ends_at)
    if start and end and end<=start: raise HTTPException(400,'موعد انتهاء الإعلان يجب أن يكون بعد موعد بدايته')
    for key,value in changes.items():
        if key in ('title','body','button_label') and isinstance(value,str): value=value.strip()
        setattr(item,key,value)
    item.updated_at=datetime.now(timezone.utc)
    db.commit(); db.refresh(item)
    totals=announcement_event_totals(db,[item.id]).get(item.id,{})
    return announcement_out(item,totals.get('view',0),totals.get('click',0))

@app.delete('/api/admin/announcements/{announcement_id}')
def stop_announcement(announcement_id:int,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    item=db.get(Announcement,announcement_id)
    if not item: raise HTTPException(404,'الإعلان غير موجود')
    item.is_active=False
    item.updated_at=datetime.now(timezone.utc)
    db.commit()
    return {'message':'تم إيقاف الإعلان','id':item.id,'is_active':False}


# Favorites, coupons, customer support and affiliate wallet ledger.
def support_ticket_out(ticket,db,include_messages=False):
    owner=db.get(User,ticket.user_id)
    result={'id':ticket.id,'subject':ticket.subject,'status':ticket.status,'priority':ticket.priority,
            'created_at':ticket.created_at.isoformat(),'updated_at':ticket.updated_at.isoformat(),
            'user_name':owner.name if owner else '—','user_email':owner.email if owner else ''}
    if include_messages:
        rows=db.scalars(select(SupportMessage).where(SupportMessage.ticket_id==ticket.id).order_by(SupportMessage.created_at.asc()).limit(300)).all()
        result['messages']=[{'id':x.id,'sender_user_id':x.sender_user_id,'sender_name':(db.get(User,x.sender_user_id).name if x.sender_user_id and db.get(User,x.sender_user_id) else 'إدارة وصلة'),'body':x.body,'created_at':x.created_at.isoformat()} for x in rows]
    return result

@app.get('/api/favorites')
def my_favorites(user:User=Depends(current_user),db:Session=Depends(get_db)):
    rows=db.scalars(select(Product).join(Favorite,Favorite.product_id==Product.id).where(Favorite.user_id==user.id,Product.status=='active').order_by(Favorite.created_at.desc()).limit(200)).all()
    return products_out(rows,db)

@app.post('/api/favorites/{product_id}')
def add_favorite(product_id:int,user:User=Depends(current_user),db:Session=Depends(get_db)):
    product=db.scalar(select(Product).where(Product.id==product_id,Product.status=='active'))
    if not product: raise HTTPException(404,'المنتج غير متاح')
    exists=db.scalar(select(Favorite.id).where(Favorite.user_id==user.id,Favorite.product_id==product_id))
    if not exists:
        db.add(Favorite(user_id=user.id,product_id=product_id)); db.commit()
    return {'ok':True,'saved':True}

@app.delete('/api/favorites/{product_id}')
def remove_favorite(product_id:int,user:User=Depends(current_user),db:Session=Depends(get_db)):
    row=db.scalar(select(Favorite).where(Favorite.user_id==user.id,Favorite.product_id==product_id))
    if row: db.delete(row); db.commit()
    return {'ok':True,'saved':False}

@app.post('/api/support/tickets')
def create_support_ticket(data:SupportTicketIn,user:User=Depends(current_user),db:Session=Depends(get_db)):
    ticket=SupportTicket(user_id=user.id,subject=data.subject.strip(),status='open',priority='normal')
    db.add(ticket); db.flush()
    db.add(SupportMessage(ticket_id=ticket.id,sender_user_id=user.id,body=data.message.strip()))
    for admin_user in db.scalars(select(User).where(User.role=='admin',User.status=='active')).all():
        notify_user(db,admin_user.id,'تذكرة دعم جديدة',f'{user.name}: {ticket.subject}','/control')
    db.commit(); db.refresh(ticket)
    return support_ticket_out(ticket,db,True)

@app.get('/api/support/tickets/my')
def my_support_tickets(user:User=Depends(current_user),db:Session=Depends(get_db)):
    rows=db.scalars(select(SupportTicket).where(SupportTicket.user_id==user.id).order_by(SupportTicket.updated_at.desc()).limit(100)).all()
    return [support_ticket_out(x,db,True) for x in rows]

@app.post('/api/support/tickets/{ticket_id}/messages')
def reply_support_ticket(ticket_id:int,data:SupportMessageIn,user:User=Depends(current_user),db:Session=Depends(get_db)):
    ticket=db.get(SupportTicket,ticket_id)
    if not ticket or (ticket.user_id!=user.id and user.role!='admin'): raise HTTPException(404,'تذكرة الدعم غير موجودة')
    if ticket.status in ('resolved','closed') and user.role!='admin': raise HTTPException(409,'تم إغلاق التذكرة؛ تواصل مع الإدارة لفتحها مجددًا')
    db.add(SupportMessage(ticket_id=ticket.id,sender_user_id=user.id,body=data.body.strip()))
    ticket.updated_at=datetime.now(timezone.utc)
    if user.role=='admin' and ticket.status=='open': ticket.status='in_progress'
    if user.role!='admin':
        owner=db.get(User,ticket.user_id)
        for admin_user in db.scalars(select(User).where(User.role=='admin',User.status=='active')).all():
            notify_user(db,admin_user.id,'رد جديد على تذكرة دعم',f'{owner.name if owner else "مستخدم"} — {ticket.subject}','/control')
    else:
        notify_user(db,ticket.user_id,'رد جديد من دعم وصلة',ticket.subject,'/dashboard')
    db.commit(); db.refresh(ticket)
    return support_ticket_out(ticket,db,True)

@app.get('/api/admin/support/tickets')
def admin_support_tickets(user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    rows=db.scalars(select(SupportTicket).order_by(SupportTicket.updated_at.desc()).limit(300)).all()
    return [support_ticket_out(x,db,True) for x in rows]

@app.patch('/api/admin/support/tickets/{ticket_id}')
def update_support_ticket(ticket_id:int,data:SupportTicketUpdateIn,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    ticket=db.get(SupportTicket,ticket_id)
    if not ticket: raise HTTPException(404,'تذكرة الدعم غير موجودة')
    changes=data.model_dump(exclude_unset=True)
    if 'status' in changes and changes['status'] not in ('open','in_progress','resolved','closed'): raise HTTPException(400,'حالة التذكرة غير صحيحة')
    if 'priority' in changes and changes['priority'] not in ('low','normal','high','urgent'): raise HTTPException(400,'أولوية التذكرة غير صحيحة')
    for key,value in changes.items(): setattr(ticket,key,value)
    ticket.updated_at=datetime.now(timezone.utc)
    db.commit(); db.refresh(ticket)
    return support_ticket_out(ticket,db,True)

def coupon_out(c):
    return {'id':c.id,'code':c.code,'discount_type':c.discount_type,'discount_value':float(c.discount_value),
        'min_order_total':float(c.min_order_total),'max_discount':float(c.max_discount) if c.max_discount is not None else None,
        'usage_limit':c.usage_limit,'used_count':c.used_count,'starts_at':c.starts_at.isoformat() if c.starts_at else None,
        'ends_at':c.ends_at.isoformat() if c.ends_at else None,'is_active':c.is_active}

@app.get('/api/admin/coupons')
def admin_coupons(user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    rows=db.scalars(select(Coupon).order_by(Coupon.created_at.desc()).limit(300)).all()
    return [coupon_out(x) for x in rows]

@app.post('/api/admin/coupons')
def create_coupon(data:CouponIn,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    code=data.code.strip().upper()
    if not re.fullmatch(r'[A-Z0-9_-]{3,40}',code): raise HTTPException(400,'الكود يجب أن يحتوي على حروف إنجليزية أو أرقام فقط')
    if data.discount_type not in ('percent','fixed'): raise HTTPException(400,'نوع الخصم غير صحيح')
    if data.discount_type=='percent' and data.discount_value>100: raise HTTPException(400,'نسبة الخصم لا يمكن أن تتجاوز 100%')
    if data.starts_at and data.ends_at and data.ends_at<=data.starts_at: raise HTTPException(400,'موعد انتهاء الكوبون يجب أن يكون بعد بدايته')
    if db.scalar(select(Coupon.id).where(Coupon.code==code)): raise HTTPException(409,'كود الخصم مستخدم بالفعل')
    item=Coupon(code=code,discount_type=data.discount_type,discount_value=data.discount_value,min_order_total=data.min_order_total,
        max_discount=data.max_discount,usage_limit=data.usage_limit,starts_at=data.starts_at,ends_at=data.ends_at,created_by=user.id)
    db.add(item); db.commit(); db.refresh(item)
    return coupon_out(item)

@app.patch('/api/admin/coupons/{coupon_id}')
def update_coupon(coupon_id:int,data:CouponUpdateIn,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    item=db.get(Coupon,coupon_id)
    if not item: raise HTTPException(404,'الكوبون غير موجود')
    changes=data.model_dump(exclude_unset=True)
    if 'ends_at' in changes and changes['ends_at'] and item.starts_at and changes['ends_at']<=item.starts_at: raise HTTPException(400,'موعد انتهاء الكوبون يجب أن يكون بعد بدايته')
    for key,value in changes.items(): setattr(item,key,value)
    db.commit(); db.refresh(item)
    return coupon_out(item)

@app.get('/api/affiliate/wallet')
def affiliate_wallet(user:User=Depends(require_role('affiliate','admin')),limit:int=Query(default=100,ge=1,le=300),db:Session=Depends(get_db)):
    earned=db.scalar(select(func.coalesce(func.sum(WalletTransaction.amount),0)).where(WalletTransaction.user_id==user.id)) or 0
    rows=db.scalars(select(WalletTransaction).where(WalletTransaction.user_id==user.id).order_by(WalletTransaction.created_at.desc()).limit(limit)).all()
    return {'balance':round(float(earned),2),'transactions':[{'id':x.id,'amount':float(x.amount),'kind':x.kind,'description':x.description,'created_at':x.created_at.isoformat()} for x in rows]}

# Optional first administrator bootstrap: set ADMIN_EMAIL and ADMIN_PASSWORD before first run.
def bootstrap_admin():
    email=os.getenv('ADMIN_EMAIL'); password=os.getenv('ADMIN_PASSWORD')
    if not email or not password: return
    db=SessionLocal()
    try:
        u=db.scalar(select(User).where(User.email==email.lower()))
        if not u:
            db.add(User(name=os.getenv('ADMIN_NAME','مدير وِصلة'),email=email.lower(),password_hash=hash_password(password),role='admin'))
            db.commit()
    finally: db.close()
bootstrap_admin()


# Wesla advanced ecosystem: initial live endpoints backed by dedicated Supabase tables.
@app.get('/api/advanced/rewards/me')
def advanced_rewards_me(user:User=Depends(current_user),db:Session=Depends(get_db)):
    if not wesla_feature_enabled(db, 'rewards', True): raise HTTPException(404, 'هذا النظام متوقف مؤقتًا من إدارة وصلة')
    row=db.execute(text("select points_available,points_pending,lifetime_earned,tier from wesla_reward_accounts where user_id=:uid"),{'uid':user.id}).mappings().first()
    ledger=db.execute(text("select delta,status,source_type,description,created_at from wesla_reward_ledger where user_id=:uid order by created_at desc limit 50"),{'uid':user.id}).mappings().all()
    return {'account':dict(row) if row else {'points_available':0,'points_pending':0,'lifetime_earned':0,'tier':'basic'},'ledger':[dict(x) for x in ledger]}

@app.get('/api/advanced/referrals/me')
def advanced_referrals_me(user:User=Depends(current_user),db:Session=Depends(get_db)):
    if not wesla_feature_enabled(db, 'referrals', True): raise HTTPException(404, 'هذا النظام متوقف مؤقتًا من إدارة وصلة')
    row=db.execute(text("select code from wesla_referral_codes where user_id=:uid"),{'uid':user.id}).mappings().first()
    if not row:
        code='WS'+secrets.token_hex(4).upper()
        db.execute(text("insert into wesla_referral_codes(user_id,code) values (:uid,:code) on conflict(user_id) do nothing"),{'uid':user.id,'code':code})
        db.commit()
        row=db.execute(text("select code from wesla_referral_codes where user_id=:uid"),{'uid':user.id}).mappings().first()
    referrals=db.execute(text("select status,count(*)::int as total,coalesce(sum(reward_points),0)::bigint as points from wesla_referrals where referrer_user_id=:uid group by status"),{'uid':user.id}).mappings().all()
    cfg=db.execute(text("select config,is_enabled from wesla_feature_settings where feature_key='referrals'")).mappings().first()
    reward_points=int(((cfg or {}).get('config') or {}).get('referral_reward_points',0))
    return {'code':row['code'],'referrals':[dict(x) for x in referrals],'reward_points':reward_points,'reward_enabled':bool(cfg and cfg['is_enabled'])}

@app.get('/api/advanced/trends')
def advanced_trends(period:int=Query(default=7,ge=1,le=30),limit:int=Query(default=20,ge=1,le=50),db:Session=Depends(get_db)):
    if not wesla_feature_enabled(db, 'trends', False): raise HTTPException(404, 'هذا النظام متوقف مؤقتًا من إدارة وصلة')
    rows=db.execute(text("""
      select p.id,p.title,p.price,p.stock,
        count(*) filter(where e.event_type='view')::int as views,
        count(*) filter(where e.event_type='favorite')::int as favorites,
        count(*) filter(where e.event_type='order')::int as order_signals,
        count(*)::int as trend_score
      from wesla_trend_events e join products p on p.id=e.product_id
      where p.status='active' and e.created_at >= now() - (:period * interval '1 day')
      group by p.id,p.title,p.price,p.stock
      order by trend_score desc,order_signals desc,views desc
      limit :limit
    """),{'period':period,'limit':limit}).mappings().all()
    return {'period_days':period,'items':[dict(x) for x in rows]}

@app.post('/api/advanced/trends/{product_id}/event')
def advanced_trend_event(product_id:int,data:dict,request:Request,db:Session=Depends(get_db)):
    kind=str(data.get('event_type','view')).strip().lower()
    if kind not in ('view','favorite','order','share'): raise HTTPException(400,'نوع التفاعل غير مدعوم')
    product=db.scalar(select(Product).where(Product.id==product_id,Product.status=='active'))
    if not product: raise HTTPException(404,'المنتج غير متاح')
    token=request.cookies.get('wesla_session','')
    actor=None
    if token:
        try: actor=current_user(request,db)
        except HTTPException: actor=None
    ip=(request.headers.get('x-forwarded-for') or (request.client.host if request.client else 'unknown')).split(',')[0].strip()
    visitor_hash=hashlib.sha256((ip+'|'+request.headers.get('user-agent','')[:250]).encode()).hexdigest()
    recent=db.execute(text("select 1 from wesla_trend_events where product_id=:pid and visitor_hash=:vh and event_type=:kind and created_at>now()-interval '30 minutes' limit 1"),{'pid':product_id,'vh':visitor_hash,'kind':kind}).first()
    if not recent:
        db.execute(text("insert into wesla_trend_events(product_id,user_id,visitor_hash,event_type) values (:pid,:uid,:vh,:kind)"),{'pid':product_id,'uid':actor.id if actor else None,'vh':visitor_hash,'kind':kind})
        db.commit()
    return {'ok':True,'recorded':not bool(recent)}

@app.get('/api/advanced/challenges')
def advanced_challenges(user:User=Depends(current_user),db:Session=Depends(get_db)):
    if not wesla_feature_enabled(db, 'challenges', False): raise HTTPException(404, 'هذا النظام متوقف مؤقتًا من إدارة وصلة')
    rows=db.execute(text("""
      select c.id,c.title,c.description,c.starts_at,c.ends_at,c.reward_points,
        coalesce(cp.status,'not_joined') as my_status
      from wesla_challenges c left join wesla_challenge_participations cp
        on cp.challenge_id=c.id and cp.user_id=:uid
      where c.is_active=true and c.starts_at<=now() and c.ends_at>now()
      order by c.ends_at asc limit 100
    """),{'uid':user.id}).mappings().all()
    return [dict(x) for x in rows]

@app.post('/api/advanced/challenges/{challenge_id}/join')
def advanced_join_challenge(challenge_id:int,user:User=Depends(current_user),db:Session=Depends(get_db)):
    challenge=db.execute(text("select id from wesla_challenges where id=:id and is_active=true and starts_at<=now() and ends_at>now()"),{'id':challenge_id}).first()
    if not challenge: raise HTTPException(404,'التحدي غير متاح حالياً')
    db.execute(text("insert into wesla_challenge_participations(challenge_id,user_id) values (:cid,:uid) on conflict(challenge_id,user_id) do nothing"),{'cid':challenge_id,'uid':user.id})
    db.commit()
    return {'ok':True,'message':'تم تسجيل اشتراكك في التحدي'}

@app.get('/api/advanced/achievements/me')
def advanced_achievements_me(user:User=Depends(current_user),db:Session=Depends(get_db)):
    if not wesla_feature_enabled(db, 'achievements', False): raise HTTPException(404, 'هذا النظام متوقف مؤقتًا من إدارة وصلة')
    rows=db.execute(text("""
      select a.code,a.title,a.description,ua.awarded_at
      from wesla_user_achievements ua join wesla_achievements a on a.id=ua.achievement_id
      where ua.user_id=:uid and a.is_active=true order by ua.awarded_at desc
    """),{'uid':user.id}).mappings().all()
    return [dict(x) for x in rows]

@app.get('/api/advanced/academy')
def advanced_academy(audience:str='all',db:Session=Depends(get_db)):
    if not wesla_feature_enabled(db, 'academy', False): raise HTTPException(404, 'هذا النظام متوقف مؤقتًا من إدارة وصلة')
    if audience not in ('all','customer','merchant','affiliate'): audience='all'
    rows=db.execute(text("""
      select id,title,content_type,audience,body,media_url,created_at
      from wesla_academy_content where is_published=true and audience in ('all',:audience)
      order by created_at desc limit 100
    """),{'audience':audience}).mappings().all()
    return [dict(x) for x in rows]

@app.post('/api/admin/advanced/rewards/adjust')
def admin_adjust_reward_points(data:dict,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    try:
        target_id=int(data.get('user_id'))
        delta=int(data.get('delta'))
    except (TypeError,ValueError):
        raise HTTPException(400,'رقم المستخدم وعدد النقاط مطلوبان')
    event_key=str(data.get('event_key','')).strip()
    description=str(data.get('description','تسوية نقاط بواسطة الإدارة')).strip()[:240]
    if delta==0 or abs(delta)>1000000: raise HTTPException(400,'عدد النقاط غير صالح')
    if not re.fullmatch(r'[A-Za-z0-9:_-]{8,120}',event_key): raise HTTPException(400,'مرجع العملية غير صالح')
    if not db.get(User,target_id): raise HTTPException(404,'المستخدم غير موجود')
    db.execute(text("insert into wesla_reward_accounts(user_id) values (:uid) on conflict(user_id) do nothing"),{'uid':target_id})
    account=db.execute(text("select points_available from wesla_reward_accounts where user_id=:uid for update"),{'uid':target_id}).mappings().first()
    if delta<0 and int(account['points_available']) < abs(delta): raise HTTPException(400,'رصيد النقاط غير كافٍ للخصم')
    ledger=db.execute(text("""
      insert into wesla_reward_ledger(user_id,delta,status,event_key,source_type,source_id,description)
      values (:uid,:delta,'posted',:event_key,'admin_adjustment',:admin_id,:description)
      on conflict(event_key) do nothing returning id
    """),{'uid':target_id,'delta':delta,'event_key':event_key,'admin_id':user.id,'description':description}).first()
    if not ledger: raise HTTPException(409,'تم تسجيل هذه العملية من قبل')
    db.execute(text("""
      update wesla_reward_accounts
      set points_available=points_available+:delta,
          lifetime_earned=greatest(0,lifetime_earned+case when :delta>0 then :delta else 0 end),
          updated_at=now()
      where user_id=:uid
    """),{'uid':target_id,'delta':delta})
    db.commit()
    return {'ok':True,'ledger_id':ledger.id,'user_id':target_id,'delta':delta}

# Every feature has an independent admin switch. Feature availability is controlled
# by the database flag; implementation-specific endpoints still validate their own data.
# Only systems with implemented user-facing flows and real backend routes can be enabled.
# The remaining switches stay visible in admin as "in development" and are not exposed to users.
FEATURE_READY = {
    'referrals': True, 'rewards': True, 'trends': False, 'challenges': False,
    'achievements': False, 'academy': False,
    'wesla_ai': False, 'recommendations': False, 'seasonal_campaigns': False,
    'fraud_detection': False, 'admin_activity_log': True, 'smart_marketer_matching': False,
    'inventory_order_alerts': False, 'marketer_competitions': False, 'verified_reviews': False,
    'advanced_order_tracking': True, 'premium_subscriptions': False, 'ads_center': False,
    'marketing_library': False, 'wallet_ledger': True, 'disputes_center': False,
    'bulk_product_import': False, 'price_drop_alerts': False, 'bundles_deals': False
}
FEATURE_KEYS = set(FEATURE_READY)

def wesla_feature_enabled(db: Session, feature_key: str, default: bool = True) -> bool:
    # A database toggle can never expose a module before its implementation is ready.
    if not FEATURE_READY.get(feature_key, False):
        return False
    value = db.execute(text("select is_enabled from wesla_feature_settings where feature_key=:key"),
                       {'key': feature_key}).scalar()
    return bool(default if value is None else value)

@app.get('/api/advanced/features')
def advanced_feature_status(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.execute(text("select feature_key,is_enabled,audience from wesla_feature_settings")).mappings().all()
    stored = {r['feature_key']: r for r in rows}
    result = {}
    for key in FEATURE_KEYS:
        setting = stored.get(key)
        audience = setting.get('audience') if setting else []
        if isinstance(audience, str):
            try: audience = json.loads(audience)
            except Exception: audience = []
        audience = audience or []
        role_allowed = 'all' in audience or user.role in audience
        result[key] = bool(FEATURE_READY[key] and setting and setting['is_enabled'] and role_allowed)
    return result

@app.get('/api/admin/activity-log')
def list_admin_activity_log(limit: int = Query(default=200, ge=1, le=500), user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    rows = db.execute(text("""
      select l.id,coalesce(l.actor_name,u.name,'مدير سابق') as actor_name,l.action,l.request_path,
             l.target_id,l.status_code,l.created_at
      from wesla_admin_activity_log l left join users u on u.id=l.actor_user_id
      order by l.created_at desc,l.id desc limit :limit
    """), {'limit':limit}).mappings().all()
    return [dict(x) for x in rows]

@app.get('/api/admin/advanced/settings')
def admin_advanced_settings(user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    rows=db.execute(text("select feature_key,is_enabled,audience,config,updated_at from wesla_feature_settings order by feature_key")).mappings().all()
    return [dict(x) for x in rows]

@app.patch('/api/admin/advanced/settings/{feature_key}')
def update_admin_advanced_setting(feature_key:str,data:dict,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    allowed=FEATURE_KEYS
    if feature_key not in allowed: raise HTTPException(404,'الميزة غير معروفة')
    enabled=data.get('is_enabled')
    if not isinstance(enabled,bool): raise HTTPException(400,'حالة التفعيل غير صحيحة')
    if enabled and not FEATURE_READY.get(feature_key, False): raise HTTPException(409,'هذا النظام ما زال قيد الربط والاختبار، ولا يمكن تفعيله قبل اكتماله')
    audience=data.get('audience',[])
    if not isinstance(audience,list) or any(x not in ('all','customer','merchant','affiliate','visitor','admin') for x in audience): raise HTTPException(400,'الجمهور المحدد غير صحيح')
    config=data.get('config',{})
    if not isinstance(config,dict): raise HTTPException(400,'الإعدادات غير صحيحة')
    db.execute(text("""
      insert into wesla_feature_settings(feature_key,is_enabled,audience,config,updated_at)
      values (:key,:enabled,cast(:audience as jsonb),cast(:config as jsonb),now())
      on conflict(feature_key) do update set is_enabled=excluded.is_enabled,audience=excluded.audience,config=wesla_feature_settings.config || excluded.config,updated_at=now()
    """),{'key':feature_key,'enabled':enabled,'audience':json.dumps(audience),'config':json.dumps(config)})
    db.commit()
    return {'ok':True,'feature_key':feature_key,'is_enabled':enabled}


# Wesla operational features requested by the owner: public merchant directory,
# referral/rewards administration, visitor analytics, internal pages and account actions.
class PublicVisitIn(BaseModel):
    visitor_key: str = Field(min_length=24, max_length=64)
    path: str = Field(default='/', max_length=500)

class InternalPageIn(BaseModel):
    slug: str = Field(min_length=2, max_length=100)
    title: str = Field(min_length=2, max_length=180)
    body: str = Field(min_length=1, max_length=30000)
    audience: str = Field(default='all', max_length=20)
    is_published: bool = False

class AccountActionIn(BaseModel):
    status: str
    reason: str = Field(min_length=5, max_length=2000)

class MerchantPenaltyIn(BaseModel):
    amount_egp: Decimal = Field(gt=0, max_digits=12, decimal_places=2)
    reason: str = Field(min_length=10, max_length=3000)
    contract_id: int | None = None

class PenaltyDecisionIn(BaseModel):
    decision: str
    admin_note: str = Field(min_length=5, max_length=2000)

class ReferralRewardConfigIn(BaseModel):
    referral_reward_points: int = Field(ge=0, le=100000)
    purchase_points_per_100_egp: int = Field(default=0, ge=0, le=10000)

class RewardOfferIn(BaseModel):
    title: str = Field(min_length=2, max_length=180)
    description: str = Field(default='', max_length=3000)
    points_cost: int = Field(gt=0, le=1000000)
    discount_type: str
    discount_value: Decimal = Field(gt=0, max_digits=12, decimal_places=2)
    min_order_total: Decimal = Field(default=Decimal('0'), ge=0, max_digits=12, decimal_places=2)
    max_discount: Decimal | None = Field(default=None, gt=0, max_digits=12, decimal_places=2)
    coupon_valid_days: int = Field(default=30, ge=1, le=365)
    usage_limit: int = Field(default=1, ge=1, le=1000)
    is_active: bool = True

class RewardRedeemIn(BaseModel):
    request_key: str = Field(min_length=16, max_length=80)

@app.post('/api/public/visit')
def record_public_visit(data: PublicVisitIn, request: Request, db: Session = Depends(get_db)):
    if not re.fullmatch(r'[A-Za-z0-9_-]{24,64}', data.visitor_key):
        raise HTTPException(400, 'معرّف الزائر غير صالح')
    path = data.path if data.path.startswith('/') and not data.path.startswith('//') else '/'
    path = path.split('?', 1)[0][:500]
    actor = None
    token = request.cookies.get('wesla_session')
    if token:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        session = db.scalar(select(AuthSession).where(AuthSession.token_hash == token_hash))
        if session:
            actor = db.get(User, session.user_id)
            if actor and actor.status != 'active':
                actor = None
    db.execute(text("""
      insert into wesla_site_visits(visitor_key,visit_date,path,user_id)
      values (:key,current_date,:path,:uid)
      on conflict(visitor_key,visit_date) do nothing
    """), {'key': data.visitor_key, 'path': path, 'uid': actor.id if actor else None})
    db.commit()
    return {'ok': True}

@app.get('/api/admin/visitors')
def admin_visitor_analytics(user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    totals = db.execute(text("""
      select count(*)::int as unique_visits_today,
             (select count(distinct visitor_key)::int from wesla_site_visits where created_at >= now()-interval '30 days') as unique_visitors_30d,
             (select count(*)::int from wesla_site_visits where created_at >= now()-interval '30 days') as visit_days_30d,
             (select count(*)::int from wesla_site_visits) as total_visit_days
      from wesla_site_visits where visit_date=current_date
    """)).mappings().first()
    daily = db.execute(text("""
      select visit_date, count(*)::int as visitors
      from wesla_site_visits
      where visit_date >= current_date - 13
      group by visit_date order by visit_date
    """)).mappings().all()
    paths = db.execute(text("""
      select path, count(*)::int as visitors
      from wesla_site_visits
      where created_at >= now()-interval '30 days'
      group by path order by visitors desc limit 15
    """)).mappings().all()
    return {'summary': dict(totals or {}), 'daily': [dict(x) for x in daily], 'top_paths': [dict(x) for x in paths]}

@app.get('/api/public/merchants')
def public_merchants(response: Response, db: Session = Depends(get_db)):
    rows = db.execute(text("""
      select u.id,u.name,count(p.id)::int as product_count
      from users u left join products p on p.merchant_id=u.id and p.status='active'
      where u.role='merchant' and u.status='active'
      group by u.id,u.name
      order by product_count desc,u.created_at desc limit 100
    """)).mappings().all()
    response.headers['Cache-Control'] = 'public, max-age=20, stale-while-revalidate=60'
    return [dict(x) for x in rows]

@app.get('/api/public/pages')
def public_internal_pages(request: Request, db: Session = Depends(get_db)):
    role = 'visitor'
    token = request.cookies.get('wesla_session')
    if token:
        session = db.scalar(select(AuthSession).where(AuthSession.token_hash == hashlib.sha256(token.encode()).hexdigest()))
        if session:
            actor = db.get(User, session.user_id)
            if actor and actor.status == 'active' and actor.role in ('customer','merchant','affiliate'):
                role = actor.role
    rows = db.execute(text("""
      select slug,title,audience,updated_at from wesla_internal_pages
      where is_published=true and audience in ('all',:role)
      order by updated_at desc limit 100
    """), {'role': role}).mappings().all()
    return [dict(x) for x in rows]

@app.get('/api/public/pages/{slug}')
def public_internal_page(slug: str, request: Request, db: Session = Depends(get_db)):
    role = 'visitor'
    token = request.cookies.get('wesla_session')
    if token:
        session = db.scalar(select(AuthSession).where(AuthSession.token_hash == hashlib.sha256(token.encode()).hexdigest()))
        if session:
            actor = db.get(User, session.user_id)
            if actor and actor.status == 'active' and actor.role in ('customer','merchant','affiliate'):
                role = actor.role
    row = db.execute(text("""
      select slug,title,body,audience,updated_at from wesla_internal_pages
      where slug=:slug and is_published=true and audience in ('all',:role)
    """), {'slug': slug, 'role': role}).mappings().first()
    if not row:
        raise HTTPException(404, 'الصفحة غير متاحة')
    return dict(row)

@app.get('/api/admin/pages')
def admin_list_internal_pages(user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    rows = db.execute(text("select id,slug,title,body,audience,is_published,created_at,updated_at from wesla_internal_pages order by updated_at desc,id desc")).mappings().all()
    return [dict(x) for x in rows]

@app.post('/api/admin/pages')
def admin_create_internal_page(data: InternalPageIn, user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    slug = re.sub(r'[^a-z0-9-]+', '-', data.slug.lower()).strip('-')
    if len(slug) < 2:
        raise HTTPException(400, 'الرابط المختصر يجب أن يحتوي على حرفين أو أكثر باللغة الإنجليزية أو أرقام')
    if data.audience not in ('all','visitor','customer','merchant','affiliate'):
        raise HTTPException(400, 'الجمهور المحدد غير صحيح')
    try:
        row = db.execute(text("""
          insert into wesla_internal_pages(slug,title,body,audience,is_published,created_by)
          values (:slug,:title,:body,:audience,:published,:actor)
          returning id,slug,title,is_published
        """), {'slug':slug,'title':data.title.strip(),'body':data.body,'audience':data.audience,'published':data.is_published,'actor':user.id}).mappings().first()
        db.commit()
        return dict(row)
    except Exception:
        db.rollback()
        raise HTTPException(409, 'الرابط المختصر مستخدم بالفعل أو تعذر حفظ الصفحة')

@app.patch('/api/admin/pages/{page_id}')
def admin_update_internal_page(page_id: int, data: InternalPageIn, user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    slug = re.sub(r'[^a-z0-9-]+', '-', data.slug.lower()).strip('-')
    if len(slug) < 2 or data.audience not in ('all','visitor','customer','merchant','affiliate'):
        raise HTTPException(400, 'بيانات الصفحة أو الجمهور غير صحيحة')
    result = db.execute(text("""
      update wesla_internal_pages set slug=:slug,title=:title,body=:body,audience=:audience,
        is_published=:published,updated_at=now()
      where id=:id returning id,slug,title,is_published
    """), {'slug':slug,'title':data.title.strip(),'body':data.body,'audience':data.audience,'published':data.is_published,'id':page_id}).mappings().first()
    if not result:
        raise HTTPException(404, 'الصفحة غير موجودة')
    db.commit()
    return dict(result)

@app.delete('/api/admin/pages/{page_id}')
def admin_delete_internal_page(page_id: int, user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    result = db.execute(text("delete from wesla_internal_pages where id=:id returning id"), {'id':page_id}).first()
    if not result:
        raise HTTPException(404, 'الصفحة غير موجودة')
    db.commit()
    return {'ok': True}

@app.get('/api/admin/accounts')
def admin_accounts(role: str = Query(default='all'), status: str = Query(default='all'), limit: int = Query(default=500, ge=1, le=1000), user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    if role not in ('all','merchant','customer','affiliate','admin') or status not in ('all','active','suspended','banned','inactive'):
        raise HTTPException(400, 'فلتر الحسابات غير صحيح')
    clauses = []
    params = {'limit': limit}
    if role != 'all':
        clauses.append('u.role=:role'); params['role'] = role
    if status != 'all':
        clauses.append('u.status=:status'); params['status'] = status
    where = ('where ' + ' and '.join(clauses)) if clauses else ''
    rows = db.execute(text(f"""
      select u.id,u.name,u.email,u.role,u.status,u.contact_phone,u.contact_whatsapp,u.contact_public,u.created_at,
        (select count(*)::int from products p where p.merchant_id=u.id and p.status='active') as product_count,
        (select count(*)::int from products p where p.merchant_id=u.id and p.status='deleted') as deleted_product_count,
        (select count(*)::int from orders o where o.merchant_id=u.id) as merchant_orders,
        (select count(*)::int from orders o where o.affiliate_id=u.id) as affiliate_orders,
        (select count(*)::int from orders o where o.customer_user_id=u.id) as customer_orders
      from users u {where} order by u.created_at desc,u.id desc limit :limit
    """), params).mappings().all()
    return [dict(x) for x in rows]

@app.patch('/api/admin/accounts/{account_id}/status')
def admin_update_account_status(account_id: int, data: AccountActionIn, user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    if data.status not in ('active','suspended','banned'):
        raise HTTPException(400, 'الحالة يجب أن تكون نشط أو موقوف مؤقتاً أو محظور')
    target = db.get(User, account_id)
    if not target:
        raise HTTPException(404, 'الحساب غير موجود')
    if target.role == 'admin':
        raise HTTPException(403, 'لا يمكن تنفيذ هذا الإجراء على حساب إدارة المنصة')
    if target.status == data.status:
        raise HTTPException(409, 'الحساب بالفعل بهذه الحالة')
    old_status = target.status
    target.status = data.status
    action = 'restore' if data.status == 'active' else ('ban' if data.status == 'banned' else 'suspend')
    db.execute(text("insert into wesla_account_actions(target_user_id,actor_user_id,action,reason) values (:target,:actor,:action,:reason)"),
      {'target':target.id,'actor':user.id,'action':action,'reason':data.reason.strip()})
    db.commit()
    return {'ok':True,'old_status':old_status,'status':target.status}

@app.get('/api/admin/merchants/{merchant_id}/penalties')
def admin_merchant_penalties(merchant_id: int, user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    rows = db.execute(text("""
      select p.id,p.amount_egp,p.reason,p.status,p.admin_note,p.contract_id,p.created_at,
             c.contract_number,c.title as contract_title
      from wesla_merchant_penalties p left join contracts c on c.id=p.contract_id
      where p.merchant_id=:id order by p.created_at desc
    """), {'id':merchant_id}).mappings().all()
    return [dict(x) for x in rows]

@app.post('/api/admin/merchants/{merchant_id}/penalties')
def admin_create_merchant_penalty(merchant_id: int, data: MerchantPenaltyIn, user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    merchant = db.get(User, merchant_id)
    if not merchant or merchant.role != 'merchant':
        raise HTTPException(404, 'حساب التاجر غير موجود')
    if data.contract_id:
        contract = db.get(Contract, data.contract_id)
        if not contract or contract.merchant_id != merchant_id:
            raise HTTPException(400, 'الاتفاقية لا تخص هذا التاجر')
        if contract.status != 'signed' or not contract.penalty_terms.strip() or not contract.penalty_type:
            raise HTTPException(400, 'اختر اتفاقية موقعة تتضمن شرطاً جزائياً موثقاً')
    row = db.execute(text("""
      insert into wesla_merchant_penalties(merchant_id,contract_id,amount_egp,reason,created_by)
      values (:merchant,:contract,:amount,:reason,:actor)
      returning id,status,amount_egp,created_at
    """), {'merchant':merchant_id,'contract':data.contract_id,'amount':data.amount_egp,'reason':data.reason.strip(),'actor':user.id}).mappings().first()
    db.commit()
    return dict(row)

@app.post('/api/admin/merchants/penalties/{penalty_id}/decision')
def admin_decide_merchant_penalty(penalty_id: int, data: PenaltyDecisionIn, user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    penalty = db.execute(text("select * from wesla_merchant_penalties where id=:id for update"), {'id':penalty_id}).mappings().first()
    if not penalty:
        raise HTTPException(404, 'الغرامة غير موجودة')
    if penalty['status'] != 'pending':
        raise HTTPException(409, 'تمت مراجعة هذا السجل بالفعل')
    if data.decision not in ('confirm','waive','dispute'):
        raise HTTPException(400, 'القرار غير صحيح')
    if data.decision == 'confirm':
        contract = db.get(Contract, penalty['contract_id']) if penalty['contract_id'] else None
        if not contract or contract.merchant_id != penalty['merchant_id'] or contract.status != 'signed':
            raise HTTPException(400, 'لا يمكن تأكيد غرامة دون اتفاقية موقعة تخص التاجر')
        if not contract.penalty_terms.strip() or not contract.penalty_type:
            raise HTTPException(400, 'الاتفاقية لا تحتوي على شرط جزائي موثق')
        if contract.penalty_type == 'fixed' and (contract.penalty_amount is None or Decimal(str(penalty['amount_egp'])) > Decimal(str(contract.penalty_amount))):
            raise HTTPException(400, 'قيمة الغرامة تتجاوز الحد الثابت الوارد في الاتفاقية')
    status = {'confirm':'confirmed','waive':'waived','dispute':'disputed'}[data.decision]
    db.execute(text("update wesla_merchant_penalties set status=:status,admin_note=:note,updated_at=now() where id=:id"),
      {'status':status,'note':data.admin_note.strip(),'id':penalty_id})
    db.commit()
    return {'ok':True,'status':status,'note':'تم تسجيل القرار. لا يتم خصم المبلغ آلياً من حساب التاجر.'}

@app.get('/api/admin/referrals')
def admin_referrals(user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    rows = db.execute(text("""
      select r.id,r.referral_code,r.status,r.reward_points,r.created_at,r.qualified_at,
             inviter.id as inviter_id,inviter.name as inviter_name,inviter.email as inviter_email,
             invited.id as invited_id,invited.name as invited_name,invited.email as invited_email
      from wesla_referrals r
      join users inviter on inviter.id=r.referrer_user_id
      join users invited on invited.id=r.referred_user_id
      order by r.created_at desc limit 500
    """)).mappings().all()
    return [dict(x) for x in rows]

@app.get('/api/admin/referral-rewards/config')
def admin_referral_rewards_config(user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    rows = db.execute(text("select feature_key,config,is_enabled from wesla_feature_settings where feature_key in ('referrals','rewards')")).mappings().all()
    cfg = {r['feature_key']: (r['config'] or {}) for r in rows}
    return {'referrals_enabled': bool(next((r['is_enabled'] for r in rows if r['feature_key']=='referrals'), True)),
            'rewards_enabled': bool(next((r['is_enabled'] for r in rows if r['feature_key']=='rewards'), True)),
            'referral_reward_points': int((cfg.get('referrals') or {}).get('referral_reward_points',0)),
            'purchase_points_per_100_egp': int((cfg.get('rewards') or {}).get('purchase_points_per_100_egp',0))}

@app.patch('/api/admin/referral-rewards/config')
def admin_update_referral_rewards_config(data: ReferralRewardConfigIn, user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    db.execute(text("""
      insert into wesla_feature_settings(feature_key,is_enabled,audience,config,updated_at)
      values ('referrals',true,'["all"]'::jsonb,jsonb_build_object('referral_reward_points'::text,CAST(:points AS integer)),now())
      on conflict(feature_key) do update set config=wesla_feature_settings.config || excluded.config,updated_at=now()
    """), {'points':data.referral_reward_points})
    db.execute(text("""
      insert into wesla_feature_settings(feature_key,is_enabled,audience,config,updated_at)
      values ('rewards',true,'["all"]'::jsonb,jsonb_build_object('purchase_points_per_100_egp'::text,CAST(:points AS integer)),now())
      on conflict(feature_key) do update set config=wesla_feature_settings.config || excluded.config,updated_at=now()
    """), {'points':data.purchase_points_per_100_egp})
    db.commit()
    return {'ok':True,'referral_reward_points':data.referral_reward_points,'purchase_points_per_100_egp':data.purchase_points_per_100_egp}

@app.post('/api/admin/referrals/{referral_id}/qualify')
def admin_qualify_referral(referral_id: int, user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    ref = db.execute(text("select * from wesla_referrals where id=:id for update"), {'id':referral_id}).mappings().first()
    if not ref:
        raise HTTPException(404, 'الإحالة غير موجودة')
    if ref['status'] != 'registered':
        raise HTTPException(409, 'الإحالة تمت مراجعتها بالفعل')
    config = db.execute(text("select config,is_enabled from wesla_feature_settings where feature_key='referrals'")).mappings().first()
    points = int(((config or {}).get('config') or {}).get('referral_reward_points',0))
    if not config or not config['is_enabled'] or points <= 0:
        raise HTTPException(400, 'فعّل برنامج الإحالات وحدد مكافأة أكبر من صفر أولاً')
    event_key = 'referral:' + str(referral_id)
    db.execute(text("insert into wesla_reward_accounts(user_id) values (:uid) on conflict(user_id) do nothing"), {'uid':ref['referrer_user_id']})
    inserted = db.execute(text("""
      insert into wesla_reward_ledger(user_id,delta,status,event_key,source_type,source_id,description)
      values (:uid,:points,'posted',:event,'referral',:rid,'مكافأة إحالة صديق مؤهلة')
      on conflict(event_key) do nothing returning id
    """), {'uid':ref['referrer_user_id'],'points':points,'event':event_key,'rid':referral_id}).first()
    if not inserted:
        raise HTTPException(409, 'تم صرف مكافأة هذه الإحالة من قبل')
    db.execute(text("""
      update wesla_reward_accounts
      set points_available=points_available+:points,lifetime_earned=lifetime_earned+:points,
          tier=case when lifetime_earned+:points>=3000 then 'platinum'
                    when lifetime_earned+:points>=1500 then 'gold'
                    when lifetime_earned+:points>=500 then 'silver' else 'basic' end,
          updated_at=now()
      where user_id=:uid
    """), {'points':points,'uid':ref['referrer_user_id']})
    db.execute(text("update wesla_referrals set status='qualified',reward_points=:points,qualified_at=now() where id=:id"),
      {'points':points,'id':referral_id})
    db.commit()
    return {'ok':True,'points_awarded':points}

@app.get('/api/admin/account-actions/{account_id}')
def admin_account_action_history(account_id: int, user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    rows = db.execute(text("""
      select action,reason,created_at from wesla_account_actions
      where target_user_id=:id order by created_at desc limit 100
    """), {'id':account_id}).mappings().all()
    return [dict(x) for x in rows]


@app.get('/api/advanced/rewards/offers')
def advanced_reward_offers(user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not wesla_feature_enabled(db, 'rewards', True): raise HTTPException(404, 'هذا النظام متوقف مؤقتًا من إدارة وصلة')
    rows=db.execute(text("""
      select id,title,description,points_cost,discount_type,discount_value,min_order_total,max_discount,
             coupon_valid_days,usage_limit
      from wesla_reward_offers where is_active=true and points_cost>0
      order by points_cost asc,id desc limit 100
    """)).mappings().all()
    return [dict(x) for x in rows]

@app.post('/api/advanced/rewards/redeem/{offer_id}')
def redeem_reward_offer(offer_id: int, data: RewardRedeemIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not wesla_feature_enabled(db, 'rewards', True): raise HTTPException(404, 'هذا النظام متوقف مؤقتًا من إدارة وصلة')
    if not re.fullmatch(r'[A-Za-z0-9_-]{16,80}', data.request_key):
        raise HTTPException(400, 'مرجع الاستبدال غير صالح')
    existing=db.execute(text("""
      select c.code,c.ends_at,r.points_spent
      from wesla_reward_redemptions r join coupons c on c.id=r.coupon_id
      where r.user_id=:uid and r.request_key=:key
    """), {'uid':user.id,'key':data.request_key}).mappings().first()
    if existing:
        return {'ok':True,'coupon_code':existing['code'],'points_spent':existing['points_spent'],'ends_at':existing['ends_at']}
    offer=db.execute(text("select * from wesla_reward_offers where id=:id and is_active=true for update"), {'id':offer_id}).mappings().first()
    if not offer:
        raise HTTPException(404, 'المكافأة غير متاحة')
    db.execute(text("insert into wesla_reward_accounts(user_id) values (:uid) on conflict(user_id) do nothing"), {'uid':user.id})
    account=db.execute(text("select points_available from wesla_reward_accounts where user_id=:uid for update"), {'uid':user.id}).mappings().first()
    cost=int(offer['points_cost'])
    if int(account['points_available'])<cost:
        raise HTTPException(400, 'رصيد النقاط غير كافٍ لاستبدال المكافأة')
    now=datetime.now(timezone.utc)
    coupon=Coupon(
      code='WESLA'+secrets.token_hex(4).upper(),
      discount_type=offer['discount_type'],
      discount_value=offer['discount_value'],
      min_order_total=offer['min_order_total'],
      max_discount=offer['max_discount'],
      usage_limit=int(offer['usage_limit']),
      used_count=0,
      starts_at=now,
      ends_at=now+timedelta(days=int(offer['coupon_valid_days'])),
      is_active=True,
      created_by=user.id
    )
    db.add(coupon); db.flush()
    redemption=db.execute(text("""
      insert into wesla_reward_redemptions(offer_id,user_id,coupon_id,points_spent,request_key)
      values (:offer,:uid,:coupon,:points,:request_key)
      on conflict(request_key) do nothing returning id
    """), {'offer':offer_id,'uid':user.id,'coupon':coupon.id,'points':cost,'request_key':data.request_key}).first()
    if not redemption:
        db.rollback()
        existing=db.execute(text("""
          select c.code,c.ends_at,r.points_spent from wesla_reward_redemptions r
          join coupons c on c.id=r.coupon_id where r.user_id=:uid and r.request_key=:key
        """), {'uid':user.id,'key':data.request_key}).mappings().first()
        if existing:
            return {'ok':True,'coupon_code':existing['code'],'points_spent':existing['points_spent'],'ends_at':existing['ends_at']}
        raise HTTPException(409, 'مرجع الاستبدال مستخدم بالفعل')
    db.execute(text("""
      insert into wesla_reward_ledger(user_id,delta,status,event_key,source_type,source_id,description)
      values (:uid,:delta,'posted',:event,'reward_redemption',:offer,'استبدال نقاط بمكافأة')
      on conflict(event_key) do nothing
    """), {'uid':user.id,'delta':-cost,'event':'reward-redeem:'+data.request_key,'offer':offer_id})
    db.execute(text("update wesla_reward_accounts set points_available=points_available-:points,updated_at=now() where user_id=:uid"),
      {'points':cost,'uid':user.id})
    db.commit()
    return {'ok':True,'coupon_code':coupon.code,'points_spent':cost,'ends_at':coupon.ends_at}

@app.get('/api/admin/rewards/offers')
def admin_reward_offers(user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    rows=db.execute(text("select * from wesla_reward_offers order by created_at desc,id desc")).mappings().all()
    return [dict(x) for x in rows]

@app.post('/api/admin/rewards/offers')
def admin_create_reward_offer(data: RewardOfferIn, user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    if data.discount_type not in ('fixed','percent'):
        raise HTTPException(400,'نوع الخصم يجب أن يكون مبلغاً ثابتاً أو نسبة مئوية')
    if data.discount_type=='percent' and data.discount_value>100:
        raise HTTPException(400,'نسبة الخصم لا يمكن أن تتجاوز 100%')
    row=db.execute(text("""
      insert into wesla_reward_offers(title,description,points_cost,discount_type,discount_value,min_order_total,max_discount,coupon_valid_days,usage_limit,is_active,created_by)
      values (:title,:description,:points,:type,:value,:minimum,:maximum,:days,:limit,:active,:actor)
      returning id
    """), {'title':data.title.strip(),'description':data.description,'points':data.points_cost,'type':data.discount_type,'value':data.discount_value,'minimum':data.min_order_total,'maximum':data.max_discount,'days':data.coupon_valid_days,'limit':data.usage_limit,'active':data.is_active,'actor':user.id}).first()
    db.commit()
    return {'ok':True,'id':row.id}

@app.patch('/api/admin/rewards/offers/{offer_id}')
def admin_update_reward_offer(offer_id: int, data: RewardOfferIn, user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    if data.discount_type not in ('fixed','percent') or (data.discount_type=='percent' and data.discount_value>100):
        raise HTTPException(400,'بيانات الخصم غير صحيحة')
    result=db.execute(text("""
      update wesla_reward_offers set title=:title,description=:description,points_cost=:points,
        discount_type=:type,discount_value=:value,min_order_total=:minimum,max_discount=:maximum,
        coupon_valid_days=:days,usage_limit=:limit,is_active=:active,updated_at=now()
      where id=:id returning id
    """), {'title':data.title.strip(),'description':data.description,'points':data.points_cost,'type':data.discount_type,'value':data.discount_value,'minimum':data.min_order_total,'maximum':data.max_discount,'days':data.coupon_valid_days,'limit':data.usage_limit,'active':data.is_active,'id':offer_id}).first()
    if not result:
        raise HTTPException(404,'المكافأة غير موجودة')
    db.commit()
    return {'ok':True}

@app.delete('/api/admin/rewards/offers/{offer_id}')
def admin_disable_reward_offer(offer_id: int, user: User = Depends(require_role('admin')), db: Session = Depends(get_db)):
    result=db.execute(text("update wesla_reward_offers set is_active=false,updated_at=now() where id=:id returning id"), {'id':offer_id}).first()
    if not result:
        raise HTTPException(404,'المكافأة غير موجودة')
    db.commit()
    return {'ok':True}

# Friendly public routes: unknown non-API paths serve the app shell so shared links
# and custom pages work without requiring a special /chat suffix.
@app.get('/{full_path:path}')
def public_spa_fallback(full_path: str):
    if full_path.startswith(('api/','static/')):
        raise HTTPException(404, 'Not Found')
    return FileResponse('app/static/index.html', headers={'Cache-Control':'no-store, no-cache, must-revalidate, max-age=0','Pragma':'no-cache','Expires':'0'})
