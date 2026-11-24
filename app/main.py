import os, secrets, hashlib, hmac, json, base64, binascii
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, HTTPException, Response, Request, Query
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import select, func, text
from .database import Base, engine, get_db, SessionLocal
from .models import User, Application, Product, Link, Order, Payout, AuthSession, Contract, ContractAcceptance, ProductVariant, ProductSizeGuide, ProductImage, ContractEvent, ContractTerminationRequest, CommissionChangeRequest, AffiliateProductExclusion, ProductAuditEvent, ContractRequest, ContractNegotiation, Notification

Base.metadata.create_all(bind=engine)
app=FastAPI(title='Wesla Affiliate Platform', version='1.0.0')

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
class RegisterIn(BaseModel): name:str=Field(min_length=2,max_length=120); email:str; password:str=Field(min_length=8,max_length=128)
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
    referral_code:str|None=None; variant_id:int|None=None
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
    # Never cache the public shell: an older cached bundle could redirect admins to /control.
    return FileResponse('app/static/index.html',headers={'Cache-Control':'no-store, no-cache, must-revalidate, max-age=0','Pragma':'no-cache','Expires':'0'})
@app.get('/control')
def control_page():
    # The admin portal is reachable only through its dedicated route, never from the public home page.
    admin_url=os.getenv('ADMIN_PORTAL_URL','').strip()
    if admin_url:
        return RedirectResponse(admin_url,status_code=307,headers={'Cache-Control':'no-store'})
    return FileResponse('app/static/control.html',headers={'Cache-Control':'no-store, no-cache, must-revalidate, max-age=0','Pragma':'no-cache','Expires':'0'})

@app.get('/health')
def health(): return {'ok':True,'service':'wesla'}
@app.post('/api/register')
def register(data:RegisterIn,db:Session=Depends(get_db)):
    email=str(data.email).lower()
    if db.scalar(select(User).where(User.email==email)): raise HTTPException(409,'البريد الإلكتروني مسجل بالفعل')
    u=User(name=data.name.strip(),email=email,password_hash=hash_password(data.password),role='customer')
    db.add(u); db.commit(); db.refresh(u); return {'message':'تم إنشاء الحساب. يمكنك التقديم كتاجر أو مسوق.','user':public_user(u)}
@app.post('/api/login')
def login(data:LoginIn,response:Response,db:Session=Depends(get_db)):
    u=db.scalar(select(User).where(User.email==str(data.email).lower()))
    if not u or not verify_password(data.password,u.password_hash): raise HTTPException(401,'بيانات الدخول غير صحيحة')
    if u.status!='active': raise HTTPException(403,'الحساب غير نشط')
    token=secrets.token_urlsafe(32); db.add(AuthSession(token_hash=hashlib.sha256(token.encode()).hexdigest(),user_id=u.id,expires_at=datetime.now(timezone.utc)+timedelta(days=7))); db.commit()
    set_session_cookie(response,token,60*60*24*7)
    return {'user':public_user(u)}
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
    rows=db.scalars(select(Product).where(Product.status=='active').order_by(Product.created_at.desc(),Product.id.desc()).limit(limit).offset(offset)).all()
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
    rows=db.scalars(select(Product).where(Product.merchant_id==owner.id,Product.status=='active').order_by(Product.created_at.desc(),Product.id.desc()).limit(limit).offset(offset)).all()
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
    chosen_price=variant.price_override if variant and variant.price_override is not None else p.price
    total=(Decimal(chosen_price)*data.quantity).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP); ac=(total*Decimal(p.affiliate_rate)/Decimal(100)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP) if affiliate_id else Decimal('0.00'); pc=(total*Decimal(p.platform_rate)/Decimal(100)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    order=Order(order_number='WS'+secrets.token_hex(5).upper(),customer_name=data.customer_name,customer_phone=data.customer_phone,address=data.address,product_id=p.id,merchant_id=p.merchant_id,affiliate_id=affiliate_id,quantity=data.quantity,variant_id=variant.id if variant else None,selected_color=variant.color if variant else None,selected_size=variant.size_label if variant else None,unit_price=chosen_price,total=total,affiliate_rate_snapshot=p.affiliate_rate,platform_rate_snapshot=p.platform_rate,affiliate_commission=ac,platform_commission=pc)
    if variant: variant.stock-=data.quantity
    p.stock-=data.quantity
    # Hide the product from all public catalogues as soon as its total stock reaches zero.
    # Keep the product/order history in the database; it can be republished by restocking.
    if p.stock<=0: p.status='sold_out'
    db.add(order)
    notify_user(db,p.merchant_id,'طلب جديد على منتجك',f'رقم الطلب {order.order_number} — إجمالي {total} جنيه','/dashboard')
    if affiliate_id:
        notify_user(db,affiliate_id,'طلب جديد من رابطك التسويقي',f'رقم الطلب {order.order_number}. ستظهر عمولتك بعد تأكيد التسليم.','/dashboard')
    db.commit(); db.refresh(order)
    return {'order_number':order.order_number,'status':order.status,'total':total,'message':'تم تسجيل الطلب. سيتواصل معك التاجر لتأكيده.'}
@app.post('/api/orders/track')
def track_order(data:OrderTrackIn,db:Session=Depends(get_db)):
    row=db.execute(select(Order,Product.title).join(Product,Product.id==Order.product_id).where(Order.order_number==data.order_number.strip().upper(),Order.customer_phone==data.customer_phone.strip())).first()
    if not row: raise HTTPException(404,'بيانات الطلب غير صحيحة. راجع رقم الطلب ورقم الهاتف.')
    order,title=row
    labels={'pending':'تم استلام الطلب','confirmed':'تم تأكيد الطلب','shipped':'الطلب في الطريق إليك','delivered':'تم تسليم الطلب','cancelled':'تم إلغاء الطلب','returned':'تم إرجاع الطلب'}
    return {'order_number':order.order_number,'product':title,'quantity':order.quantity,'total':float(order.total),'status':order.status,'status_label':labels.get(order.status,order.status),'created_at':order.created_at.isoformat()}

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
    p=Payout(affiliate_id=user.id,amount=Decimal(str(data.amount)),method=data.method,destination=data.destination); db.add(p); db.commit(); return {'message':'تم إرسال طلب السحب للإدارة'}
@app.get('/api/merchant/orders')
def merchant_orders(limit:int=Query(default=100,ge=1,le=200),offset:int=Query(default=0,ge=0),user:User=Depends(require_role('merchant','admin')),db:Session=Depends(get_db)):
    rows=db.execute(select(Order,Product.title).join(Product,Product.id==Order.product_id).where(Order.merchant_id==user.id).order_by(Order.created_at.desc()).limit(limit).offset(offset)).all()
    return [{'order_number':o.order_number,'customer_name':o.customer_name,'customer_phone':o.customer_phone,'address':o.address,'product':title,'quantity':o.quantity,'color':o.selected_color,'size':o.selected_size,'total':o.total,'status':o.status,'affiliate_commission':float(o.affiliate_commission or 0) if o.status=='delivered' else None,'platform_commission':float(o.platform_commission or 0) if o.status=='delivered' else None,'merchant_net':round(float(o.total or 0)-float(o.affiliate_commission or 0)-float(o.platform_commission or 0),2) if o.status=='delivered' else None} for o,title in rows]
@app.post('/api/merchant/orders/{order_number}/status')
def update_order(order_number:str,status:str,user:User=Depends(require_role('merchant','admin')),db:Session=Depends(get_db)):
    if status not in ('confirmed','shipped','delivered','cancelled','returned'): raise HTTPException(400,'حالة الطلب غير صحيحة')
    order_query=select(Order).where(Order.order_number==order_number)
    if user.role!='admin': order_query=order_query.where(Order.merchant_id==user.id)
    o=db.scalar(order_query)
    if not o: raise HTTPException(404,'الطلب غير موجود')
    if o.status in ('cancelled','returned','delivered'): raise HTTPException(409,'لا يمكن تغيير حالة هذا الطلب')
    o.status=status
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
    if not p or p.status!='pending': raise HTTPException(404,'طلب السحب غير موجود')
    p.status={'approve':'approved','reject':'rejected','paid':'paid'}[decision]; db.commit(); return {'message':'تم تحديث طلب السحب'}


# Electronic agreements. Visual platform marks are not a government certificate or accredited e-signature.
class ContractIn(BaseModel):
    contract_type:str
    title:str=Field(min_length=3,max_length=180)
    body:str=Field(min_length=20)
    merchant_id:int|None=None
    affiliate_id:int|None=None
    commission_rate:float|None=Field(default=None,ge=0,le=100)
    penalty_terms:str=''
    starts_at:datetime|None=None
    ends_at:datetime|None=None
    legal_entity_name:str=''
    commission_scope:str='contract'
    penalty_type:str|None=None
    penalty_amount:float|None=Field(default=None,ge=0)
    penalty_percent:float|None=Field(default=None,ge=0,le=100)
    termination_terms:str=''

class ContractDecision(BaseModel):
    full_name:str=Field(min_length=3,max_length=120)
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

def contract_party_ids(c):
    ids=[]
    if c.contract_type in ('platform_merchant','merchant_affiliate') and c.merchant_id: ids.append(c.merchant_id)
    if c.contract_type in ('platform_affiliate','merchant_affiliate') and c.affiliate_id: ids.append(c.affiliate_id)
    return ids

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
      'commission_rate':c.commission_rate,'commission_scope':c.commission_scope,'penalty_terms':c.penalty_terms,
      'penalty_type':c.penalty_type,'penalty_amount':c.penalty_amount,'penalty_percent':c.penalty_percent,
      'termination_terms':c.termination_terms,'legal_entity_name':c.legal_entity_name,
      'starts_at':c.starts_at.isoformat() if c.starts_at else None,'ends_at':c.ends_at.isoformat() if c.ends_at else None,
      'approved_at':c.approved_at.isoformat() if c.approved_at else None,'platform_signer_name':c.platform_signer_name,
      'final_hash':c.final_hash,'status':c.status,'created_at':c.created_at.isoformat(),
      'acceptances':[{'user_id':a.user_id,'full_name':a.full_name,'accepted_at':a.accepted_at.isoformat(),'document_hash':a.document_hash} for a in accepts],
      'events':[{'event':e.event_type,'details':e.details if isinstance(e.details,dict) else (json.loads(e.details) if isinstance(e.details,str) and e.details else {}),'created_at':e.created_at.isoformat()} for e in events]}

CONTRACT_ACKNOWLEDGEMENT="""إقرار بالموافقة والالتزام
أقرّ أنا الطرف الموقّع أدناه بأنني اطّلعت على جميع بنود هذه الاتفاقية وشروطها، وفهمت مضمونها وآثارها، وأوافق عليها بإرادتي الحرة ورضاي التام، وأتعهد بالالتزام بما ورد فيها من حقوق والتزامات.
وتُعد موافقتي المثبتة إلكترونيًا دليلًا على قبولي والتزامي بهذه البنود، وتكون حجةً بين أطراف الاتفاقية في الحدود التي يقررها القانون المصري ومتى ثبتت صحة نسبتها إلى صاحبها.
(والله شاهدٌ علينا)"""

def ensure_contract_ack(body:str)->str:
    if 'والله شاهد' in (body or ''): return body
    return (body or '').rstrip()+chr(10)+chr(10)+CONTRACT_ACKNOWLEDGEMENT

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
    if not c or c.status!='active': raise HTTPException(404,'الاتفاقية غير متاحة للتوقيع')
    if not can_view_contract(c,user) or user.role=='admin': raise HTTPException(403,'هذه الاتفاقية ليست موجهة لحسابك')
    old=db.scalar(select(ContractAcceptance).where(ContractAcceptance.contract_id==c.id,ContractAcceptance.user_id==user.id))
    if old: raise HTTPException(409,'تم تسجيل موافقتك من قبل')
    snapshot=json.dumps({'number':c.contract_number,'version':c.version,'type':c.contract_type,'title':c.title,'body':c.body,'merchant_id':c.merchant_id,'affiliate_id':c.affiliate_id,'commission_rate':str(c.commission_rate) if c.commission_rate is not None else None,'commission_scope':c.commission_scope,'penalty_terms':c.penalty_terms,'penalty_type':c.penalty_type,'penalty_amount':str(c.penalty_amount) if c.penalty_amount is not None else None,'penalty_percent':str(c.penalty_percent) if c.penalty_percent is not None else None,'termination_terms':c.termination_terms,'legal_entity_name':c.legal_entity_name,'starts_at':str(c.starts_at),'ends_at':str(c.ends_at)},ensure_ascii=False,sort_keys=True)
    digest=hashlib.sha256(snapshot.encode()).hexdigest()
    db.add(ContractAcceptance(contract_id=c.id,user_id=user.id,full_name=data.full_name.strip(),document_hash=digest,ip_address=(request.client.host if request.client else '')[:64],user_agent=request.headers.get('user-agent','')[:500]))
    contract_event(db,c,user,'party_accepted',{'name':data.full_name.strip(),'hash':digest})
    db.flush()
    signed=db.scalars(select(ContractAcceptance).where(ContractAcceptance.contract_id==c.id)).all()
    required=contract_party_ids(c)
    if required and all(any(a.user_id==uid for a in signed) for uid in required):
        c.status='signed'
        c.approved_at=datetime.now(timezone.utc)
        c.final_hash=hashlib.sha256((snapshot+'|'+'|'.join(sorted(a.document_hash for a in signed))).encode()).hexdigest()
        contract_event(db,c,None,'platform_approved',{'platform_signer':c.platform_signer_name,'final_hash':c.final_hash})
    db.commit()
    return {'message':'تم تسجيل الموافقة الإلكترونية', 'status':c.status,'document_hash':digest}

@app.get('/api/contracts/{contract_id}/document')
def contract_document(contract_id:int,user:User=Depends(current_user),db:Session=Depends(get_db)):
    c=db.get(Contract,contract_id)
    if not c or not can_view_contract(c,user): raise HTTPException(404,'العقد غير موجود')
    if c.status!='signed': raise HTTPException(409,'لا تتوفر نسخة نهائية قبل اكتمال التوقيعات')
    from fastapi.responses import HTMLResponse
    safe=lambda x: str(x or '').replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;').replace("'","&#39;")
    acceptances=db.scalars(select(ContractAcceptance).where(ContractAcceptance.contract_id==c.id).order_by(ContractAcceptance.accepted_at)).all()
    acceptance_by_user={a.user_id:a for a in acceptances}
    merchant=db.get(User,c.merchant_id) if c.merchant_id else None
    affiliate=db.get(User,c.affiliate_id) if c.affiliate_id else None
    party_specs=[]
    if merchant: party_specs.append(('التاجر',merchant.id,merchant.name))
    if affiliate: party_specs.append(('المسوق',affiliate.id,affiliate.name))
    if len(party_specs)==1:
        party_specs.append(('المنصة',None,c.platform_signer_name or 'WESLA | منصة وصلة'))
    signature_cards=[]
    for role,uid,display_name in party_specs[:2]:
        accepted=acceptance_by_user.get(uid) if uid else None
        signed_name=accepted.full_name if accepted else (display_name if uid is None else 'بانتظار التوقيع')
        signed_date=accepted.accepted_at.isoformat() if accepted else (c.approved_at.isoformat() if uid is None and c.approved_at else 'اعتماد المنصة')
        signature_cards.append(f'<section class="signature-card"><div class="party-role">{safe(role)}</div><div class="signature-name">{safe(signed_name)}</div><div class="signature-rule"></div><div class="party-name">{safe(display_name)}</div><div class="signature-date">{safe(signed_date)}</div><div class="signed-status">{"تم التوقيع إلكترونيًا" if accepted or uid is None else "بانتظار التوقيع"}</div></section>')
    signatures=''.join(signature_cards)
    penalty_type_labels={'fixed':'مبلغ ثابت','percentage':'نسبة مئوية','both':'مبلغ ثابت ونسبة مئوية'}
    penalty_type_label=penalty_type_labels.get(c.penalty_type,c.penalty_type or 'غير محدد')
    penalty_amount_text=(f'{safe(c.penalty_amount)} جنيه مصري' if c.penalty_amount is not None else 'غير محدد')
    penalty_percent_text=(f'{safe(c.penalty_percent)}%' if c.penalty_percent is not None else 'غير محددة')
    html=f"""<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{safe(c.contract_number)}</title>
    <style>@import url('https://fonts.googleapis.com/css2?family=Aref+Ruqaa+Ink:wght@400;700&display=swap');@page{{size:A4 portrait;margin:5mm}}*{{box-sizing:border-box}}html,body{{margin:0;padding:0;background:#fff}}body{{font:9px/1.24 Tahoma,Arial,sans-serif;color:#252a35}}.paper{{width:100%;padding:7px 10px;border:3px double #b9974b;background:#fffdf7;position:relative}}.brand{{display:flex;align-items:center;gap:7px;justify-content:flex-start;margin:0 0 2px;color:#8d6a24}}.brand-mark{{width:29px;height:29px;border:2px solid #b9974b;border-radius:50%;display:grid;place-items:center;font:bold 16px Georgia;color:#8d6a24;flex:none}}.brand-name{{font-size:15px;font-weight:bold;letter-spacing:.3px}}.doc-heading{{text-align:right;margin:0 0 5px;padding:0 0 4px;border-bottom:1px solid #d8c28c}}.doc-heading h1{{font-size:15px;color:#8d6a24;margin:0}}.doc-heading h2{{font-size:10px;color:#34445a;margin:2px 0 0}}h3{{font-size:9px;color:#8d6a24;border-bottom:1px solid #e6d9b7;padding-bottom:1px;margin:5px 0 2px}}.contract-data{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:3px}}.data-cell{{background:#f8f4e9;border:1px solid #e6d9b7;padding:3px 5px;border-radius:3px;min-width:0;overflow-wrap:anywhere}}.data-cell b{{display:block;color:#80601f;font-size:8px}}.penalty{{background:#fff7f0;border:1px solid #c67b48;padding:4px 6px;border-radius:4px}}.penalty-amount{{font-size:10px;font-weight:bold;color:#9a3d20}}.signature-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px;margin-top:2px;direction:rtl}}.signature-card{{min-width:0;text-align:center;border:1px solid #d7c18e;border-radius:4px;padding:3px 5px;background:#fffdf7;break-inside:avoid}}.party-role{{font-weight:bold;color:#8d6a24;font-size:8px}}.signature-name{{font-family:'Aref Ruqaa Ink','Amiri','Traditional Arabic',cursive;font-size:22px;line-height:1;letter-spacing:-1.2px;word-spacing:-2px;color:#173f70;text-shadow:.4px .4px 0 #173f70;white-space:nowrap;overflow:hidden;min-height:23px;margin:0 auto}}.signature-rule{{width:78%;margin:1px auto 2px;border-bottom:1px solid #9a8350}}.party-name{{font-weight:bold;font-size:8px}}.signature-date{{font-size:7px;color:#667085;direction:ltr;overflow-wrap:anywhere}}.signed-status{{font-size:7px;color:#28734b;margin-top:1px}}.body-text{{white-space:pre-wrap;overflow-wrap:anywhere;font-size:8.5px;line-height:1.22}}.meta{{background:#f7f0df;border:1px solid #dfcfaa;padding:3px 5px;border-radius:3px;margin:4px 0 0;font-size:7px;line-height:1.2}}.hash{{direction:ltr;display:block;overflow-wrap:anywhere;font-size:7px}}button{{margin-top:6px;padding:5px 12px;border:0;border-radius:4px;background:#8d6a24;color:#fff;font:inherit}}@media(max-width:560px){{.paper{{padding:7px 8px}}.contract-data{{grid-template-columns:repeat(2,minmax(0,1fr))}}.signature-grid{{gap:4px}}.signature-name{{font-size:20px}}}}@media print{{html,body{{width:100%;margin:0!important;padding:0!important;background:#fff}}.paper{{width:100%;padding:5px 7px;break-inside:avoid;page-break-inside:avoid}}button{{display:none!important}}h3,.signature-card,.data-cell,.penalty{{break-inside:avoid;page-break-inside:avoid}}*{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}}}</style>
    <main class="paper"><header class="brand"><span class="brand-mark">W</span><span class="brand-name">وصلة | WESLA</span></header><header class="doc-heading"><h1>اتفاقية إلكترونية</h1><h2>{safe(c.title)}</h2></header>
    <div class="contract-data"><div class="data-cell"><b>رقم العقد</b>{safe(c.contract_number)}</div><div class="data-cell"><b>رقم الإصدار</b>{safe(c.version)}</div><div class="data-cell"><b>تاريخ الإنشاء</b>{safe(c.created_at.isoformat() if c.created_at else '')}</div><div class="data-cell"><b>حالة العقد</b>{safe(c.status)}</div><div class="data-cell"><b>التاجر</b>{safe(merchant.name if merchant else 'غير منطبق')}</div><div class="data-cell"><b>المسوق</b>{safe(affiliate.name if affiliate else 'غير منطبق')}</div><div class="data-cell"><b>الكيان القانوني</b>{safe(c.legal_entity_name or 'غير محدد')}</div><div class="data-cell"><b>مدة الاتفاقية</b>من {safe(c.starts_at.isoformat() if c.starts_at else 'غير محدد')} إلى {safe(c.ends_at.isoformat() if c.ends_at else 'غير محدد')}</div></div>
    <h3>نص الاتفاقية وجميع البنود</h3><article class="body-text">{safe(c.body)}</article>
    <h3>العمولات</h3><div class="data-cell"><b>نسبة العمولة</b>{safe(c.commission_rate)}%<br><b>نطاق احتساب العمولة</b>{safe(c.commission_scope)}</div>
    <h3>الشرط الجزائي</h3><div class="penalty"><b>نوع الشرط الجزائي:</b> {safe(penalty_type_label)}<br><b>القيمة المالية:</b> <span class="penalty-amount">{penalty_amount_text}</span><br><b>النسبة:</b> <span class="penalty-amount">{penalty_percent_text}</span><br><b>تفاصيل الشرط الجزائي:</b><div class="body-text">{safe(c.penalty_terms or 'لا توجد تفاصيل إضافية مسجلة')}</div></div>
    <h3>شروط الإنهاء والفسخ</h3><div class="body-text">{safe(c.termination_terms or 'لا توجد شروط إضافية مسجلة')}</div>
    <h3>توقيعات الأطراف الإلكترونية</h3><div class="signature-grid">{signatures}</div>
    <h3>اعتماد المنصة والبصمة الرقمية</h3><div class="data-cell"><b>المعتمد</b>{safe(c.platform_signer_name or 'WESLA | منصة وصلة')}<br><b>تاريخ الاعتماد</b>{safe(c.approved_at.isoformat() if c.approved_at else '—')}<br><b>بصمة النسخة النهائية</b><span class="hash">{safe(c.final_hash)}</span></div>
    <p class="meta">هذا المستند يعرض سجل الموافقات الإلكترونية المسجلة على الاتفاقية. الشكل الطباعي للأسماء تمثيل بصري ولا يُعد صورة لتوقيعٍ حر مرسوم باليد أو شهادة تصديق إلكتروني مستقلة. تُقدّر الحجية وفقًا للقانون المصري والضوابط المنظمة للتوقيع الإلكتروني.</p><button onclick="print()">طباعة / حفظ PDF</button><script>function fitContractForPrint(){{const paper=document.querySelector(".paper");if(!paper)return;paper.style.zoom="1";const available=1030;const needed=paper.scrollHeight;const scale=Math.min(1,available/Math.max(needed,1));paper.style.zoom=String(scale)}}window.addEventListener("beforeprint",fitContractForPrint);window.addEventListener("afterprint",()=>{{const paper=document.querySelector(".paper");if(paper)paper.style.zoom="1"}});</script></main></html>"""
    return HTMLResponse(html)

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

@app.get('/api/admin/contracts')
def admin_contracts(user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    return [contract_out(c,db) for c in db.scalars(select(Contract).order_by(Contract.created_at.desc())).all()]

@app.post('/api/admin/contracts')
def create_contract(data:ContractIn,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    if data.contract_type not in ('platform_merchant','platform_affiliate','merchant_affiliate'):
        raise HTTPException(400,'نوع الاتفاقية غير صحيح')
    if data.contract_type in ('platform_merchant','merchant_affiliate'):
        if not data.merchant_id or not db.get(User,data.merchant_id) or db.get(User,data.merchant_id).role!='merchant': raise HTTPException(400,'اختر حساب تاجر صحيح')
    if data.contract_type in ('platform_affiliate','merchant_affiliate'):
        if not data.affiliate_id or not db.get(User,data.affiliate_id) or db.get(User,data.affiliate_id).role!='affiliate': raise HTTPException(400,'اختر حساب مسوق صحيح')
    if data.commission_scope not in ('contract','all_products','product'): raise HTTPException(400,'نطاق العمولة غير صحيح')
    c=Contract(contract_type=data.contract_type,title=data.title.strip(),body=ensure_contract_ack(data.body),merchant_id=data.merchant_id,affiliate_id=data.affiliate_id,commission_rate=data.commission_rate,penalty_terms=data.penalty_terms,status='draft',contract_number='WS-'+datetime.now(timezone.utc).strftime('%Y%m%d')+'-'+secrets.token_hex(3).upper(),starts_at=data.starts_at,ends_at=data.ends_at,legal_entity_name=data.legal_entity_name,commission_scope=data.commission_scope,penalty_type=data.penalty_type,penalty_amount=data.penalty_amount,penalty_percent=data.penalty_percent,termination_terms=data.termination_terms,platform_signer_name='WESLA | المنصة')
    db.add(c); db.flush(); contract_event(db,c,user,'created',{'number':c.contract_number})
    db.commit(); db.refresh(c); return contract_out(c,db)

@app.post('/api/admin/contracts/{contract_id}/{action}')
def contract_action(contract_id:int,action:str,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    c=db.get(Contract,contract_id)
    if not c: raise HTTPException(404,'الاتفاقية غير موجودة')
    if action=='activate':
        if c.status!='draft': raise HTTPException(409,'لا يمكن إرسال هذه النسخة في حالتها الحالية')
        c.status='active'; contract_event(db,c,user,'sent_for_signature')
    elif action=='archive':
        if c.status=='signed': raise HTTPException(409,'العقد الموقع لا يُحذف أو يُؤرشف؛ استخدم طلب فسخ')
        c.status='archived'; contract_event(db,c,user,'archived')
    elif action=='draft':
        if c.status=='signed': raise HTTPException(409,'لا يمكن تعديل نسخة موقعة؛ أنشئ إصدارًا أو ملحقًا جديدًا')
        c.status='draft'; contract_event(db,c,user,'returned_to_draft')
    else: raise HTTPException(400,'الإجراء غير صحيح')
    db.commit(); return {'message':'تم تحديث حالة الاتفاقية','status':c.status}

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
