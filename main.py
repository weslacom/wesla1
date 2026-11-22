import os, secrets, hashlib, hmac
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, HTTPException, Response, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from .database import Base, engine, get_db, SessionLocal
from .models import User, Application, Product, Link, Order, Payout, AuthSession

Base.metadata.create_all(bind=engine)
app=FastAPI(title='Wesla Affiliate Platform', version='1.0.0')
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

def public_user(u): return {'id':u.id,'name':u.name,'email':u.email,'role':u.role,'status':u.status}
def product_out(p,db):
    merchant=db.get(User,p.merchant_id)
    return {'id':p.id,'title':p.title,'description':p.description,'price':p.price,'stock':p.stock,'affiliate_rate':p.affiliate_rate,'platform_rate':p.platform_rate,'status':p.status,'merchant':merchant.name if merchant else ''}
class RegisterIn(BaseModel): name:str=Field(min_length=2,max_length=120); email:str; password:str=Field(min_length=8,max_length=128)
class LoginIn(BaseModel): email:str; password:str
class ApplicationIn(BaseModel): role:str; details:str=''
class ProductIn(BaseModel): title:str=Field(min_length=2,max_length=180); description:str=''; price:float=Field(gt=0); stock:int=Field(ge=0); affiliate_rate:float=Field(ge=0,le=80); platform_rate:float=Field(ge=0,le=30)
class OrderIn(BaseModel): product_id:int; quantity:int=Field(ge=1,le=20); customer_name:str; customer_phone:str; address:str; referral_code:str|None=None
class PayoutIn(BaseModel): amount:float=Field(gt=0); method:str; destination:str

@app.get('/')
def home(): return FileResponse('app/static/index.html')
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
    response.set_cookie('wesla_session',token,httponly=True,samesite='lax',secure=os.getenv('COOKIE_SECURE','0')=='1',max_age=60*60*24*7)
    return {'user':public_user(u)}
@app.post('/api/logout')
def logout(response:Response,request:Request,db:Session=Depends(get_db)):
    token=request.cookies.get('wesla_session')
    if token:
        session=db.scalar(select(AuthSession).where(AuthSession.token_hash==hashlib.sha256(token.encode()).hexdigest()))
        if session: db.delete(session); db.commit()
    response.delete_cookie('wesla_session'); return {'ok':True}
@app.get('/api/me')
def me(user:User=Depends(current_user)): return {'user':public_user(user)}
@app.post('/api/applications')
def apply(data:ApplicationIn,user:User=Depends(current_user),db:Session=Depends(get_db)):
    if data.role not in ('merchant','affiliate'): raise HTTPException(400,'نوع الحساب غير صحيح')
    if user.role in ('admin',data.role): raise HTTPException(409,'حسابك لديه هذه الصلاحية بالفعل')
    old=db.scalar(select(Application).where(Application.user_id==user.id,Application.requested_role==data.role,Application.status=='pending'))
    if old: raise HTTPException(409,'لديك طلب قيد المراجعة بالفعل')
    a=Application(user_id=user.id,requested_role=data.role,details=data.details); db.add(a); db.commit(); return {'message':'تم إرسال طلبك للإدارة للمراجعة'}
@app.get('/api/products')
def products(db:Session=Depends(get_db)):
    rows=db.scalars(select(Product).where(Product.status=='active').order_by(Product.created_at.desc())).all()
    return [product_out(p,db) for p in rows]
@app.post('/api/merchant/products')
def add_product(data:ProductIn,user:User=Depends(require_role('merchant','admin')),db:Session=Depends(get_db)):
    platform_rate=data.platform_rate if user.role=='admin' else float(os.getenv('PLATFORM_RATE_DEFAULT','5'))
    p=Product(merchant_id=user.id,title=data.title,description=data.description,price=data.price,stock=data.stock,affiliate_rate=data.affiliate_rate,platform_rate=platform_rate)
    db.add(p); db.commit(); db.refresh(p); return product_out(p,db)
@app.get('/api/merchant/products')
def my_products(user:User=Depends(require_role('merchant','admin')),db:Session=Depends(get_db)):
    return [product_out(p,db) for p in db.scalars(select(Product).where(Product.merchant_id==user.id)).all()]
@app.post('/api/affiliate/links/{product_id}')
def create_link(product_id:int,user:User=Depends(require_role('affiliate','admin')),db:Session=Depends(get_db)):
    p=db.get(Product,product_id)
    if not p or p.status!='active': raise HTTPException(404,'المنتج غير موجود')
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
    p=db.get(Product,data.product_id)
    if not p or p.status!='active': raise HTTPException(404,'المنتج غير متاح')
    if p.stock<data.quantity: raise HTTPException(409,'الكمية المطلوبة غير متاحة حالياً')
    code=data.referral_code or request.cookies.get('wesla_ref'); link=db.scalar(select(Link).where(Link.code==code)) if code else None
    affiliate_id=link.affiliate_id if link and link.product_id==p.id else None
    total=(Decimal(p.price)*data.quantity).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP); ac=(total*Decimal(p.affiliate_rate)/Decimal(100)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP) if affiliate_id else Decimal('0.00'); pc=(total*Decimal(p.platform_rate)/Decimal(100)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    order=Order(order_number='WS'+secrets.token_hex(5).upper(),customer_name=data.customer_name,customer_phone=data.customer_phone,address=data.address,product_id=p.id,merchant_id=p.merchant_id,affiliate_id=affiliate_id,quantity=data.quantity,unit_price=p.price,total=total,affiliate_rate_snapshot=p.affiliate_rate,platform_rate_snapshot=p.platform_rate,affiliate_commission=ac,platform_commission=pc)
    p.stock-=data.quantity; db.add(order); db.commit(); db.refresh(order)
    return {'order_number':order.order_number,'status':order.status,'total':total,'message':'تم تسجيل الطلب. سيتواصل معك التاجر لتأكيده.'}
@app.get('/api/affiliate/links')
def affiliate_links(user:User=Depends(require_role('affiliate','admin')),db:Session=Depends(get_db)):
    return [{'code':l.code,'product_id':l.product_id,'product':db.get(Product,l.product_id).title,'clicks':l.clicks} for l in db.scalars(select(Link).where(Link.affiliate_id==user.id)).all()]
@app.get('/api/affiliate/dashboard')
def affiliate_dashboard(user:User=Depends(require_role('affiliate','admin')),db:Session=Depends(get_db)):
    orders=db.scalars(select(Order).where(Order.affiliate_id==user.id)).all()
    return {'links':[{'code':l.code,'product_id':l.product_id,'product':db.get(Product,l.product_id).title,'clicks':l.clicks} for l in db.scalars(select(Link).where(Link.affiliate_id==user.id)).all()],'orders':[{'order_number':o.order_number,'total':o.total,'commission':o.affiliate_commission,'status':o.status} for o in orders],'pending':round(sum(o.affiliate_commission for o in orders if o.status in ('pending','confirmed','shipped')),2),'approved':round(sum(o.affiliate_commission for o in orders if o.status=='delivered'),2)}
@app.post('/api/affiliate/payouts')
def payout(data:PayoutIn,user:User=Depends(require_role('affiliate','admin')),db:Session=Depends(get_db)):
    delivered=db.scalars(select(Order).where(Order.affiliate_id==user.id,Order.status=='delivered')).all(); earned=sum(o.affiliate_commission for o in delivered)
    paid=sum(x.amount for x in db.scalars(select(Payout).where(Payout.affiliate_id==user.id,Payout.status.in_(['approved','paid']))).all())
    pending=sum(x.amount for x in db.scalars(select(Payout).where(Payout.affiliate_id==user.id,Payout.status=='pending')).all())
    if Decimal(str(data.amount))>Decimal(str(earned))-Decimal(str(paid))-Decimal(str(pending)): raise HTTPException(400,'المبلغ يتجاوز رصيدك القابل للسحب')
    p=Payout(affiliate_id=user.id,amount=Decimal(str(data.amount)),method=data.method,destination=data.destination); db.add(p); db.commit(); return {'message':'تم إرسال طلب السحب للإدارة'}
@app.get('/api/merchant/orders')
def merchant_orders(user:User=Depends(require_role('merchant','admin')),db:Session=Depends(get_db)):
    rows=db.scalars(select(Order).where(Order.merchant_id==user.id).order_by(Order.created_at.desc())).all()
    return [{'order_number':o.order_number,'customer_name':o.customer_name,'customer_phone':o.customer_phone,'address':o.address,'product':db.get(Product,o.product_id).title,'quantity':o.quantity,'total':o.total,'status':o.status} for o in rows]
@app.post('/api/merchant/orders/{order_number}/status')
def update_order(order_number:str,status:str,user:User=Depends(require_role('merchant','admin')),db:Session=Depends(get_db)):
    if status not in ('confirmed','shipped','delivered','cancelled','returned'): raise HTTPException(400,'حالة الطلب غير صحيحة')
    o=db.scalar(select(Order).where(Order.order_number==order_number,Order.merchant_id==user.id))
    if not o: raise HTTPException(404,'الطلب غير موجود')
    if o.status in ('cancelled','returned','delivered'): raise HTTPException(409,'لا يمكن تغيير حالة هذا الطلب')
    o.status=status
    if status in ('cancelled','returned'):
        p=db.get(Product,o.product_id); p.stock+=o.quantity; o.affiliate_commission=0; o.platform_commission=0
    db.commit(); return {'message':'تم تحديث حالة الطلب'}
@app.get('/api/admin/overview')
def admin_overview(user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    return {'users':db.scalar(select(func.count(User.id))),'products':db.scalar(select(func.count(Product.id))),'orders':db.scalar(select(func.count(Order.id))),'sales':db.scalar(select(func.coalesce(func.sum(Order.total),0)).where(Order.status=='delivered')),'applications':db.scalar(select(func.count(Application.id)).where(Application.status=='pending')),'payouts':db.scalar(select(func.count(Payout.id)).where(Payout.status=='pending'))}
@app.get('/api/admin/applications')
def admin_applications(user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    return [{'id':a.id,'name':db.get(User,a.user_id).name,'email':db.get(User,a.user_id).email,'role':a.requested_role,'details':a.details,'status':a.status} for a in db.scalars(select(Application).where(Application.status=='pending')).all()]
@app.post('/api/admin/applications/{app_id}/{decision}')
def decide_application(app_id:int,decision:str,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    if decision not in ('approve','reject'): raise HTTPException(400,'القرار غير صحيح')
    a=db.get(Application,app_id)
    if not a or a.status!='pending': raise HTTPException(404,'الطلب غير موجود أو تمت مراجعته')
    a.status='approved' if decision=='approve' else 'rejected'
    if decision=='approve': db.get(User,a.user_id).role=a.requested_role
    db.commit(); return {'message':'تمت مراجعة الطلب'}
@app.get('/api/admin/orders')
def admin_orders(user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    return [{'order_number':o.order_number,'customer':o.customer_name,'total':o.total,'affiliate_commission':o.affiliate_commission,'platform_commission':o.platform_commission,'status':o.status} for o in db.scalars(select(Order).order_by(Order.created_at.desc())).all()]
@app.get('/api/admin/payouts')
def admin_payouts(user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    return [{'id':p.id,'affiliate':db.get(User,p.affiliate_id).name,'amount':p.amount,'method':p.method,'destination':p.destination,'status':p.status} for p in db.scalars(select(Payout).where(Payout.status=='pending')).all()]
@app.post('/api/admin/payouts/{payout_id}/{decision}')
def decide_payout(payout_id:int,decision:str,user:User=Depends(require_role('admin')),db:Session=Depends(get_db)):
    if decision not in ('approve','reject','paid'): raise HTTPException(400,'القرار غير صحيح')
    p=db.get(Payout,payout_id)
    if not p or p.status!='pending': raise HTTPException(404,'طلب السحب غير موجود')
    p.status={'approve':'approved','reject':'rejected','paid':'paid'}[decision]; db.commit(); return {'message':'تم تحديث طلب السحب'}

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
