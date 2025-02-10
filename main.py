from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Response
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import os
from dotenv import load_dotenv
import csv
import io
import secrets
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

# Load environment variables
load_dotenv()

# Security configurations
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database Configuration
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("No DATABASE_URL set in .env file")

# Database Setup
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"sslmode": "require"}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class DBUser(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)

class DBEmployee(Base):
    __tablename__ = "employees"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    department = Column(String, nullable=False)
    rank = Column(String, nullable=False)
    current_salary = Column(Float, nullable=False)
    job_duration = Column(String, nullable=False)
    increment_amount = Column(Float, nullable=False)

Base.metadata.create_all(bind=engine)

# FastAPI App Setup
app = FastAPI()
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")



# Temporary Storage
temp_storage = []

# Security Functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
        return {"username": username, "role": role}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

# Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Authentication Middleware
async def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return None
    
    try:
        token_type, token_value = token.split(" ")
        if token_type.lower() != "bearer":
            return None
            
        token_data = verify_token(token_value)
        user = db.query(DBUser).filter(DBUser.username == token_data["username"]).first()
        return user
    except:
        return None

# Role-based access control middleware
def admin_required(current_user: DBUser = Depends(get_current_user)):
    if not current_user or current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized"
        )
    return current_user

# Routes
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(DBUser).filter(DBUser.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role}
    )
    
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=1800
    )
    
    return response

@app.post("/logout")
async def logout(response: Response):
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response

@app.get("/", response_class=HTMLResponse)
async def read_employees(
    request: Request,
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(get_current_user)
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
        
    employees = db.query(DBEmployee).all()
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "employees": employees,
            "temp_count": len(temp_storage),
            "current_user": current_user
        }
    )

#additional functions

@app.get("/employee/{employee_id}")
async def get_employee(
    employee_id: int,
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(admin_required)
):
    employee = db.query(DBEmployee).filter(DBEmployee.id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    return employee

@app.post("/edit")
async def edit_employee(
    id: int = Form(...),
    name: str = Form(...),
    department: str = Form(...),
    rank: str = Form(...),
    current_salary: float = Form(...),
    job_duration: str = Form(...),
    increment_amount: float = Form(...),
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(admin_required)
):
    employee = db.query(DBEmployee).filter(DBEmployee.id == id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    employee.name = name
    employee.department = department
    employee.rank = rank
    employee.current_salary = current_salary
    employee.job_duration = job_duration
    employee.increment_amount = increment_amount
    
    try:
        db.commit()
        return RedirectResponse(url="/", status_code=303)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/delete/{employee_id}")
async def delete_employee(
    employee_id: int,
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(admin_required)
):
    employee = db.query(DBEmployee).filter(DBEmployee.id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    try:
        db.delete(employee)
        db.commit()
        return RedirectResponse(url="/", status_code=303)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
        
        
#Password reset and export to SQL feature button

@app.post("/reset-password")
async def reset_password(
    current_password: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(get_current_user)
):
    if not verify_password(current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect current password"
        )
    
    current_user.hashed_password = get_password_hash(new_password)
    try:
        db.commit()
        return RedirectResponse(url="/", status_code=303)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/export-sql")
async def export_sql(
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(get_current_user)
):
    employees = db.query(DBEmployee).all()
    
    sql_statements = []
    # Generate CREATE TABLE statement
    create_table = """
    CREATE TABLE IF NOT EXISTS employees (
        id SERIAL PRIMARY KEY,
        name VARCHAR NOT NULL,
        department VARCHAR NOT NULL,
        rank VARCHAR NOT NULL,
        current_salary FLOAT NOT NULL,
        job_duration VARCHAR NOT NULL,
        increment_amount FLOAT NOT NULL
    );
    """
    sql_statements.append(create_table)
    
    # Generate INSERT statements
    for emp in employees:
        insert_stmt = f"""
        INSERT INTO employees (name, department, rank, current_salary, job_duration, increment_amount)
        VALUES (
            '{emp.name}',
            '{emp.department}',
            '{emp.rank}',
            {emp.current_salary},
            '{emp.job_duration}',
            {emp.increment_amount}
        );"""
        sql_statements.append(insert_stmt)
    
    sql_content = "\n".join(sql_statements)
    
    return StreamingResponse(
        iter([sql_content]),
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=employees.sql"}
    )
    

# Add a utility function to create an admin user
def create_admin_user(db: Session):
    admin_user = db.query(DBUser).filter(DBUser.username == "admin").first()
    if not admin_user:
        admin_user = DBUser(
            username="admin",
            email="admin@example.com",
            hashed_password=get_password_hash("admin123"),  # Change this in production
            role="admin",
            is_active=True
        )
        db.add(admin_user)
        try:
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"Error creating admin user: {e}")

# Call this function when the application starts
@app.on_event("startup")
async def startup_event():
    db = SessionLocal()
    try:
        create_admin_user(db)
    finally:
        db.close()

@app.post("/add")
async def add_employee(
    name: str = Form(...),
    department: str = Form(...),
    rank: str = Form(...),
    current_salary: float = Form(...),
    job_duration: str = Form(...),
    increment_amount: float = Form(...),
    current_user: DBUser = Depends(admin_required)
):
    temp_storage.append({
        "name": name,
        "department": department,
        "rank": rank,
        "current_salary": current_salary,
        "job_duration": job_duration,
        "increment_amount": increment_amount
    })
    return RedirectResponse(url="/", status_code=303)

@app.post("/save_to_postgres")
async def save_to_postgres(
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(admin_required)
):
    try:
        for employee in temp_storage:
            db_employee = DBEmployee(**employee)
            db.add(db_employee)
        db.commit()
        temp_storage.clear()
        return RedirectResponse(url="/", status_code=303)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/export_csv")
async def export_csv(
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(get_current_user)
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
        
    employees = db.query(DBEmployee).all()
    csv_data = io.StringIO()
    writer = csv.writer(csv_data)
    writer.writerow([
        "ID", "Name", "Department", "Rank", "Salary", "Duration", "Increment"
    ])
    
    for emp in employees:
        writer.writerow([
            emp.id,
            emp.name,
            emp.department,
            emp.rank,
            emp.current_salary,
            emp.job_duration,
            emp.increment_amount
        ])
    
    csv_data.seek(0)
    return StreamingResponse(
        iter([csv_data.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=employees.csv"}
    )

if __name__ == "__main__":
    import uvicorn
    import socket
    from fastapi.middleware.cors import CORSMiddleware

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def get_ip_addresses():
        hostname = socket.gethostname()
        ip_addresses = []
        try:
            ips = socket.getaddrinfo(hostname, None)
            for ip in ips:
                if ip[0] == socket.AF_INET:  # IPv4 only
                    ip_addr = ip[4][0]
                    if not ip_addr.startswith('127.'):
                        ip_addresses.append(ip_addr)
        except Exception as e:
            print(f"Error getting IP addresses: {e}")
        return list(set(ip_addresses))

    port = 8000
    ip_list = get_ip_addresses()
    
    print("\n=== Server Information ===")
    print(f"Local Access:\thttp://localhost:{port}")
    print("\nNetwork Access:")
    for ip in ip_list:
        print(f"WiFi/LAN:\thttp://{ip}:{port}")
    
    config = uvicorn.Config(
        app=app,
        host="0.0.0.0",  # This is crucial - it binds to all interfaces
        port=port,
        reload=True,
        log_level="debug",
        proxy_headers=True,
        forwarded_allow_ips="*",
        access_log=True,
        workers=1
    )
    
    server = uvicorn.Server(config)
    server.run()