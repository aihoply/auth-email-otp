import os
import smtplib
import random
import string
import time
import sqlite3
import jwt
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
from contextlib import contextmanager
import logging

load_dotenv()

app = FastAPI()

SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class EmailRequest(BaseModel):
    email: EmailStr

class OTPVerificationRequest(BaseModel):
    email: EmailStr
    otp: str

class UserRegistrationRequest(BaseModel):
    email: EmailStr

@contextmanager
def smtp_connection():
    try:
        server = smtplib.SMTP(os.getenv("EMAIL_HOST"), int(os.getenv("EMAIL_PORT")))
        server.starttls()
        server.login(os.getenv("EMAIL_HOST_USER"), os.getenv("EMAIL_HOST_PASSWORD"))
        yield server
    finally:
        server.quit()

@contextmanager
def get_db_connection():
    conn = sqlite3.connect('auth.db')
    try:
        yield conn
    finally:
        conn.close()

def send_email(to_email: str, otp: str):
    from_email = os.getenv("EMAIL_FROM")
    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = "Your OTP Code"
    body = f"Your OTP code is {otp}"
    msg.attach(MIMEText(body, "plain"))

    with smtp_connection() as server:
        text = msg.as_string()
        server.sendmail(from_email, to_email, text)

def generate_otp(length: int = 6) -> str:
    digits = string.digits
    return ''.join(random.choice(digits) for i in range(length))

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return email
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def is_token_blacklisted(token: str) -> bool:
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT token FROM blacklisted_tokens WHERE token = ?", (token,))
        blacklisted_token = c.fetchone()
    return blacklisted_token is not None

@app.post("/register")
async def register_user(request: UserRegistrationRequest):
    email = request.email
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT email FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        if user is not None:
            raise HTTPException(status_code=400, detail="Email already registered")
        c.execute("INSERT INTO users (email, otp, timestamp) VALUES (?, ?, ?)", (email, None, None))
        conn.commit()
    return {"message": "User registered successfully"}

@app.post("/send-otp")
async def send_otp(request: EmailRequest):
    email = request.email
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT email FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        if user is None:
            raise HTTPException(status_code=400, detail="Email not allowed")
        otp = generate_otp()
        timestamp = time.time()
        c.execute("UPDATE users SET otp = ?, timestamp = ? WHERE email = ?", (otp, timestamp, email))
        conn.commit()
    try:
        send_email(email, otp)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to send email")
    return {"message": "OTP sent"}

@app.post("/verify-otp")
async def verify_otp(request: OTPVerificationRequest):
    email = request.email
    otp = request.otp
    current_time = time.time()
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT otp, timestamp FROM users WHERE email = ?", (email,))
        result = c.fetchone()
        if result is None:
            raise HTTPException(status_code=404, detail="OTP not found")
        stored_otp, timestamp = result
        if current_time - timestamp > 180:
            c.execute("UPDATE users SET otp = NULL, timestamp = NULL WHERE email = ?", (email,))
            conn.commit()
            raise HTTPException(status_code=400, detail="OTP expired")
        if stored_otp != otp:
            raise HTTPException(status_code=400, detail="Invalid OTP")
        c.execute("UPDATE users SET otp = NULL, timestamp = NULL WHERE email = ?", (email,))
        conn.commit()
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/token-check")
async def token_check(token: str = Depends(oauth2_scheme)):
    if is_token_blacklisted(token):
        raise HTTPException(status_code=401, detail="Token has been revoked")
    email = verify_token(token)
    return {"message": "Token is valid", "email": email}

@app.post("/logout")
async def logout(token: str = Depends(oauth2_scheme)):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO blacklisted_tokens (token) VALUES (?)", (token,))
        conn.commit()
    return {"message": "Successfully logged out"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
