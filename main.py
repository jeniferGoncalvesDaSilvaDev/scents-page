from contextlib import asynccontextmanager
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter
from slowapi.util import get_remote_address
from pydantic import BaseModel
import shutil
import os
import jwt
import datetime
import sqlite3
from PIL import Image

SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

RATE_LIMITS = {
    "free": 100,  
    "basic": 1000,  
    "pro": 10000   
}

limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n🚀 API running at http://0.0.0.0:8000")
    print("📚 Documentation available at http://0.0.0.0:8000/docs\n")
    yield

app = FastAPI(lifespan=lifespan)

app.mount("/static", StaticFiles(directory="."), name="static")

def init_db():
    conn = sqlite3.connect("scents_ads.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            subscription_tier TEXT DEFAULT 'free'
        )
    """)
    conn.commit()
    conn.close()

init_db()

class User(BaseModel):
    username: str
    password: str

@app.get("/", response_class=HTMLResponse)
async def root():
    return FileResponse("index.html")

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return FileResponse("login.html")

@app.post("/register")
async def register(request: Request):
    data = await request.json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username e senha são obrigatórios")
    
    conn = sqlite3.connect("scents_ads.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Usuário já existe")

    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()
    return RedirectResponse("/login", status_code=303)

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = sqlite3.connect("scents_ads.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (form_data.username, form_data.password))
    user = cursor.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    token = jwt.encode({"sub": form_data.username, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/check-auth")
async def check_auth(token: str = Depends(oauth2_scheme)):
    try:
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"authenticated": True}
    except:
        raise HTTPException(status_code=401)

@app.post("/upload")
async def upload_ad(audio: UploadFile = File(...), media: UploadFile = File(...), token: str = Depends(oauth2_scheme)):
    if not os.path.exists("uploads"):
        os.makedirs("uploads")

    audio_location = f"uploads/{audio.filename}"
    with open(audio_location, "wb") as buffer:
        shutil.copyfileobj(audio.file, buffer)

    media_location = f"uploads/{media.filename}"
    with open(media_location, "wb") as buffer:
        shutil.copyfileobj(media.file, buffer)

    return {
        "status": "success",
        "audio_url": f"/uploads/{audio.filename}",
        "media_url": f"/uploads/{media.filename}"
    }

@app.get("/extract-audio")
async def extract_audio_from_image(image_path: str):
    try:
        img = Image.open(image_path)
        audio_data = img.info.get("audio", "Nenhum áudio embutido encontrado")
        return {"audio_data": audio_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao processar imagem: {str(e)}")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return FileResponse("dashboard.html")

@app.get("/uploads/{file_name}")
async def get_uploaded_file(file_name: str):
    file_path = f"uploads/{file_name}"
    if os.path.exists(file_path):
        return FileResponse(file_path)
    raise HTTPException(status_code=404, detail="Arquivo não encontrado")        
