from contextlib import asynccontextmanager
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional

from fastapi.middleware.cors import CORSMiddleware

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Rate limits por plano
RATE_LIMITS = {
    "free": 100,  # 100 requests/day
    "basic": 1000,  # 1000 requests/day
    "pro": 10000   # 10000 requests/day
}

async def check_subscription(token: str = Depends(oauth2_scheme)) -> Optional[str]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT subscription_tier FROM users WHERE username = ?", (username,))
        tier = cursor.fetchone()[0]
        conn.close()
        return tier
    except:
        raise HTTPException(status_code=401)
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import shutil
import os
import jwt
import datetime
import sqlite3

SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n🚀 API running at http://0.0.0.0:8000")
    print("📚 Documentation available at http://0.0.0.0:8000/docs\n")
    yield

app = FastAPI(lifespan=lifespan)

# Serve static files
app.mount("/static", StaticFiles(directory="."), name="static")

@app.get("/", response_class=HTMLResponse)
async def root():
    return FileResponse("index.html")

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return FileResponse("login.html")

@app.get("/upload", response_class=HTMLResponse)
async def upload_page():
    return FileResponse("upload.html")

@app.get("/my-uploads")
async def my_uploads_page():
    return RedirectResponse("/dashboard", status_code=303)

@app.get("/docs-page", response_class=HTMLResponse)
async def docs_page():
    return FileResponse("docs-page.html")

# Database functions
def init_db():
    conn = sqlite3.connect("scents_ads.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            subscription_tier TEXT DEFAULT 'free',
            api_key TEXT UNIQUE
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            endpoint TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect("scents_ads.db")
    return conn

init_db()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class User(BaseModel):
    username: str
    password: str

@app.post("/register")
async def register(request: Request):
    try:
        data = await request.json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            raise HTTPException(status_code=400, detail="Username e password são obrigatórios")
            
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Usuário já existe")

        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()
        return RedirectResponse("/login", status_code=303)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db()
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
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"authenticated": True}
    except:
        raise HTTPException(status_code=401)


@app.post("/upload")
async def upload_ad(
    audio: UploadFile = File(...),
    media: UploadFile = File(...),
    token: str = Depends(oauth2_scheme)
):
    try:
        if not os.path.exists("uploads"):
            os.makedirs("uploads")

        # Save audio file
        audio_location = f"uploads/audio_{audio.filename}"
        with open(audio_location, "wb") as buffer:
            shutil.copyfileobj(audio.file, buffer)

        # Save media file
        media_location = f"uploads/media_{media.filename}"
        with open(media_location, "wb") as buffer:
            shutil.copyfileobj(media.file, buffer)

        return {
            "status": "success",
            "message": "Arquivos enviados com sucesso",
            "audio_filename": audio.filename,
            "media_filename": media.filename
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/apply-scents/{ad_id}")
def apply_scents(ad_id: int, token: str = Depends(oauth2_scheme)):
    if ad_id not in ads_db:
        raise HTTPException(status_code=404, detail="Anúncio não encontrado")

    ads_db[ad_id]["scents_applied"] = True
    return {"message": "Scents aplicado ao anúncio", "ad_id": ad_id}

@app.get("/ad/{ad_id}")
def get_ad(ad_id: int):
    if ad_id not in ads_db:
        raise HTTPException(status_code=404, detail="Anúncio não encontrado")

    return {"ad_id": ad_id, "filename": ads_db[ad_id]["filename"], "scents_applied": ads_db[ad_id]["scents_applied"]}

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page():
    return FileResponse("dashboard.html")

@app.get("/token", response_class=HTMLResponse)
async def token_page():
    return FileResponse("token.html")

@app.get("/apply-scents", response_class=HTMLResponse)
async def apply_scents_page():
    return FileResponse("apply-scents.html")

@app.get("/download.html", response_class=HTMLResponse)
async def download_page():
    return FileResponse("download.html")

@app.get("/download/{filename}")
async def download_file(filename: str):
    file_path = os.path.join("uploads", filename)
    if os.path.exists(file_path):
        return FileResponse(file_path, filename=filename)
    raise HTTPException(status_code=404, detail="Arquivo não encontrado")

@app.post("/apply-scents")
async def apply_scents(token: str = Depends(oauth2_scheme)):
    try:
        import os
        from PIL import Image
        import cv2
        import numpy as np
        
        # Verifica o tipo de arquivo
        media_file = next(f for f in os.listdir("uploads") if f.startswith("media_"))
        file_ext = media_file.lower().split('.')[-1]
        import wave
        
        audio_file = next(f for f in os.listdir("uploads") if f.startswith("audio_"))
        media_file = next(f for f in os.listdir("uploads") if f.startswith("media_"))

        # Lê o arquivo de áudio
        audio_path = os.path.join("uploads", audio_file)
        media_path = os.path.join("uploads", media_file)
        
        # Cria o arquivo combinado
        output_path = os.path.join("uploads", f"scents_{media_file}")
        
        # Implementa esteganografia real
        img = Image.open(media_path)
        with open(audio_path, 'rb') as audio:
            audio_data = audio.read()
        
        # Converte os dados do áudio em bits
        audio_bits = ''.join(format(byte, '08b') for byte in audio_data)
        
        # Converte a imagem para RGB se não estiver
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        pixels = list(img.getdata())
        newPixels = []
        
        # Insere os bits do áudio nos bits menos significativos dos pixels
        for i, pixel in enumerate(pixels):
            if i < len(audio_bits) // 3:
                r = (pixel[0] & ~1) | int(audio_bits[i*3])
                g = (pixel[1] & ~1) | int(audio_bits[i*3 + 1])
                b = (pixel[2] & ~1) | int(audio_bits[i*3 + 2])
                newPixels.append((r,g,b))
            else:
                newPixels.append(pixel)
                
        # Cria nova imagem com os dados escondidos
        newImg = Image.new(img.mode, img.size)
        newImg.putdata(newPixels)
        newImg.save(output_path)
        
        return {
            "status": "success", 
            "message": "Scents aplicado com sucesso",
            "output_file": f"scents_{media_file}"
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/paste-token", response_class=HTMLResponse)
async def paste_token_page():
    return FileResponse("paste-token.html")

@app.get("/api/stats")
async def get_api_stats(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, subscription_tier FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()
        
        if not user_data:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
            
        user_id, tier = user_data
        
        # Get usage statistics
        cursor.execute("SELECT COUNT(*) FROM api_usage WHERE user_id = ?", (user_id,))
        usage_count = cursor.fetchone()[0]
        
        # Define limits based on tier
        tier_limits = {
            "free": 100,
            "basic": 1000,
            "pro": 10000
        }
        
        limit = tier_limits.get(tier, 100)
        remaining = max(0, limit - usage_count)
        
        return {
            "active_ads": usage_count,
            "conversions": usage_count,
            "remaining_calls": remaining,
            "tier": tier
        }
    finally:
        conn.close()

@app.get("/api/subscription")
async def get_subscription(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT subscription_tier, api_key FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()
        
        if not user_data:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
            
        tier, api_key = user_data
        return {"tier": tier, "api_key": api_key}
    finally:
        conn.close()

@app.get("/list-uploads")
def list_uploads(token: str = Depends(oauth2_scheme)):
    if not os.path.exists("uploads"):
        return []
    
    from datetime import datetime
    import pytz
    
    timezone = pytz.timezone('America/Sao_Paulo')
    files = []
    for filename in os.listdir("uploads"):
        file_path = os.path.join("uploads", filename)
        if os.path.isfile(file_path):
            timestamp = os.path.getctime(file_path)
            dt = datetime.fromtimestamp(timestamp)
            br_time = timezone.localize(dt)
            files.append({
                "filename": filename,
                "uploaded_at": br_time.strftime("%d/%m/%Y %H:%M:%S")
            })
    return files

# Simulação de banco de dados (temporário) -  Retained from original code
users_db = {}
ads_db = {}