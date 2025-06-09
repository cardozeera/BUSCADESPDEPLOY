# main.py

import os
import io
import logging
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel
from passlib.hash import bcrypt
from jose import JWTError, jwt
from dotenv import load_dotenv
import requests

from telethon import TelegramClient, events
from supabase_config.supabase_client import supabase

# ─────────── Carrega variáveis de ambiente ───────────
load_dotenv()

SECRET_KEY                  = os.getenv("SECRET_KEY", "buscadesp_is_lit_2025")
ALGORITHM                   = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

API_ID       = int(os.getenv("API_ID", "0"))
API_HASH     = os.getenv("API_HASH", "")
SESSION_NAME = os.getenv("SESSION_NAME", "buscadesp_session")
BOT_USERNAME = os.getenv("BOT_USERNAME", "@Yanbuscabot")
BASE_URL     = os.getenv("BASE_URL", "https://buscadespdeploy-2.onrender.com")

# ───────── Configure Logging ─────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─────────── Inicializa o FastAPI ───────────
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────── JWT no Swagger (Botão Authorize) ───────────
security = HTTPBearer()

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="BuscaDesp API",
        version="1.0.0",
        description="API do BuscaDesp com autenticação JWT",
        routes=app.routes,
    )

    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {"type": "http", "scheme": "bearer"}
    }
    for path in openapi_schema["paths"].values():
        for method in path.values():
            method.setdefault("security", [{"BearerAuth": []}])

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# ─────────── Modelos Pydantic ───────────
class Usuario(BaseModel):
    email: str
    senha: str

class Consulta(BaseModel):
    tipo_busca: str
    termo: str
    resultado: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

# ─────────── Funções de JWT ───────────
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Token inválido")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    token = credentials.credentials
    return verify_token(token)

# ─────────── Rotas FastAPI ───────────
@app.get("/")
def root():
    return {"message": "🚀 API BuscaDesp rodando. Use /login para obter token."}

@app.post("/login", response_model=TokenResponse)
def login_usuario(usuario: Usuario):
    resultado = supabase.table("usuarios").select("*").eq("email", usuario.email).execute()
    if not resultado.data:
        raise HTTPException(status_code=401, detail="Email não encontrado")
    usuario_db = resultado.data[0]
    if not bcrypt.verify(usuario.senha, usuario_db["senha_hash"]):
        raise HTTPException(status_code=401, detail="Senha incorreta")

    token = create_access_token(
        {"sub": str(usuario_db["id"])},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": token, "token_type": "bearer"}

@app.post("/consulta")
def registrar_consulta(
    consulta: Consulta,
    current_user_id: str = Depends(get_current_user)
):
    supabase.table("consultas").insert({
        "usuario_id": current_user_id,
        "tipo_busca": consulta.tipo_busca,
        "termo": consulta.termo,
        "resultado": consulta.resultado,
        "criado_em": datetime.utcnow().isoformat()
    }).execute()
    return {"status": "registrado", "usuario_id": current_user_id}

@app.get("/consultas")
def listar_consultas(current_user_id: str = Depends(get_current_user)):
    resp = supabase.table("consultas") \
        .select("*") \
        .eq("usuario_id", current_user_id) \
        .order("criado_em", desc=True) \
        .execute()
    return resp.data

# ─────────── Telegram Opcional ───────────
client = TelegramClient(SESSION_NAME, API_ID, API_HASH)

@app.on_event("startup")
async def startup_event():
    if os.getenv("RENDER") == "true":
        logger.info("Rodando no Render: pulando conexão do Telegram.")
        return
    try:
        await client.connect()
        if not await client.is_user_authorized():
            logger.warning("Telethon NÃO autorizado no container.")
            return
        username = (await client.get_me()).username
        logger.info("Telethon conectado como @%s", username)
    except Exception as e:
        logger.error("Falha ao conectar Telethon no startup: %s", e, exc_info=True)

@app.on_event("shutdown")
async def shutdown_event():
    try:
        await client.disconnect()
    except:
        pass
