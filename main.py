import os
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
import pdfplumber

from telethon import TelegramClient
from telethon.errors import TimeoutError
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

# ─────────── JWT no Swagger (Authorise Button) ───────────
security = HTTPBearer()

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title="BuscaDesp API",
        version="1.0.0",
        description="API BuscaDesp com JWT e consulta via Telegram",
        routes=app.routes,
    )
    schema["components"]["securitySchemes"] = {
        "BearerAuth": {"type": "http", "scheme": "bearer"}
    }
    for path in schema["paths"].values():
        for op in path.values():
            op.setdefault("security", [{"BearerAuth": []}])

    app.openapi_schema = schema
    return app.openapi_schema

app.openapi = custom_openapi

# ─────────── Modelos Pydantic ───────────
class Usuario(BaseModel):
    email: str
    senha: str

class Consulta(BaseModel):
    tipo_busca: str
    termo: str

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
        if not user_id:
            raise HTTPException(status_code=401, detail="Token inválido")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    return verify_token(credentials.credentials)

# ─────────── Inicializa Telethon ───────────
client = TelegramClient(SESSION_NAME, API_ID, API_HASH)

@app.on_event("startup")
async def on_startup():
    if os.getenv("RENDER") == "true":
        logger.info("Render detectado: pulando Telethon.")
        return
    await client.connect()
    if not await client.is_user_authorized():
        logger.warning("Telethon NÃO autorizado no container.")
    else:
        user = await client.get_me()
        logger.info(f"Telethon conectado como @{user.username}")

@app.on_event("shutdown")
async def on_shutdown():
    await client.disconnect()

# ─────────── Extração de PDF ───────────
def extract_text_do_pdf(path: str) -> str:
    try:
        with pdfplumber.open(path) as pdf:
            return "\n".join(page.extract_text() or "" for page in pdf.pages)
    except Exception as e:
        logger.error(f"Erro extraindo PDF: {e}", exc_info=True)
        return ""

# ─────────── Consulta via Bot ───────────
async def consulta_bot(tipo: str, termo: str, timeout: int = 30) -> str:
    cmd = f"/{tipo} {termo}"
    try:
        async with client.conversation(BOT_USERNAME, timeout=timeout) as conv:
            await conv.send_message(cmd)
            resp = await conv.get_response()
            if resp.document:
                path = await resp.download_media()
                return extract_text_do_pdf(path)
            return resp.text or ""
    except TimeoutError:
        raise HTTPException(status_code=504, detail="Timeout no bot Telegram")
    except Exception as e:
        logger.error(f"Erro consulta_bot: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Erro interno de consulta")

# ─────────── Rotas FastAPI ───────────
@app.get("/")
def root():
    return {"message": "🚀 BuscaDesp OK — use /login e /busca"}

@app.post("/login", response_model=TokenResponse)
def login(usuario: Usuario):
    resp = supabase.table("usuarios").select("*").eq("email", usuario.email).execute()
    if not resp.data:
        raise HTTPException(status_code=401, detail="Email não encontrado")
    user = resp.data[0]
    if not bcrypt.verify(usuario.senha, user["senha_hash"]):
        raise HTTPException(status_code=401, detail="Senha incorreta")
    token = create_access_token({"sub": str(user["id"])}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token}

@app.post("/busca")
async def busca(consulta: Consulta, user_id: str = Depends(get_current_user)):
    resultado = await consulta_bot(consulta.tipo_busca, consulta.termo)
    supabase.table("consultas").insert({
        "usuario_id": user_id,
        "tipo_busca": consulta.tipo_busca,
        "termo": consulta.termo,
        "resultado": resultado,
        "criado_em": datetime.utcnow().isoformat()
    }).execute()
    return {"resultado": resultado}

@app.get("/consultas")
def listar(user_id: str = Depends(get_current_user)):
    resp = supabase.table("consultas") \
        .select("*") \
        .eq("usuario_id", user_id) \
        .order("criado_em", desc=True) \
        .execute()
    return resp.data
