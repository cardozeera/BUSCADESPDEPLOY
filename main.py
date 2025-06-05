# main.py

import os
import io
import logging
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.hash import bcrypt
from jose import JWTError, jwt
from dotenv import load_dotenv
import requests

from telethon import TelegramClient, events
from supabase_config.supabase_client import supabase  # seu cliente Supabase já está configurado neste módulo

# ─────────── Carrega variáveis de ambiente ───────────
load_dotenv()

# Supabase (já configurado em supabase_config), mas deixamos as variáveis aqui para referência:
# SUPABASE_URL   = os.getenv("SUPABASE_URL")
# SUPABASE_KEY   = os.getenv("SUPABASE_KEY")

SECRET_KEY               = os.getenv("SECRET_KEY", "buscadesp_is_lit_2025")
ALGORITHM                = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Telethon / Telegram
API_ID         = int(os.getenv("API_ID", "0"))                # ex.: 28382442
API_HASH       = os.getenv("API_HASH", "")                    # ex.: 5f5cdede83eecadeef4234fc1bd095a5c
PHONE          = os.getenv("PHONE", "")                       # ex.: +5551995788207
SESSION_NAME   = os.getenv("SESSION_NAME", "buscadesp_session")
BOT_USERNAME   = os.getenv("BOT_USERNAME", "@Yanbuscabot")     # ex.: @Yanbuscabot

# Base URL público do seu backend no Render (para chamadas HTTP internas)
BASE_URL = os.getenv("BASE_URL", "https://buscadespdeploy-2.onrender.com")

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
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Token inválido")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

async def get_current_user(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Header Authorization inválido")
    token = authorization.split("Bearer ")[1]
    return verify_token(token)

# ─────────── Rotas FastAPI ───────────
@app.get("/")
def root():
    return {"message": "🚀 API BuscaDesp: use /login para obter token e depois /consulta com Authorization."}

@app.post("/login", response_model=TokenResponse)
def login_usuario(usuario: Usuario):
    resultado = supabase.table("usuarios").select("*").eq("email", usuario.email).execute()
    if not resultado.data:
        raise HTTPException(status_code=401, detail="Email não encontrado")
    usuario_db = resultado.data[0]
    if not bcrypt.verify(usuario.senha, usuario_db["senha_hash"]):
        raise HTTPException(status_code=401, detail="Senha incorreta")

    acesso_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token({"sub": str(usuario_db["id"])}, expires_delta=acesso_expires)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/consulta")
def registrar_consulta(consulta: Consulta, current_user_id: str = Depends(get_current_user)):
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

# ─────────── Integração com Telethon ───────────
client = TelegramClient(SESSION_NAME, API_ID, API_HASH)

@client.on(events.NewMessage(pattern=r"^/start"))
async def start_cmd(event):
    await event.reply("Olá! Para consultar, envie:\n/consulta <email> <senha> <tipo> <termo>")

@client.on(events.NewMessage(pattern=r"^/consulta\s+"))
async def consulta_cmd(event):
    chat_id = event.chat_id
    texto = event.message.message.strip()
    partes = texto.split()
    # /consulta <email> <senha> <tipo> <termo>
    if len(partes) < 5:
        await event.reply("Uso incorreto. Envie:\n/consulta <email> <senha> <tipo> <termo>")
        return

    _, email, senha, tipo_busca, *resto = partes
    termo = " ".join(resto).strip()
    if not termo:
        await event.reply("Informe o termo após /consulta <email> <senha> <tipo> <termo>")
        return

    # 1) Autentica via /login do próprio FastAPI
    try:
        resp_login = requests.post(
            f"{BASE_URL}/login",
            json={"email": email, "senha": senha}
        )
    except Exception:
        await event.reply("Erro de rede ao tentar autenticar.")
        return

    if resp_login.status_code != 200:
        detalhe = resp_login.json().get("detail", "Falha no login")
        await event.reply(f"Falha no login: {detalhe}")
        return

    token = resp_login.json().get("access_token")
    if not token:
        await event.reply("Erro ao obter token de acesso.")
        return

    # 2) Gera resultado (substitua pela sua lógica real de consulta)
    resultado_texto = f"Resultado fictício para {tipo_busca} = {termo}"

    # 3) Grava no Supabase via /consulta
    try:
        requests.post(
            f"{BASE_URL}/consulta",
            json={"tipo_busca": tipo_busca, "termo": termo, "resultado": resultado_texto},
            headers={"Authorization": "Bearer " + token}
        )
    except Exception:
        logger.error("Erro ao gravar consulta no Supabase", exc_info=True)

    # 4) Monta arquivo TXT em memória
    txt_content = f"Tipo: {tipo_busca}\nTermo: {termo}\nResultado:\n{resultado_texto}"
    bio = io.BytesIO()
    bio.write(txt_content.encode("utf-8"))
    bio.seek(0)

    # 5) Envia o arquivo TXT de volta ao usuário
    await client.send_file(chat_id, bio, filename="consulta.txt",
                           caption="Aqui está seu resultado em TXT.")

# ─────────── Eventos de Startup/Shutdown ───────────
@app.on_event("startup")
async def startup_event():
    await client.connect()
    if not await client.is_user_authorized():
        raise Exception("Conta Telegram não está autorizada. Execute gerar_session.py primeiro.")
    username = (await client.get_me()).username
    logger.info("Telethon conectado como @%s", username)

@app.on_event("shutdown")
async def shutdown_event():
    await client.disconnect()
