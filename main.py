from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # ou liste seus domínios em produção
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

import os
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel
from passlib.hash import bcrypt
from jose import JWTError, jwt
from dotenv import load_dotenv
import requests
from telethon import TelegramClient, events
from supabase_config.supabase_client import supabase

# ─── Configurações gerais ───
load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
SECRET_KEY = os.getenv("SECRET_KEY", "buscadesp_is_lit_2025")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(
    title="BuscaDesp",
    version="1.0.0",
    docs_url="/docs",           # em produção você pode desabilitar (/docs=None)
    openapi_url="/openapi.json"
)

# ─── Middlewares ───
app.add_middleware(GZipMiddleware, minimum_size=1024)  # compacta respostas >1KB
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Modelos Pydantic ───
class UserIn(BaseModel):
    email: str
    password: str

# ─── Endpoints ───
@app.post("/login")
async def login(data: UserIn):
    # exemplo: valida no Supabase
    resp = supabase.auth.sign_in(email=data.email, password=data.password)
    if resp.get("user"):
        token = jwt.encode({"sub": data.email}, SECRET_KEY, algorithm=ALGORITHM)
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Credenciais inválidas")

@app.get("/")
async def root():
    return {"message": "🚀 BuscaDesp rodando em produção!"}

# ─── Bot do Telegram ───
API_ID = int(os.getenv("TG_API_ID", 0))
API_HASH = os.getenv("TG_API_HASH", "")
bot = TelegramClient("buscadesp_session", API_ID, API_HASH)

@bot.on(events.NewMessage(pattern=r"/nome (.+)"))
async def handler_nome(event):
    nome = event.pattern_match.group(1)
    # aqui implementa a consulta e reply
    await event.reply(f"[BUSCADESP] pesquisando nome: {nome}")

@app.on_event("startup")
async def start_telegram_bot():
    if API_ID and API_HASH:
        logging.info("Iniciando bot Telegram…")
        bot.start()
    else:
        logging.warning("TG_API_ID ou TG_API_HASH não configurados, bot não iniciará")

# ─── Entry point para o Gunicorn ───
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), log_level="info")

if __name__ == "__main__":
    import os
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        workers=4,
        timeout_keep_alive=120
    )

