import os
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from telethon import TelegramClient, events
from supabase_config.supabase_client import supabase

# ─── Carrega variáveis de ambiente ───
load_dotenv()

# ─── Configurações Gerais ───
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
SECRET_KEY = os.getenv("SECRET_KEY", "buscadesp_is_lit_2025")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ─── Inicializa FastAPI ───
app = FastAPI(
    title="BuscaDesp",
    version="1.0.0",
    docs_url="/docs",
    openapi_url="/openapi.json"
)

# ─── Middlewares ───
app.add_middleware(GZipMiddleware, minimum_size=1024)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Models ───
class UserIn(BaseModel):
    email: str
    password: str

class ConsultaRequest(BaseModel):
    tipo: str  # Ex: "nome", "cpf3", "telefone"
    valor: str

# ─── Endpoints ───
@app.post("/login")
async def login(data: UserIn):
    resp = supabase.auth.sign_in(email=data.email, password=data.password)
    if resp.get("user"):
        return {"message": "Login válido (token desativado por enquanto)"}
    raise HTTPException(status_code=401, detail="Credenciais inválidas")

@app.post("/consulta")
async def consulta(data: ConsultaRequest):
    # Aqui você colocará a lógica real depois (ex: enviar comando via bot)
    return {
        "status": "Consulta enviada",
        "comando": f"/{data.tipo} {data.valor}"
    }

@app.get("/")
async def root():
    return {"message": "🚀 BuscaDesp rodando em produção!"}

# ─── Bot Telegram (só ativa se variáveis estiverem setadas) ───
API_ID = int(os.getenv("TG_API_ID", 0))
API_HASH = os.getenv("TG_API_HASH", "")
bot = TelegramClient("buscadesp_session", API_ID, API_HASH)

@bot.on(events.NewMessage(pattern=r"/nome (.+)"))
async def handler_nome(event):
    nome = event.pattern_match.group(1)
    await event.reply(f"[BUSCADESP] pesquisando nome: {nome}")

@app.on_event("startup")
async def start_telegram_bot():
    if API_ID and API_HASH:
        logging.info("🤖 Iniciando bot Telegram...")
        await bot.start()
    else:
        logging.warning("❌ TG_API_ID ou TG_API_HASH não configurados. Bot não será iniciado.")

# ─── Entry Point ───
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), log_level="info")
