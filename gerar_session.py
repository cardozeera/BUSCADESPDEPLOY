from telethon import TelegramClient
from dotenv import load_dotenv
import os

load_dotenv()
client = TelegramClient(os.getenv("SESSION_NAME"), int(os.getenv("API_ID")), os.getenv("API_HASH"))

async def main():
    await client.start(phone=os.getenv("PHONE"))
    print("Sessão Telethon criada com sucesso.")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
