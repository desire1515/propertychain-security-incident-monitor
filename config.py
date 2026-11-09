import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")


class Config:
    SECRET_KEY = os.getenv("PCSIRM_SECRET_KEY")

    DATABASE_PATH = BASE_DIR / "instance" / "pcsirm.db"
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024 + 128 * 1024

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv(
        "PCSIRM_SESSION_COOKIE_SECURE", "true"
    ).strip().lower() in {"1", "true", "yes", "on"}
