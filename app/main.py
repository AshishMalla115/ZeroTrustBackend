from fastapi import FastAPI
from app.engine.ffi_engine import create_ffi_engine
from app.engine.stub_engine import EngineConfig
from app.routes import auth
import os

app = FastAPI(title="ZeroTrust Backend")

config = EngineConfig(
    model_path            = "none",
    score_threshold_mfa   = 0.4,
    score_threshold_block = 0.75,
    decay_rate            = 0.1,
    tick_interval_sec     = 60,
    max_users             = 1000
)

SO_PATH = os.getenv("SO_PATH", "/home/ashis/ZeroTrustBackend/libriskscore.so")
engine  = create_ffi_engine(config, SO_PATH)

app.include_router(auth.router)


@app.get("/health")
def health():
    return {"status": "ok", "engine": "ffi"}