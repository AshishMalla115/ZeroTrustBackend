from fastapi import FastAPI
from app.engine.ffi_engine import create_ffi_engine
from app.engine.stub_engine import EngineConfig
from app.middleware.risk import RiskMiddleware
from app.routes import auth
import os

# 1. Create app first
app = FastAPI(title="ZeroTrust Backend")

# 2. Create engine
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

# 3. Add middleware (app exists now, engine exists now)
app.add_middleware(RiskMiddleware, engine=engine)

# 4. Include routes
app.include_router(auth.router)

@app.get("/protected")
def protected():
    return {"message": "you got through"}

@app.get("/health")
def health():
    return {"status": "ok", "engine": "ffi"}