from fastapi import FastAPI
from app.engine.stub_engine import create_engine, EngineConfig

app = FastAPI(title="ZeroTrust Backend")

# Initialize engine — swap create_engine import in Week 2 for real FFI engine
config = EngineConfig(
    model_path            = "none",
    score_threshold_mfa   = 0.4,
    score_threshold_block = 0.75,
    decay_rate            = 0.1,
    tick_interval_sec     = 60,
    max_users             = 1000
)
engine = create_engine(config)


@app.get("/health")
def health():
    return {"status": "ok", "engine": "stub"}
