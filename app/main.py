from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from app.engine.ffi_engine import create_ffi_engine
from app.engine.stub_engine import EngineConfig
from app.middleware.risk import RiskMiddleware
from app.routes import auth, ws, admin
from app.routes.auth import get_current_user
from app.models.db_models import User, ThresholdConfig
from app.core.database import SessionLocal
from sqlalchemy.exc import SQLAlchemyError
import os
import logging

# 1. Create app first
from contextlib import asynccontextmanager
import asyncio

from sqlalchemy.exc import SQLAlchemyError
import logging

logger = logging.getLogger(__name__)

def load_thresholds():
    db = SessionLocal()
    try:
        tc = db.query(ThresholdConfig).filter(ThresholdConfig.id == 1).first()
        if tc:
            return tc.mfa_threshold, tc.block_threshold
        else:
            # create default row
            tc = ThresholdConfig(id=1, mfa_threshold=0.4, block_threshold=0.75)
            db.add(tc)
            db.commit()
            return 0.4, 0.75
    except SQLAlchemyError as e:
        db.rollback()
        logger.warning("Could not load thresholds from DB, using defaults: %s", e)
        return 0.4, 0.75
    finally:
        db.close()

mfa_thr, block_thr = load_thresholds()

@asynccontextmanager
async def lifespan(app):
    async def tick_loop():
        while True:
            await asyncio.sleep(60)
            engine.tick()
    task = asyncio.create_task(tick_loop())
    yield
    task.cancel()

app = FastAPI(title="ZeroTrust Backend", lifespan=lifespan)


# 2. CORS first — must be before RiskMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. Create engine
MODEL_PATH = os.getenv("MODEL_PATH", "/home/ashis/ZeroTrustBackend/model.isof")

config = EngineConfig(
    model_path            = MODEL_PATH,
    score_threshold_mfa   = mfa_thr,
    score_threshold_block = block_thr,
    decay_rate            = 0.1,
    tick_interval_sec     = 60,
    max_users             = 1000
)
SO_PATH = os.getenv("SO_PATH", "/home/ashis/ZeroTrustBackend/libriskscore.so")
engine  = create_ffi_engine(config, SO_PATH)

# 4. Risk middleware after CORS
app.add_middleware(RiskMiddleware, engine=engine)

# 4. Include routes
app.include_router(auth.router)
app.include_router(ws.router)
app.include_router(admin.router)


@app.get("/health")
def health():
    return {"status": "ok", "engine": "ffi"}


@app.get("/protected")
def protected(user: User = Depends(get_current_user)):
    return {"message": "you got through", "user_id": str(user.id)}
