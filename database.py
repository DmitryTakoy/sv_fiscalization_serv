from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.pool import QueuePool

SQLALCHEMY_DATABASE_URL = "sqlite:///./webhooks.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False},
    poolclass=QueuePool,
    pool_size=20,  # Увеличиваем размер пула
    max_overflow=30,  # Увеличиваем максимальное количество дополнительных соединений
    pool_timeout=60,  # Увеличиваем таймаут
    pool_recycle=3600  # Переиспользуем соединения каждый час
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close() 