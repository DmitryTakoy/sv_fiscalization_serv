from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class WebhookLog(Base):
    __tablename__ = "webhook_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    signature = Column(String)
    payload = Column(JSON)
    human_readable_payload = Column(JSON)  # Store human-readable version of the payload
    verification_status = Column(String)  # success/failed
    error_message = Column(String, nullable=True)

class FiscalizationLog(Base):
    __tablename__ = "fiscalization_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    sale_id = Column(String, index=True)  # To link with original sale
    status = Column(String)  # success/failed
    payload = Column(JSON)
    fiscal_receipt = Column(JSON)  # Store the formatted receipt data
    error_message = Column(String, nullable=True)

class QRCodeLog(Base):
    __tablename__ = "qr_code_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    serial_number = Column(String, unique=True, index=True)  # Unique constraint ensures one record per device
    qr_string = Column(String)  # The formatted QR code string
    timestamp = Column(DateTime, default=datetime.utcnow) 