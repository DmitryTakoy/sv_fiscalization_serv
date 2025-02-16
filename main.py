import json
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Dict, Any
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import logging
import codecs
from datetime import datetime
import os
from dotenv import load_dotenv

from models import Base, WebhookLog, FiscalizationLog
from database import engine, get_db

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# SmartVend Ed25519 public key (DER format)
PUBLIC_KEY_DER = bytes.fromhex(os.getenv('PUBLIC_KEY_DER'))

def decode_unicode(s: str) -> str:
    """Decode Unicode escape sequences to readable text."""
    if not isinstance(s, str):
        return s
    try:
        # Try to decode unicode escapes
        decoded = bytes(s, 'utf-8').decode('unicode-escape')
        # Then ensure proper UTF-8 encoding
        return decoded.encode('latin1').decode('utf-8')
    except Exception as e:
        logger.error(f"Error decoding string: {e}")
        return s

def humanize_payload(payload: Dict) -> Dict:
    """Convert Unicode escape sequences in payload to readable text."""
    result = {}
    for key, value in payload.items():
        if isinstance(value, str):
            result[key] = decode_unicode(value)
        elif isinstance(value, list):
            result[key] = [
                humanize_payload(item) if isinstance(item, dict) else 
                decode_unicode(item) if isinstance(item, str) else item 
                for item in value
            ]
        elif isinstance(value, dict):
            result[key] = humanize_payload(value)
        else:
            result[key] = value
    return result

def load_public_key():
    """Загрузка Ed25519 ключа из DER с правильной обработкой структуры"""
    try:
        # Публичный ключ всегда последние 32 байта в DER для Ed25519
        key_bytes = PUBLIC_KEY_DER[-32:]
        return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
    except Exception as e:
        logger.error(f"Ошибка загрузки ключа: {e}")
        raise

# Load public key once at startup
PUBLIC_KEY = load_public_key()


# В обработчике вебхука добавьте комментарий:
# SmartVend должен гарантировать единый формат для paymentTypes:
# - Либо всегда массив: ["electronic"]
# - Либо всегда строка: "{electronic}"
# Текущая реализация принимает оба формата, но требует согласования
def prepare_json_for_signature(data: Any) -> Any:
    """Рекурсивная канонизация без изменения типов данных"""
    if isinstance(data, dict):
        return {
            key: prepare_json_for_signature(value)
            for key, value in sorted(data.items(), key=lambda x: x[0])
        }
    
    if isinstance(data, list):
        if data and isinstance(data[0], dict):
            return sorted(
                [prepare_json_for_signature(item) for item in data],
                key=lambda x: json.dumps(x, sort_keys=True, ensure_ascii=False)
            )
        return [prepare_json_for_signature(item) for item in data]
    
    return data  # Сохраняем оригинальные значения

def get_canonical_json(payload: Dict) -> bytes:
    """Генерация канонического JSON в бинарном виде"""
    processed = prepare_json_for_signature(payload)
    return json.dumps(
        processed,
        ensure_ascii=False,
        separators=(',', ':'),
        sort_keys=True
    ).encode('utf-8')

def get_canonical_json(payload: Dict) -> bytes:
    """Get canonical JSON representation for signature verification."""
    try:
        # Convert to canonical form
        canonical = prepare_json_for_signature(payload)
        # Convert to JSON string with specific formatting
        canonical_str = json.dumps(
            canonical,
            ensure_ascii=False,
            separators=(',', ':'),
            sort_keys=True
        )
        logger.debug(f"Canonical JSON: {canonical_str}")
        # Convert to UTF-8 bytes
        return canonical_str.encode('utf-8')
    except Exception as e:
        logger.error(f"Error creating canonical JSON: {e}")
        raise

def verify_signature(payload: Dict, signature: str) -> bool:
    try:
        canonical_bytes = get_canonical_json(payload)
        logger.info(f"Canonical JSON: {canonical_bytes.decode('utf-8')}")
        
        signature_bin = base64.b64decode(signature)
        if len(signature_bin) != 64:
            logger.error(f"Invalid signature length: {len(signature_bin)} bytes")
            return False
        
        PUBLIC_KEY.verify(signature_bin, canonical_bytes)
        return True
    
    except InvalidSignature:
        logger.error("Signature mismatch. Critical checks:")
        logger.error(f"Expected: {canonical_bytes.hex()}")
        logger.error(f"Signature: {signature_bin.hex()}")
        return False

# @app.post("/webhook")
# async def webhook(request: Request, db: Session = Depends(get_db)):
#     try:
#         # Логирование сырого payload для отладки
#         raw_body = await request.body()
#         logger.info(f"Raw body: {raw_body.decode()}")
#         logger.info("Received webhook request")
#         logger.info(f"Headers: {dict(request.headers)}")
#         payload = await request.json()
#         payload = await request.json()
        
#         # Логирование для сравнения с сервером
#         logger.info("Original payload structure:")
#         logger.info(json.dumps(payload, indent=2, ensure_ascii=False))
#         # Get signature from headers
#         signature = request.headers.get("x-signature")
#         if not signature:
#             logger.error("Missing x-signature header")
#             raise HTTPException(status_code=400, detail="Missing x-signature header")
        
#         # Get payload
#         payload = await request.json()
        
#         # Create human-readable version of the payload
#         human_readable = humanize_payload(payload)
        
#         # Log both versions
#         logger.info(f"Original payload: {json.dumps(payload, indent=2, ensure_ascii=False)}")
#         logger.info(f"Human-readable payload: {json.dumps(human_readable, indent=2, ensure_ascii=False)}")
        
#         # Verify signature
#         is_valid = verify_signature(payload, signature)
#         logger.info(f"Signature verification result: {'valid' if is_valid else 'invalid'}")
        
#         # Log webhook with both original and human-readable payloads
#         log = WebhookLog(
#             signature=signature,
#             payload=payload,
#             human_readable_payload=human_readable,
#             verification_status="success" if is_valid else "failed",
#             error_message=None if is_valid else "Invalid signature"
#         )
#         db.add(log)
#         db.commit()
#         logger.info(f"Webhook logged with ID: {log.id}")
        
#         # Now we'll enforce signature validation
#         if not is_valid:
#             raise HTTPException(status_code=400, detail="Invalid signature")
        
#         return {"status": "success"}
#     except Exception as e:
#         logger.error(f"Error processing webhook: {str(e)}", exc_info=True)
#         raise

@app.post("/fiscalization")
async def fiscalization(request: Request, db: Session = Depends(get_db)):
    try:
        # Log raw payload for debugging
        raw_body = await request.body()
        logger.info(f"Raw fiscalization body: {raw_body.decode()}")
        
        # Get payload
        payload = await request.json()
        logger.info(f"Fiscalization payload: {json.dumps(payload, indent=2, ensure_ascii=False)}")
        
        # Extract key information
        sale_id = payload.get("saleId")
        status = payload.get("fiscalizationStatus")
        
        # Prepare fiscal receipt data if successful
        fiscal_receipt = None
        if status == "success" and "fiscalizationSuccess" in payload:
            fiscal_data = payload["fiscalizationSuccess"]
            orange_data = fiscal_data.get("orangedataCheck", {})
            fiscal_receipt = {
                "qr_hex": fiscal_data.get("qrHexString"),
                "receipt_number": orange_data.get("i"),  # номер чека
                "amount": orange_data.get("s"),  # сумма
                "timestamp": orange_data.get("t"),  # время
                "fiscal_number": orange_data.get("fn"),  # номер ФН
                "fiscal_document": orange_data.get("fp")  # ФП документа
            }
        
        # Create fiscalization log
        log = FiscalizationLog(
            sale_id=sale_id,
            status=status,
            payload=payload,
            fiscal_receipt=fiscal_receipt,
            error_message=payload.get("fiscalizationFailedReason")
        )
        db.add(log)
        db.commit()
        logger.info(f"Fiscalization logged with ID: {log.id}")
        
        return {"status": "success", "message": "Fiscalization event logged"}
        
    except Exception as e:
        logger.error(f"Error processing fiscalization: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, db: Session = Depends(get_db)):
    # Get both webhook and fiscalization logs
    webhook_logs = db.query(WebhookLog).order_by(WebhookLog.timestamp.desc()).all()
    fiscalization_logs = db.query(FiscalizationLog).order_by(FiscalizationLog.timestamp.desc()).all()
    
    # Convert Unicode escapes to readable text in webhook logs
    readable_webhook_logs = []
    for log in webhook_logs:
        readable_log = log.__dict__.copy()
        readable_log['payload'] = humanize_payload(log.payload)
        readable_webhook_logs.append(readable_log)
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "webhook_logs": readable_webhook_logs,
        "fiscalization_logs": fiscalization_logs
    })
