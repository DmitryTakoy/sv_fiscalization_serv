# SmartVend Webhook Logger

Изолированное приложение для приема и логирования вебхуков от SmartVend.

## Установка

1. Создайте виртуальное окружение:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# или
venv\Scripts\activate  # Windows
```

2. Установите зависимости:
```bash
pip install -r requirements.txt
```

3. Настройте публичный ключ RSA в файле `main.py`

## Запуск

```bash
python run.py
```

Приложение будет доступно по адресу: http://127.0.0.1:8001

## Endpoints

- `GET /` - веб-интерфейс для просмотра логов
- `POST /webhook` - endpoint для приема вебхуков

## Формат webhook'а

Заголовки:
- `x-signature` - RSA подпись в формате base64

Тело запроса: JSON

## Проверка подписи

1. JSON сортируется по ключам
2. Подпись декодируется из base64
3. Проверяется RSA подпись 