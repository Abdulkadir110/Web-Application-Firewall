FROM python:3.9-slim

WORKDIR /app
COPY ml_service.py requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

# Install scikit-learn explicitly (required for joblib)
RUN pip install scikit-learn==1.0.2 flask pandas

CMD ["python", "ml_service.py"]