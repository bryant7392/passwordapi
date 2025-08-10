FROM python:3.11-slim

# Optional: system packages for better compatibility
RUN apt-get update && apt-get install -y gcc libmariadb-dev libmariadb-dev-compat && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app /app

# Install dependencies
RUN pip install fastapi uvicorn mysql-connector-python

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
