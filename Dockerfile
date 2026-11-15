FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip wheel && \
    pip install --no-cache-dir -r requirements.txt && \
    python -c "import streamlit; import plotly; import pandas; import numpy; print('Preloaded')"

COPY app.py .
COPY auth.py .
COPY secrets_loader.py .
COPY dashboards/ ./dashboards/
COPY config/ ./config/
COPY agent/ ./agent/
COPY assets/ ./assets/
COPY .streamlit/ ./.streamlit/

RUN mkdir -p /app/data

# Pre-compile all Python files to bytecode
RUN python -m compileall /app /usr/local/lib/python3.11/site-packages 2>/dev/null || true

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.headless=true", "--server.runOnSave=false", "--server.fileWatcherType=none", "--browser.gatherUsageStats=false"]
