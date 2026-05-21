# Optional containerized deployment (dashboard + tooling; daemon needs host webcam)
FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1-mesa-glx libglib2.0-0 libsm6 libxext6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

EXPOSE 8765
CMD ["python", "-c", "from dashboard.app import run_dashboard; run_dashboard('0.0.0.0', 8765)"]
