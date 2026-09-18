# Build from the repository root:
#   docker build -f control-plane/Dockerfile .
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY control-plane/ /app/
RUN pip install '.[postgres]'

CMD ["python", "-m", "iasg"]
