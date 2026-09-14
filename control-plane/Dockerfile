# Build from the repository root: the model is trained from datasets/v4.
#   docker build -f control-plane/Dockerfile .
# glibc-based image keeps the official scikit-learn wheels available.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY control-plane/ /app/
RUN pip install '.[postgres,ml]'

# Trained here rather than copied in, so the pickled model always matches the
# scikit-learn version this image runs. Flags mirror models/part5-v4-iforest.
COPY datasets/v4 /tmp/v4
RUN python -m iasg.ml.train \
        --dataset /tmp/v4 \
        --out /app/models/current \
        --version part5-v4-iforest \
        --false-positive-budget 0.02 \
    && rm -rf /tmp/v4

ENV IASG_MODEL_PATH=/app/models/current/model.joblib \
    IASG_MODEL_METADATA_PATH=/app/models/current/metadata.json

CMD ["python", "-m", "iasg"]
