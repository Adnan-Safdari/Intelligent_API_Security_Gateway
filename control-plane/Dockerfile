# Build from the repository root:
#   docker build -f control-plane/Dockerfile .
# glibc-based image keeps the official scikit-learn wheels available.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY control-plane/ /app/
RUN pip install '.[postgres,ml]'

# No anomaly model is baked in: the training datasets are kept outside the
# repository. Without one the ML component reports model_unavailable and
# contributes nothing to the risk score. To use a model, train it from a
# dataset (python -m iasg.ml.train) and mount it at /app/models/current.

CMD ["python", "-m", "iasg"]
