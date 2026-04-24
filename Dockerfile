# syntax=docker/dockerfile:1.6

# ---- Stage 1: build frontend static assets ----
FROM node:20-alpine AS frontend-build
WORKDIR /build/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build


# ---- Stage 2: runtime image ----
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SG_WORKSPACE=/app/workspace \
    SG_DATABASE=/app/workspace/history.db \
    SG_HTTP_HOST=0.0.0.0 \
    SG_HTTP_PORT=8765

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY smartgraphical ./smartgraphical
COPY docs ./docs
COPY sg_web.py sg_cli.py ./

COPY --from=frontend-build /build/frontend/dist ./frontend/dist

RUN mkdir -p /app/workspace

ARG SG_TOOL_VERSION=docker-unversioned
ENV SG_TOOL_VERSION=${SG_TOOL_VERSION}

EXPOSE 8765

CMD ["python", "sg_web.py"]
