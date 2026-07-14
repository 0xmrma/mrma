FROM python:3.13-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY pyproject.toml README.md LICENSE ./
COPY mrma ./mrma

RUN python -m venv /opt/mrma \
    && /opt/mrma/bin/pip install --upgrade pip \
    && /opt/mrma/bin/pip install .


FROM python:3.13-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/0xmrma/mrma" \
      org.opencontainers.image.description="Evidence-driven HTTP trust-boundary experimentation" \
      org.opencontainers.image.licenses="MIT"

ENV PATH="/opt/mrma/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin mrma \
    && mkdir /workspace \
    && chown mrma:mrma /workspace

COPY --from=builder /opt/mrma /opt/mrma

USER mrma
WORKDIR /workspace

ENTRYPOINT ["mrma"]
