ARG PYTHON_IMAGE=python:3.13-slim@sha256:bffeb7bd6a85767587059c6ba23e1e9122078e3aa3fa836099171b9bb5a9bb00
FROM ${PYTHON_IMAGE} AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY requirements-build.txt ./
RUN python -m venv /opt/build \
    && /opt/build/bin/pip install --only-binary=:all: --require-hashes -r requirements-build.txt

COPY pyproject.toml README.md LICENSE ./
COPY mrma ./mrma

RUN /opt/build/bin/python -m build --wheel --no-isolation --outdir /dist


FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.source="https://github.com/0xmrma/mrma" \
      org.opencontainers.image.description="Evidence-driven HTTP trust-boundary experimentation" \
      org.opencontainers.image.licenses="MIT"

ENV PATH="/opt/mrma/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin mrma \
    && mkdir /workspace \
    && chown mrma:mrma /workspace

COPY requirements-container.txt ./
RUN python -m venv /opt/mrma \
    && /opt/mrma/bin/pip install --only-binary=:all: --require-hashes -r requirements-container.txt
COPY --from=builder /dist/*.whl /tmp/
RUN /opt/mrma/bin/pip install --no-deps /tmp/*.whl \
    && rm -f /tmp/*.whl

USER mrma
WORKDIR /workspace

ENTRYPOINT ["mrma"]
