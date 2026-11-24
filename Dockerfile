# ReconPulse runtime image.
#
#   docker build -t reconpulse .
#   docker run --rm -v "$PWD/out:/out" reconpulse scan https://example.com --out /out
#
# Active runs need an authorization file mounted read-only and the explicit
# confirmation flag, exactly like the CLI:
#   docker run --rm -v "$PWD/authorization.yaml:/auth/authorization.yaml:ro" \
#     reconpulse scan https://example.com --mode active --auth /auth/authorization.yaml \
#     --i-have-written-authorization --dry-run

FROM python:3.12-slim AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --prefix=/install .

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 reconpulse \
    && useradd --uid 10001 --gid reconpulse --no-create-home --shell /usr/sbin/nologin reconpulse \
    && mkdir -p /out \
    && chown reconpulse:reconpulse /out

COPY --from=build /install /usr/local

USER reconpulse
WORKDIR /out

ENTRYPOINT ["reconpulse"]
CMD ["--help"]
