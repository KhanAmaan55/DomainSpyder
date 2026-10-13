# syntax=docker/dockerfile:1

# Build:  docker build -t domainspyder .
# Run:    docker run --rm -it domainspyder dns example.com
# Save reports to the current directory by mounting it at /data:
#         docker run --rm -it -v "$PWD:/data" domainspyder info example.com --output report.html

ARG PYTHON_VERSION=3.13

# --- build: install the package and its dependencies into a venv ---
FROM python:${PYTHON_VERSION}-slim AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /src
COPY pyproject.toml README.md LICENCE ./
COPY domainspyder ./domainspyder
RUN pip install .

# --- runtime: the venv only, no build context or pip cache ---
FROM python:${PYTHON_VERSION}-slim

LABEL org.opencontainers.image.title="DomainSpyder" \
      org.opencontainers.image.description="Domain intelligence from one CLI: subdomains, DNS, ports, tech detection and WHOIS" \
      org.opencontainers.image.source="https://github.com/KhanAmaan55/DomainSpyder" \
      org.opencontainers.image.url="https://github.com/KhanAmaan55/DomainSpyder" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.authors="Amaan Khan"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=build /opt/venv /opt/venv

# Run as an unprivileged user. /data is the working directory, so relative
# --output, --save and --wordlist paths resolve inside a mounted volume.
RUN useradd --create-home --uid 1000 spyder \
    && mkdir /data \
    && chown spyder:spyder /data
USER 1000:1000
WORKDIR /data

ENTRYPOINT ["domainspyder"]
CMD ["--help"]
