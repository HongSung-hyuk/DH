FROM debian:13-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssh-client python3 python3-cryptography \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 rotator \
    && useradd -u 10001 -g 10001 -M -d /nonexistent -s /usr/sbin/nologin rotator
WORKDIR /app
COPY --chmod=0644 rotator.py .
USER 10001:10001
ENTRYPOINT ["python3", "/app/rotator.py"]
