FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 agent
WORKDIR /agent
COPY --chmod=0644 agent.py probes.py ./
ENV PYTHONUNBUFFERED=1
USER agent
CMD ["python", "agent.py"]
