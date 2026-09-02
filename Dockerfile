FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# 8080 plaintext (behind a TLS-terminating Ingress), 8443 when the service
# terminates TLS itself -- which a NodePort requires, since L4 forwarding
# puts nothing in the path to do it for us. Which one is actually bound
# comes from PORT; see app/__main__.py.
EXPOSE 8080 8443
ENV PYTHONUNBUFFERED=1

# `python -m app` rather than a hardcoded uvicorn invocation: HOST/PORT and
# the TLS keypair all come from settings, and the previous CMD silently
# ignored them.
CMD ["python", "-m", "app"]
