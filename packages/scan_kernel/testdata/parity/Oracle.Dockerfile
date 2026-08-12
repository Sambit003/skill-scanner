FROM python:3.12.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/oracle/packages

RUN pip install --no-cache-dir \
    httpx==0.28.1 \
    pydantic==2.13.4 \
    pyyaml==6.0.3 \
    rich==15.0.0 \
    typer==0.27.1 \
    yara-python==4.5.4

COPY packages/scan_kernel /oracle/packages/scan_kernel
COPY oracle_runner.py /oracle/oracle_runner.py

ENTRYPOINT ["python", "/oracle/oracle_runner.py"]
