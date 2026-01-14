FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

ADD mitm_proxy.py /app/


ENV PYTHONUNBUFFERED=1
RUN pip install rethinkdb


CMD ["python", "mitm_proxy.py"]
