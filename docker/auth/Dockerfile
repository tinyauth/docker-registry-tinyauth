FROM alpine:3.7 AS builder

RUN apk add --no-cache build-base python3-dev libffi-dev openssl-dev
RUN python3 -m venv /app

COPY requirements.txt /requirements.txt
RUN /app/bin/pip install -r requirements.txt

FROM alpine:3.7

RUN apk add --no-cache python3 openssl

COPY --from=builder /app /app
COPY app.py /app/src/app.py

ENV FLASK_APP=/app/src/app.py
ENV PYTHONUNBUFFERED=1

CMD ["/app/bin/flask", "run", "--host=0.0.0.0"]
