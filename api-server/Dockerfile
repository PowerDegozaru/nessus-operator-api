FROM python:3.13-slim

RUN useradd -ms /bin/bash app

COPY --chown=app:app ./requirements.txt /home/app/
RUN pip install --no-cache-dir -r /home/app/requirements.txt
RUN playwright install-deps     # Needs root

USER app
WORKDIR /home/app

RUN playwright install          # Per-User Installation Only

COPY . /home/app

CMD ["fastapi", "run", "/home/app/src/main.py"]
