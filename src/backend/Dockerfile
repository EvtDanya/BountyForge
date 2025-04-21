# syntax=docker/dockerfile:1

FROM python:3.12-slim-bookworm

WORKDIR /app

ARG APP__PORT

COPY ./requirements.txt ./requirements.txt
# COPY ./pyproject.toml ./pyproject.toml
RUN ["python", "-m", "pip", "install", "-r", "requirements.txt"]
# RUN ["poetry", "install"]

COPY ./src/bountyforge ./bountyforge
COPY ./src/backend ./backend
# COPY ./static ./static
ENV PYTHONPATH="/app/"

RUN mkdir -p /var/log/bountyforge

COPY ./src/bountyforge/scripts/run.py ./run.py

EXPOSE $APP__PORT

CMD ["python", "run.py"]
# CMD ["poetry", "run", "python", "run.py"]
