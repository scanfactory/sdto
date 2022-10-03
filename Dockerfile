FROM python:3.8-alpine

WORKDIR /app

ADD . .

RUN pip3 install poetry && poetry install

ENTRYPOINT ["python3", "-m", "sdto"]
CMD ["-v"]
