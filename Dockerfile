FROM python:3.10-slim

# Don't use WORKDIR here as per Github's docs
RUN mkdir /app

RUN apt-get update && apt-get -y install docker.io jq && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install poetry and pipenv; used for converting their respective lockfile formats to generic requirements.txt
RUN cd /app && python3 -m pip install poetry==1.1.13 pipenv==2022.6.7

# Install this project dependencies
COPY . /app
RUN cd /app && python3 -m pip install -e .

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV PYTHONPATH="/app"

LABEL safety_autodetect=ignore

ENTRYPOINT ["/app/entrypoint.sh"]
