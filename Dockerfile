FROM python:3.12-slim
ARG SAFETY_VERSION

# Don't use WORKDIR here as per Github's docs
RUN mkdir /app

RUN apt-get update && apt-get -y install docker.io jq git && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /app/entrypoint.sh

RUN cd /app && python3 -m pip install safety==$SAFETY_VERSION

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV PYTHONPATH="/app"

ENTRYPOINT ["/app/entrypoint.sh"]
