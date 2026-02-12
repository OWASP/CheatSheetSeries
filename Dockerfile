FROM python:latest
WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt Makefile ./
RUN make install-python-requirements

COPY . .
RUN make generate-site

EXPOSE 8000
ENTRYPOINT ["make", "serve"]
