FROM python:latest
WORKDIR /usr/src/app

COPY requirements.txt Makefile ./
RUN make install-python-requirements

COPY . .
RUN make generate-site

EXPOSE 8000
ENTRYPOINT ["make", "serve"]
