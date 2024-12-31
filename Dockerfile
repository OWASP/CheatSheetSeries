FROM python:latest
WORKDIR /usr/src/app
COPY . .

EXPOSE 8000

RUN make install-python-requirements
RUN make generate-site
ENTRYPOINT ["make", "serve"]