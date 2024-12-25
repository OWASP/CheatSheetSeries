# FROM python:latest
# WORKDIR /usr/src/app
# COPY . .

# EXPOSE 8000

# RUN apt-get update && apt-get install -y \
#     build-essential \
#     python3-pip \
#     && pip3 install mkdocs


# RUN make install-python-requirements
# RUN make generate-site
# ENTRYPOINT ["make", "serve"]

##
FROM python:latest
WORKDIR /usr/src/app
COPY . .

EXPOSE 8000

RUN apt-get update && apt-get install -y \
    build-essential \
    python3-pip \
    dos2unix \
    && pip3 install mkdocs

RUN dos2unix scripts/Generate_Site_mkDocs.sh
RUN make install-python-requirements
RUN make generate-site
ENTRYPOINT ["make", "serve"]