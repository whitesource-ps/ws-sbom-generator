FROM python:3.9-slim-buster

ARG version
ENV SBOM_GENERATOR_WHL="ws_sbom_generator-$version-py3-none-any.whl"

COPY dist/$SBOM_GENERATOR_WHL ./

RUN python3 -m pip install --upgrade pip
RUN pip3 install $SBOM_GENERATOR_WHL
HEALTHCHECK NONE

RUN chmod 777 /opt/ws-sbom-generator/sbom_generator/output
RUN useradd sbom
USER sbom

VOLUME /opt/ws-sbom-generator/sbom_generator/resources
VOLUME /opt/ws-sbom-generator/sbom_generator/output

#HEALTHCHECK CMD ws_sbom_generator -o /opt/ws-sbom-generator/sbom_generator/output -e /opt/ws-sbom-generator/sbom_generator/resources/creation_info.json
CMD ws_sbom_generator -o /opt/ws-sbom-generator/sbom_generator/output -e /opt/ws-sbom-generator/sbom_generator/resources/creation_info.json
