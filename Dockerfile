FROM python:3.9-slim-buster

VOLUME /opt/ws-sbom-generator/sbom_generator/resources
VOLUME /opt/ws-sbom-generator/sbom_generator/output

COPY dist/ws_sbom_generator-0.3-py3-none-any.whl spdx_tools-0.7.0a3_ws-py3-none-any.whl ./

RUN python3 -m pip install --upgrade pip
RUN pip3 install spdx_tools-0.7.0a3_ws-py3-none-any.whl
RUN pip3 install ws_sbom_generator-0.3-py3-none-any.whl

CMD sbom_generator -o /opt/ws-sbom-generator/sbom_generator/output -e /opt/ws-sbom-generator/sbom_generator/resources/sbom_extra.json

