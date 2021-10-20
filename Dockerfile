FROM python:3.9-slim-buster

COPY . /opt/ws-sbom-generator

RUN python3 -m pip install --upgrade pip
WORKDIR /opt/ws-sbom-generator
RUN pip3 install -r requirements.txt
RUN pip3 install spdx_tools-0.7.0a3-py3-none-any.whl

ENTRYPOINT ["python3", "/opt/ws-sbom-generator/sbom_generator/sbom_generator.py"]
CMD ["-h"]