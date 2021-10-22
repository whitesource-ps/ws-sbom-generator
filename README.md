![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)  
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/whitesource-ps/ws-sbom-report/actions/workflows/ci-master.yml/badge.svg)](https://github.com/whitesource-ps/ws-sbom-report/actions/workflows/ci-master.yml)
[![Python 3.6](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8c/Blue_Python_3.6%2B_Shield_Badge.svg/86px-Blue_Python_3.6%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-360/)
[![GitHub release](https://img.shields.io/github/v/release/whitesource-ps/ws-sbom-spdx-report)](https://github.com/whitesource-ps/ws-sbom-spdx-report/releases/latest)  

# WS SBOM Report Generator in SPDX format 
CLI Tool to generate SBOM report on chosen scope in [SPDX format](https://spdx.org).
* The tool utilizes [spdx-tools](https://github.com/spdx/tools).
* The tool can be executed on WS Product or Project scope.
* The tool accepts additional values which are unknown to WS via `sbom_extra.json`.
* If not stated, the tool will access SAAS.
* If not stated, the tool will produce report in JSON format.

## Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu, RedHat
- **Windows (PowerShell):**	10, 2012, 2016

## Prerequisites
Python 3.6+ 

## Installation
1. Download and unzip the tool.
2. Install requirements: `pip install -r sbom_report/requirements.txt`
3. Edit the file **sbom_extra.json** with the appropriate values to complete the report:

## Usage
```
sbom_report.py [-h] -u WS_USER_KEY -k WS_TOKEN [-s SCOPE_TOKEN]
                      [-a WS_URL] [-t {tv,json,xml,rdf,yaml}] [-e EXTRA]
                      [-o OUT_DIR]

Utility to create SBOM from WhiteSource data

optional arguments:
  -h, --help            show this help message and exit
  -u WS_USER_KEY, --userKey WS_USER_KEY
                        WS User Key
  -k WS_TOKEN, --token WS_TOKEN
                        WS Organization Key
  -s SCOPE_TOKEN, --scope SCOPE_TOKEN
                        Scope token of SBOM report to generate
  -a WS_URL, --wsUrl WS_URL
                        WS URL
  -t {tv,json,xml,rdf,yaml}, --type {tv,json,xml,rdf,yaml}
                        Output type
  -e EXTRA, --extra EXTRA
                        Extra configuration of SBOM
  -o OUT_DIR, --out OUT_DIR
                        Output directory
```

## Execution
Execution instructions:  
```
python sbom_report.py -u <USER_KEY> -k <TOKEN> -s <SCOPE_TOKEN>
```
