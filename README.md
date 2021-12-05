![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)  
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/whitesource-ps/ws-sbom-generator/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-sbom-generator/actions/workflows/ci.yml)
[![Python 3.6](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8c/Blue_Python_3.6%2B_Shield_Badge.svg/86px-Blue_Python_3.6%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-360/)
[![GitHub release](https://img.shields.io/github/v/release/whitesource-ps/ws-sbom-generator)](https://github.com/whitesource-ps/ws-sbom-generator/releases/latest)  

# WS SBOM Generator in SPDX format 
CLI Tool and a Docker image to generate SBOM report in [SPDX format](https://spdx.org).
* The tool can generate reports on the following scopes (defined with: **-s/WS_SCOPE**):
  * Project token - the tool will generate report on a specific project.
  * Product token - teh tool will generate report on all the projects within the product.
  * No Token specified - the tool will generate report on all the projects within the organization.
* The tool utilizes a forked package of [spdx-tools](https://github.com/spdx/tools).
* The tool accepts additional values which are unknown to WhiteSource via `sbom_extra.json`.
* If URL is not stated (defined with: **-a/WS_URL**), the tool will access **saas**.
* If report type is not stated (defined with: **-t/WS_REPORT_TYPE**) the tool will generate a report in **tag-value** format.  
  * Supported file formats: json, tv, rdf, xml and yaml.
## Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu, RedHat
- **Windows (PowerShell):**	10, 2012, 2016
## Prerequisites
Python 3.7+
## Deployment and Usage
## From PyPi (simplest)
### Install as a PyPi package:
Execute: `pip install ws-sbom-generator`
## Usage:
       ```shell
       usage: ws_sbom_generator.py [-h] -u WS_USER_KEY -k WS_TOKEN [-s SCOPE_TOKEN] [-a WS_URL] [-t {json,tv,rdf,xml,yaml,all}] [-e EXTRA] [-o OUT_DIR]
    
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
         -t {json,tv,rdf,xml,yaml,all}, --type {json,tv,rdf,xml,yaml,all}
                               Output type
         -e EXTRA, --extra EXTRA
                               Extra configuration of SBOM
         -o OUT_DIR, --out OUT_DIR
                               Output directory
       ```

## Examples:
```shell
# Create tag value report on a specific project 
ws_sbom_generator -u <WS_USER_KEY> -k <WS_ORG_TOKEN> -a app-eu -s <WS_PROJECT_TOKEN> -e /<path/to>/sbom_extra.json -o </path/reports>
# Creating JSON report on all projects within the product 
ws_sbom_generator -u <WS_USER_KEY> -k <WS_ORG_TOKEN> -a https://di.whitesourcesoftware.com -s <WS_PRODUCT_TOKEN> -t json -e /<path/to>/sbom_extra.json -o </path/reports>
```

## Docker container
### Installation:
```shell
docker pull whitesourcetools/ws-sbom-generator:latest 
 ```
### Execution:
```shell
docker run --name ws-sbom-generator \ 
  -v /<EXTRA_CONF_DIR>:/opt/ws-sbom-generator/sbom-generator/resources \ 
  -v /<REPORT_OUTPUT_DIR>:/opt/ws-sbom-generator/sbom-generator/output \
  -e WS_USER_KEY=<USER_KEY> \ 
  -e WS_TOKEN=<ORG_WS_TOKEN> \
  -e WS_SCOPE=<WS_SCOPE> \
  -e WS_URL=<WS_URL> \
  -e WS_TYPE=<WS_TYPE> \
  whitesourcetools/ws-sbom-generator 
````
## GitHub Package
### Installation 
1. Download and unzip the tool.
2. Install the requirements: `pip install -r sbom_generator/requirements.txt`
3. Edit the file **sbom_extra.json** with the appropriate values to complete the report:

## Execution
Same as the PyPi package but prefix the script with `python sbom_report.py...`