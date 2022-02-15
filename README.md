![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)  
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/whitesource-ps/ws-sbom-generator/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-sbom-generator/actions/workflows/ci.yml)
[![Python 3.6](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8c/Blue_Python_3.6%2B_Shield_Badge.svg/86px-Blue_Python_3.6%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-360/)
[![GitHub release](https://img.shields.io/github/v/release/whitesource-ps/ws-sbom-generator)](https://github.com/whitesource-ps/ws-sbom-generator/releases/latest)  

# WS SBOM Generator in SPDX format
CLI Tool and a Docker image to generate SBOM report in [SPDX format](https://spdx.org).
* The tool can generate reports on the following scopes (defined with: **-s/WS_SCOPE_TOKEN**):
  * Specific Project token - the tool will generate a report on a specific project (user key and token of organization admin or of Product Admin).
  * No Token specified - the tool will generate a report on all the projects within the organization (user key and token of organization admin).
* To run the tool with product-level permissions pass `-y product` along with the product token (-k) and user key with permission on this product (-u).
* The tool utilizes a forked package of [spdx-tools](https://github.com/spdx/tools).
* The tool accepts additional values which are unknown to WhiteSource (`-e sbom_extra.json`).
* If URL is not stated (defined with: **-a/WS_URL**), the tool will access **saas**.
* If report type is not stated (defined with: **-t/WS_REPORT_TYPE**) the tool will generate a report in **tag-value** format.
  * Supported file formats: json, tv, rdf, xml and yaml.
## Permissions to run the tool
The user key used (**-u**) must be a member of one of the following groups:
- Organization Administrator - For dynamically obtaining the organization name and generating reports on all projects (in all products).
- Product Administrator (**-y** must be passed ) - For running on a specific project or all projects within the product.
## Prerequisites
Python 3.7+
## Deployment and Usage
## From PyPi (simplest)
### Install as a PyPi package:
Execute: `pip install ws-sbom-generator`
## Usage:
```shell
 usage: sbom_generator.py [-h] [-u WS_USER_KEY] [-k WS_TOKEN] [-s SCOPE_TOKEN]
                         [-y {product,organization}] [-a WS_URL]
                         [-t {json,tv,rdf,xml,yaml,all}] [-e EXTRA]
                         [-o OUT_DIR]

Utility to create SBOM from WhiteSource data

optional arguments:
  -h, --help            show this help message and exit
  -u WS_USER_KEY, --userKey
                  WS User Key
  -k WS_TOKEN, --token 
                  WS Org Token (API Key) or WS Product Token
  -s WS_SCOPE_TOKEN, --scope 
                  Scope token of SBOM report to generate
  -y WS_TOKEN_TYPE, --tokenType {product, organization}
                  Optional WS Token type to be stated in case WS Org Token
                  does not have organization level permissions
  -a WS_URL, --wsUrl {saas, app, app-eu, saas-eu, your_url}
                  WS URL 
  -t WS_REPORT_TYPE, --type {json,tv,rdf,xml,yaml,all}
                  Report type
  -e EXTRA, --extra 
                  Extra configuration of SBOM
  -o OUT_DIR, --out 
                  Output directory
```
## Examples:
```shell
# Create tag value report on a specific project 
ws_sbom_generator -u <WS_USER_KEY> -k <WS_ORG_TOKEN> -a app-eu -s <WS_PROJECT_TOKEN> -e /<path/to>/sbom_extra.json -o </path/reports>
# Creating JSON report on all projects of organization
ws_sbom_generator -u <WS_USER_KEY> -k <WS_ORG_TOKEN> -a https://di.whitesourcesoftware.com -t json -o </path/reports>
# Creating XML report on a project with product permissions (SAAS organization)   
ws_sbom_generator -u <WS_USER_KEY> -y product -k <WS_PRODUCT_TOKEN> -s <WS_PROJECT_TOKEN> -t xml -e /<path/to>/sbom_extra.json -o </path/reports>

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
  -e WS_TOKEN=<WS_ORG_TOKEN> \
  -e WS_URL=<WS_URL> \
  -e WS_REPORT_TYPE=<REPORT_TYPE> \
  whitesourcetools/ws-sbom-generator 
````

## Examples (Docker):
```shell
# Run tool as Org Administrator on all projects, default extra args and output in JSON format.
docker run --name ws-sbom-generator \  
  -v /<EXTRA_CONF_DIR>:/opt/ws-sbom-generator/sbom_generator/resources \ 
  -v /<REPORT_OUTPUT_DIR>:/opt/ws-sbom-generator/sbom_generator/output \
  -e WS_USER_KEY=<USER_KEY> \ 
  -e WS_TOKEN=<WS_ORG_TOKEN> \
  -e WS_URL=saas \
  -e WS_REPORT_TYPE=json
  whitesourcetools/ws-sbom-generator
  
# Run tool as Org Administrator on specific project, default extra args and output in tv format.
docker run --name ws-sbom-generator \  
  -v /<EXTRA_CONF_DIR>:/opt/ws-sbom-generator/sbom_generator/resources \
  -v /<REPORT_OUTPUT_DIR>:/opt/ws-sbom-generator/sbom_generator/output \
  -e WS_USER_KEY=<USER_KEY> \ 
  -e WS_TOKEN=<WS_ORG_TOKEN> \
  -e WS_SCOPE_TOKEN=<WS_PROJECT_TOKEN> \
  -e WS_URL=https://di.whitesourcesoftware.com \
  whitesourcetools/ws-sbom-generator

# Run tool as Product Administrator on specific project, default extra args and output in rdf format.
docker run --name ws-sbom-generator \  
  -v /<EXTRA_CONF_DIR>:/opt/ws-sbom-generator/sbom_generator/resources \
  -v /<REPORT_OUTPUT_DIR>:/opt/ws-sbom-generator/sbom_generator/output \
  -e WS_USER_KEY=<USER_KEY> \ 
  -e WS_TOKEN=<WS_PROD_TOKEN> \
  -e WS_SCOPE_TOKEN=<WS_PROJECT_TOKEN> \
  -e WS_URL=app-eu \
  -e WS_TOKEN_TYPE=product
  whitesourcetools/ws-sbom-generator
````

## Sample extra configuration (--extra/-e switch)
```json
{
  "namespace": "http://CreatorWebsite/pathToSpdx/DocumentName-UUID",
  "org_email": "org@email.address",
  "person": "person name",
  "person_email": "person@email.address"
}
```
