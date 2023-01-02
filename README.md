[![Logo](https://resources.mend.io/mend-sig/logo/mend-dark-logo-horizontal.png)](https://www.mend.io/)
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/whitesource-ps/ws-sbom-generator/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-sbom-generator/actions/workflows/ci.yml)
[![Python 3.8](https://upload.wikimedia.org/wikipedia/commons/thumb/a/a5/Blue_Python_3.8_Shield_Badge.svg/76px-Blue_Python_3.8_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-380/)
[![GitHub release](https://img.shields.io/github/v/release/whitesource-ps/ws-sbom-generator)](https://github.com/whitesource-ps/ws-sbom-generator/releases/latest)  

# Mend SBOM Generator in SPDX or CycloneDX format
CLI Tool and a Docker image to generate SBOM report in [SPDX format](https://spdx.org) or in [CycloneDX format](https://cyclonedx.org/).
* The tool can generate reports on the following scopes (defined with: **-s/WS_SCOPE_TOKEN**):
  * Specific Project token - the tool will generate a report on a specific project (user key and token of organization admin or of Product Admin).
  * No Token specified - the tool will generate a report on all the projects within the organization (user key and token of organization admin).
* To run the tool with product-level permissions pass `-y product` along with the product token (-k) and user key with permission on this product (-u).
* The tool utilizes a forked package of [spdx-tools](https://github.com/spdx/tools).

## Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu, RedHat
- **Windows (PowerShell):**	10, 2012, 2016

## Prerequisites
Python 3.8+

## Permissions to run the tool
The user key used (**-u**) must be a member of one of the following groups:
- Organization Administrator - For dynamically obtaining the organization name and generating reports on all projects (in all products).
- Product Administrator (**-y** must be passed ) - For running on a specific project or all projects within the product.

## Installation and Execution by pulling package from PyPi:
1. Execute pip install `pip install ws-sbom-generator`
   * Note: If installing packages as a non-root be sure to include the path to the executables within the Operating System paths.

### Command-Line Arguments

| Parameter                                        |  Type  | Required | Description                                                                                        |
|:-------------------------------------------------|:------:|:--------:|:---------------------------------------------------------------------------------------------------|
| **&#x2011;h,&nbsp;&#x2011;&#x2011;help**         | switch |    No    | Show help and exit                                                                                 |
| **&#x2011;u,&nbsp;&#x2011;&#x2011;userKey**      | string |   Yes    | Mend User Key                                                                                      |
| **&#x2011;k,&nbsp;&#x2011;&#x2011;token**        | string |   Yes    | Mend API Key                                                                                       |
| **&#x2011;y,&nbsp;&#x2011;&#x2011;tokenType**    | string |    No    | To be stated in case Mend Org Token does not have organization level permissions                   |
| **&#x2011;e,&nbsp;&#x2011;&#x2011;extra**        | string |   No*    | Extra configuration of SBOM (Default : `$PWD/resources/sbom_extra.json`                            |
| **&#x2011;s,&nbsp;&#x2011;&#x2011;scope**        | string |    No    | Scope token of SBOM report to generate                                                             |
| **&#x2011;a,&nbsp;&#x2011;&#x2011;wsUrl**        | string |    No    | Mend server URL (Available values: **saas, app, app-eu, saas-eu, your_url**). Default value : saas |
| **&#x2011;t,&nbsp;&#x2011;&#x2011;type**         | string |   No*    | Report type (Available values: **json,tv,rdf,xml,yaml,cdx,all**). Default value: tv                |
| **&#x2011;o,&nbsp;&#x2011;&#x2011;out**          | string |    No    | Output directory (Default: `$PWD`)                                                                 |
| **&#x2011;on,&nbsp;&#x2011;&#x2011;outfile**     | string |   No*    | Name of output file                                                                                |
| **&#x2011;lt,&nbsp;&#x2011;&#x2011;licensetext** |  bool  |   No*    | Include license text for each package (default: `False`)                                           |
| **&#x2011;th,&nbsp;&#x2011;&#x2011;threads**     | string |    No    | Number of parallel threads for creation output reports (default: `10`)                             |
   * Note: 
     * The tool accepts additional values which are unknown to Mend (`-e sbom_extra.json`)
     * **cdx** type : The report will be created in CycloneDX format v1.4 (JSON type of output file)
     * Name of output file can be used just for single report (Project layer)
     * In case **True** : The report will include a full license text for each library, not only for libraries that are not in the SPDX list

### Execution Examples
   * Run report: `ws_sbom_generator -u <WS_USERKEY> -k <WS_TOKEN> -a <WS_URL> -t <WS_REPORTTYPE> {json,tv,rdf,xml,yaml,all} -e <EXTRA> -o <OUT_DIR>`
   * Note: If installing packages as a non-root be sure to include the path to the executables within the Operating System paths.

Create tag value report on a specific project  
`ws_sbom_generator -u <WS_USER_KEY> -k <WS_ORG_TOKEN> -a app-eu -s <WS_PROJECT_TOKEN> -e /<path/to>/sbom_extra.json -o </path/reports>`
---
Create tag value report on all projects of product  
`ws_sbom_generator -u <WS_USER_KEY> -k <WS_ORG_TOKEN> -a app-eu -s <WS_PRODUCT_TOKEN> -e /<path/to>/sbom_extra.json -o </path/reports>`
---
Creating JSON report on all projects of organization  
`ws_sbom_generator -u <WS_USER_KEY> -k <WS_ORG_TOKEN> -a https://di.whitesourcesoftware.com -t json -o </path/reports>`
---
Creating XML report on a project with a user which only has product permissions (SAAS organization)   
`ws_sbom_generator -u <WS_USER_KEY> -y product -k <WS_PRODUCT_TOKEN> -s <WS_PROJECT_TOKEN> -t xml -e /<path/to>/sbom_extra.json -o </path/reports>`
---
Creating JSON report for specific project with customized name  
`ws_sbom_generator -u <WS_USER_KEY> -k <WS_ORG_TOKEN> -a app-eu -s <WS_PROJECT_TOKEN> -e /<path/to>/sbom_extra.json -o </path/reports> -on <filename>`
---
Creating JSON report on all projects of organization with Full License Text option  
`ws_sbom_generator -u <WS_USER_KEY> -k <WS_ORG_TOKEN> -a https://di.whitesourcesoftware.com -t json -o </path/reports> -lt True`

<br/>

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
