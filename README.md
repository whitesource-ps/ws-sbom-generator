[![Logo](https://resources.mend.io/mend-sig/logo/mend-dark-logo-horizontal.png)](https://www.mend.io/)  

[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/whitesource-ps/ws-sbom-generator/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-sbom-generator/actions/workflows/ci.yml)
[![Python 3.8](https://upload.wikimedia.org/wikipedia/commons/thumb/a/a5/Blue_Python_3.8_Shield_Badge.svg/76px-Blue_Python_3.8_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-380/)
[![GitHub release](https://img.shields.io/github/v/release/whitesource-ps/ws-sbom-generator)](https://github.com/whitesource-ps/ws-sbom-generator/releases/latest)  

# Mend SBOM Generator
This tool generates SBOM reports in either [SPDX](https://spdx.org) or [CycloneDX](https://cyclonedx.org/) formats, for specified projects.  

The tool can be executed either via [CLI](#sbom-generator-cli) or as a [Docker container](#sbom-generator-docker-container).  

>**Note:** This tool utilizes a forked package of [spdx-tools](https://github.com/spdx/tools).  

<br/>

# SBOM Generator CLI

## Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu, RedHat
- **Windows (PowerShell):**	10, 2012, 2016

## Prerequisites
- Python 3.8 or later
- Mend user with admin permissions

>**Note:**  
>The specified user (`--userKey`) must be associated with a group assigned as either Organization Administrators (for generating report for all projects in the organization) or Product Administrators.  

## Installation
1. Install the PyPI package `ws-sbom-generator`
    ```
    pip install ws-sbom-generator
    ```
    > **Note:** Depending on whether the package was installed as a root user or not, you need to make sure the package installation location was added to the `$PATH` environment variable.  

1. Update the [creation info](https://spdx.github.io/spdx-spec/v2-draft/document-creation-information/#68-creator-field) as needed in the [resource/creation_info.json](https://github.com/whitesource-ps/ws-sbom-generator/blob/master/ws_sbom_generator/resources/creation_info.json) file:
    ```json
    {
      "namespace": "http://CreatorWebsite/pathToSpdx/DocumentName-UUID",
      "org_email": "org@domain.com",
      "person": "First Last",
      "person_email": "first.last@domain.com"
    }
    ```

## Usage

```shell
ws_sbom_generator --wsUrl $WS_WSS_URL --userKey $WS_USERKEY --token $WS_APIKEY --type $FORMAT --out $HOME/reports --extra resources/creation_info.json
```

### Command-Line Arguments

| Parameter                                        | Type | Required | Description                                                                                                                                                                                                              |
|:-------------------------------------------------|:----:|:--------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **&#x2011;&#x2011;help**                         | switch |    No    | Show help and exit                                                                                                                                                                                                       |
| **&#x2011;&#x2011;mendUrl**                      | string |   Yes    | Mend server URL                                                                                                                                                                                                          |
| **&#x2011;&#x2011;userKey**      | string |   Yes    | Mend User Key                                                                                                                                                                                                            |
| **&#x2011;&#x2011;apiKey**                       | string |   Yes    | Mend API Key                                                                                                                                                                                                             |
| **&#x2011;&#x2011;type**                         | string |   No*    | Report format [`json` `tv` `rdf` `xml` `yaml` `cdx` `all`] (default: `tv`)                                                                                                                                               | 
| **&#x2011;&#x2011;projectToken** | string |    No    | Project token to generate the report for.                                                                                                                                                                                |
| **&#x2011;&#x2011;productToken** | string |    No    | Product token to generate the report for. When specifying a Product token, one report will be generated for each project under that product.                                                                             |
| **&#x2011;&#x2011;out**          | string |    No    | Output directory (default: `$PWD`)                                                                                                                                                                                       |
| **&#x2011;&#x2011;outfile**     | string |   No*    | Output file name* (default: `Mend {PROJECT_NAME} SBOM report-{FORMAT}`)                                                                                                                                                  |
| **&#x2011;&#x2011;licensetext** | bool   |   No*    | Include full license text for all libraries (default: `False`)                                                                                                                                                          |
| **&#x2011;&#x2011;threads**     | int    |    No    | Number of threads to run in parallel for report generation (default: `10`)                                                                                                                                               |
| **&#x2011;&#x2011;extra**        | string |   No*    | Path to a json file containing the [creation info](https://spdx.github.io/spdx-spec/v2-draft/document-creation-information/#68-creator-field) to be included in the report (default: `$PWD/resources/creation_info.json` |

>**Notes:**  
>\* Report type (`--type`) `cdx` will generate a JSON file in [CycloneDX v1.4](https://cyclonedx.org/docs/1.4/json/) format.  
>\* Report type (`--type`) `all` will generate one file in each format for each specified project.  
>\* Output file name (`--outfile`) is only supported for a single project scope.  
>\* Full license texts will be taken by default from the [SPDX License List](https://spdx.org/licenses/). If a given license does not exist there, the tool will attempt to take it from Mend's database.  
>\* By default, the tool will use the placeholders in the [resource/creation_info.json](https://github.com/whitesource-ps/ws-sbom-generator/blob/master/ws_sbom_generator/resources/creation_info.json) file.  

### Execution Examples

Generating `tv` formatted SBOM report for a specific project  
```shell
ws_sbom_generator --mendUrl $WS_WSS_URL --userKey $WS_USERKEY --apiKey $WS_APIKEY --projectToken $WS_PROJECTTOKEN --out $HOME/reports --extra creation_info.json
```

Generating `tv` formatted SBOM report for all projects of a specified product  
```shell
ws_sbom_generator --mendUrl $WS_WSS_URL --userKey $WS_USERKEY --apiKey $WS_APIKEY --projectToken $WS_PRODUCTTOKEN --out $HOME/reports --extra creation_info.json
```

Generating `json` formatted SBOM report for all projects in the organization  
```shell
ws_sbom_generator --mendUrl $WS_WSS_URL --userKey $WS_USERKEY --apiKey $WS_APIKEY --type json --out $HOME/reports
```

Generating `json` formatted SBOM report for all projects in the organization, including full license text  
```shell
ws_sbom_generator --mendUrl $WS_WSS_URL --userKey $WS_USERKEY --apiKey $WS_APIKEY --type json --out $HOME/reports --licensetext True
```

Generating `xml` formatted SBOM report for a single project (executed by a product administrator)  
```shell
ws_sbom_generator --mendUrl $WS_WSS_URL --userKey $WS_USERKEY --apiKey $WS_APIKEY --projectToken $WS_PROJECTTOKEN --type xml --out $HOME/reports --extra creation_info.json
```

Generating `json` formatted SBOM report for a single project, specifying file name  
```shell
ws_sbom_generator --mendUrl $WS_WSS_URL --userKey $WS_USERKEY --apiKey $WS_APIKEY --scope $WS_PROJECTTOKEN --type json --out $HOME/reports --extra creation_info.json --outfile my-project-sbom.json

```

<br/>

# SBOM Generator Docker Container

## Supported Operating Systems
- **Linux:**	CentOS, Debian, Ubuntu, RedHat
- **Windows:**	10, 2012, 2016

## Prerequisites
- Docker version 20 or later
- Mend user with admin permissions

>**Note:**  
>The specified user (`--userKey`) must be associated with a group assigned as either Organization Administrators (for generating report for all projects in the organization) or Product Administrators.  

## Installation

```shell
docker pull whitesourcetools/ws-sbom-generator:latest 
 ```

## Usage

```shell
docker run --name ws-sbom-generator \ 
  -v /tmp:/tmp \ 
  -v /tmp:/tmp \
  -e WS_URL=$WS_WSS_URL \
  -e WS_USER_KEY=$WS_USERKEY \ 
  -e WS_TOKEN=$WS_APIKEY \
  -e WS_REPORTTYPE=<REPORT_TYPE> \
  whitesourcetools/ws-sbom-generator 
```

### Execution Examples

Running as organization administrator, generating `json` formatted SBOM reports for all projects, default extra args  

```shell
docker run --name ws-sbom-generator \  
  -v /tmp:/tmp \ 
  -v /tmp:/tmp \
  -e WS_URL=$WS_WSS_URL \
  -e WS_USER_KEY=$WS_USERKEY \ 
  -e WS_TOKEN=$WS_APIKEY \
  -e WS_REPORTTYPE=json
  whitesourcetools/ws-sbom-generator
```

Running as organization administrator, generating `tv` formatted SBOM report for a single project, default extra args  

```shell
docker run --name ws-sbom-generator \  
  -v /tmp:/tmp \
  -v /tmp:/tmp \
  -e WS_URL=$WS_WSS_URL \
  -e WS_USER_KEY=$WS_USERKEY \
  -e WS_TOKEN=$WS_APIKEY \
  -e WS_SCOPE_TOKEN=<WS_PROJECTTOKEN> \
  whitesourcetools/ws-sbom-generator
```

Running as a product administrator, generating `rdf` formatted SBOM report for a single project, default extra args  

```shell
docker run --name ws-sbom-generator \  
  -v /tmp:/tmp \
  -v /tmp:/tmp \
  -e WS_URL=$WS_WSS_URL \
  -e WS_USER_KEY=$WS_USERKEY \
  -e WS_TOKEN=$WS_PRODUCTTOKEN \
  -e WS_TOKEN_TYPE=product
  -e WS_SCOPE_TOKEN=$WS_PROJECTTOKEN \
  whitesourcetools/ws-sbom-generator
```
