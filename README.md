[![Logo](https://resources.mend.io/mend-sig/logo/mend-dark-logo-horizontal.png)](https://www.mend.io/)  

[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/whitesource-ps/ws-sbom-generator/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-sbom-generator/actions/workflows/ci.yml)
[![Python 3.8](https://upload.wikimedia.org/wikipedia/commons/thumb/a/a5/Blue_Python_3.8_Shield_Badge.svg/76px-Blue_Python_3.8_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-380/)
[![GitHub release](https://img.shields.io/github/v/release/whitesource-ps/ws-sbom-generator)](https://github.com/whitesource-ps/ws-sbom-generator/releases/latest)  

# Mend SBOM Generator
This tool generates SBOM reports in either [SPDX](https://spdx.org) or [CycloneDX](https://cyclonedx.org/) formats, for specified projects.  

The tool can be executed either via [CLI](#sbom-generator-cli) or as a [Docker container](#sbom-generator-docker-container).  

The tool also supports including additional tag values that aren't necessarily configured in Mend, by referencing a designated `sbom_extra.json` file, with the following structure:  
**[TBC]**  
```json
{
  "namespace": "http://CreatorWebsite/pathToSpdx/DocumentName-UUID",
  "org_email": "org@domain.com",
  "person": "First Last",
  "person_email": "first.last@domain.com"
}
```

>Note: This tool utilizes a forked package of [spdx-tools](https://github.com/spdx/tools).  

<br/>

# SBOM Generator CLI

## Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu, RedHat
- **Windows (PowerShell):**	10, 2012, 2016

## Prerequisites
- Python 3.8+
- Mend user with admin permissions

>**Note:**  
>The specified user (`-u, --userKey`) must be associated with a group assigned as either Organization Administrators (for generating report for all projects in the organization) or Product Administrators. For the latter, `--tokenType` must be specified (see [Command-Line Arguments](#command-line-arguments)).  

## Installation

```
pip install ws-sbom-generator
```
> **Note:** Depending on whether the package was installed as a root user or not, you need to make sure the package installation location was added to the `$PATH` environment variable.  

## Usage

```shell
ws_sbom_generator --wsUrl $WS_WSS_URL --userKey $WS_USERKEY --token $WS_APIKEY --type $FORMAT --out $HOME/reports --extra resources/sbom_extra.json
```

### Command-Line Arguments

| Parameter | Type | Required | Description |
|:----------|:----:|:--------:|:------------|
| **&#x2011;h,&nbsp;&#x2011;&#x2011;help**         | switch | No  | Show help and exit |
| **&#x2011;a,&nbsp;&#x2011;&#x2011;wsUrl**        | string | Yes | Mend server URL |
| **&#x2011;u,&nbsp;&#x2011;&#x2011;userKey**      | string | Yes | Mend User Key |
| **&#x2011;k,&nbsp;&#x2011;&#x2011;token**        | string | Yes | Mend API Key or Product token |
| **&#x2011;y,&nbsp;&#x2011;&#x2011;tokenType**    | string | No* | [`organization`\|`product`*] (default: `organization`) |
| **&#x2011;t,&nbsp;&#x2011;&#x2011;type**         | string | No* | Report format [`json`\|`tv`\|`rdf`\|`xml`\|`yaml`\|`cdx`\*\|`all`\*] (default: `tv`) |
| **&#x2011;s,&nbsp;&#x2011;&#x2011;scope**        | string | No  | Product or Project token to generate the report(s) for. When specifying a Product token, one report will be generated for each project under that product. If not specified, one report will be generated for each project in your organization. |
| **&#x2011;o,&nbsp;&#x2011;&#x2011;out**          | string | No  | Output directory (default: `$PWD`) |
| **&#x2011;on,&nbsp;&#x2011;&#x2011;outfile**     | string | No* | Output file name* (default: `Mend {PROJECT_NAME} SBOM report-{FORMAT}`) |
| **&#x2011;lt,&nbsp;&#x2011;&#x2011;licensetext** | bool   | No  | **Include full license text for all libraries, not just the ones that aren't in the SPDX list (default: `False`) [TBC]** |
| **&#x2011;th,&nbsp;&#x2011;&#x2011;threads**     | int    | No  | Number of threads to run in parallel for report generation (default: `10`) |
| **&#x2011;e,&nbsp;&#x2011;&#x2011;extra**        | string | No* | Additional SBOM configuration (default: `$PWD/resources/sbom_extra.json` |

>**Notes:**  
>\* Token type (`--tokenType product`) is required in case the specified `userKey` is associated with a group with Product Administrators permissions.  
>\* Report type (`--type`) `cdx` will generate a JSON file in [CycloneDX v1.4](https://cyclonedx.org/docs/1.4/json/) format.  
>\* Report type (`--type`) `all` will generate one file in each format for each specified project.  
>\* Output file name (`--outfile`) is only supported for a single project scope.  
>\* **The tool accepts additional values which are unknown to Mend (`-e sbom_extra.json`).  [TBC]**  

### Execution Examples

**Create tag value report on a specific project [TBC]**  
```shell
ws_sbom_generator --wsUrl $WS_WSS_URL --userKey $WS_USERKEY --token $WS_APIKEY --scope $WS_PROJECTTOKEN --out $HOME/reports --extra sbom_extra.json
```

**Create tag value report on all projects of product [TBC]**  
```shell
ws_sbom_generator --wsUrl $WS_WSS_URL --userKey $WS_USERKEY --token $WS_APIKEY --scope $WS_PRODUCTTOKEN --out $HOME/reports --extra sbom_extra.json
```

Generating `json` formatted SBOM report for all projects in the organization  
```shell
ws_sbom_generator --wsUrl $WS_WSS_URL --userKey $WS_USERKEY --token $WS_APIKEY --type json --out $HOME/reports
```

Generating `json` formatted SBOM report for all projects in the organization, including full license text  
```shell
ws_sbom_generator --wsUrl $WS_WSS_URL --userKey $WS_USERKEY --token $WS_APIKEY --type json --out $HOME/reports --licensetext True
```

Generating `xml` formatted SBOM report for a single project (executed by a product administrator)  
```shell
ws_sbom_generator --wsUrl $WS_WSS_URL --userKey $WS_USERKEY --token $WS_PRODUCTTOKEN --tokenType product --scope $WS_PROJECTTOKEN --type xml --out $HOME/reports --extra sbom_extra.json
```

Generating `json` formatted SBOM report for a single project, specifying file name  
```shell
ws_sbom_generator --wsUrl $WS_WSS_URL --userKey $WS_USERKEY --token $WS_APIKEY --scope $WS_PROJECTTOKEN --type json --out $HOME/reports --extra sbom_extra.json --outfile my-project-sbom.json
```

<br/>

# SBOM Generator Docker Container

## Supported Operating Systems
- **Linux:**	CentOS, Debian, Ubuntu, RedHat
- **Windows:**	10, 2012, 2016

## Prerequisites
- Docker **version [TBC]**
- Mend user with admin permissions

>**Note:**  
>The specified user (`-u, --userKey`) must be associated with a group assigned as either Organization Administrators (for generating report for all projects in the organization) or Product Administrators. For the latter, `--tokenType` must be specified (see [Command-Line Arguments](#command-line-arguments)).  

## Installation

```shell
docker pull whitesourcetools/ws-sbom-generator:latest 
 ```

## Usage

```shell
docker run --name ws-sbom-generator \ 
  -v $HOME/ws-sbom-generator/resources:/opt/ws-sbom-generator/sbom-generator/resources \ 
  -v $HOME/reports:/opt/ws-sbom-generator/sbom-generator/output \
  -e WS_URL=$WS_WSS_URL \
  -e WS_USER_KEY=$WS_USERKEY \ 
  -e WS_TOKEN=$WS_APIKEY \
  -e WS_REPORT_TYPE=<REPORT_TYPE> \
  whitesourcetools/ws-sbom-generator 
```

### Execution Examples

Running as organization administrator, generating `json` formatted SBOM reports for all projects, default extra args  

```shell
docker run --name ws-sbom-generator \  
  -v $HOME/ws-sbom-generator/resources:/opt/ws-sbom-generator/sbom_generator/resources \ 
  -v $HOME/reports:/opt/ws-sbom-generator/sbom_generator/output \
  -e WS_URL=$WS_WSS_URL \
  -e WS_USER_KEY=$WS_USERKEY \ 
  -e WS_TOKEN=$WS_APIKEY \
  -e WS_REPORT_TYPE=json
  whitesourcetools/ws-sbom-generator
```

Running as organization administrator, generating `tv` formatted SBOM report for a single project, default extra args  

```shell
docker run --name ws-sbom-generator \  
  -v $HOME/ws-sbom-generator/resources:/opt/ws-sbom-generator/sbom_generator/resources \
  -v $HOME/reports:/opt/ws-sbom-generator/sbom_generator/output \
  -e WS_URL=$WS_WSS_URL \
  -e WS_USER_KEY=$WS_USERKEY \
  -e WS_TOKEN=$WS_APIKEY \
  -e WS_SCOPE_TOKEN=<WS_PROJECT_TOKEN> \
  whitesourcetools/ws-sbom-generator
```

Running as a product administrator, generating `rdf` formatted SBOM report for a single project, default extra args  

```shell
docker run --name ws-sbom-generator \  
  -v $HOME/ws-sbom-generator/resources:/opt/ws-sbom-generator/sbom_generator/resources \
  -v $HOME/reports:/opt/ws-sbom-generator/sbom_generator/output \
  -e WS_URL=$WS_WSS_URL \
  -e WS_USER_KEY=$WS_USERKEY \
  -e WS_TOKEN=$WS_PRODUCTTOKEN \
  -e WS_TOKEN_TYPE=product
  -e WS_SCOPE_TOKEN=$WS_PROJECTTOKEN \
  whitesourcetools/ws-sbom-generator
```
