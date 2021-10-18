import json
import logging
import os
import argparse
import sys

import spdx.document
from spdx import version, creationinfo
from spdx.checksum import Algorithm
from spdx.creationinfo import CreationInfo
from spdx.document import Document, License
from spdx.package import Package
from spdx.relationship import Relationship, RelationshipType
from spdx.utils import SPDXNone, UnKnown, NoAssert
from ws_sdk import ws_constants, WS, ws_utilities

logging.basicConfig(level=logging.DEBUG if os.environ.get("DEBUG") else logging.INFO,
                    handlers=[logging.StreamHandler(stream=sys.stdout)],
                    format='%(levelname)s %(asctime)s %(thread)d: %(message)s',
                    datefmt='%y-%m-%d %H:%M:%S')

ARCHIVE_SUFFICES = (".jar", ".zip", ".tar", ".gz", ".tgz", ".gem", ".whl")
BIN_SUFFICES = (".dll", ".so", ".exe")
SOURCE_SUFFICES = ("JavaScript")
VERSION = "0.3"
args = None


def create_sbom_doc() -> spdx.document.Document:
    init()
    scope = args.ws_conn.get_scope_by_token(args.scope_token)
    logging.info(f"Creating SBOM Document from WhiteSource {scope['type']} {scope['name']}")
    scope_name = args.ws_conn.get_scope_name_by_token(args.scope_token)
    namespace = args.extra_conf.get('namespace', 'http://[CreatorWebsite]/[pathToSpdx]/[DocumentName]-[UUID]')
    doc, doc_spdx_id = create_document(scope_name, namespace)

    doc.creation_info = create_creation_info(args.ws_conn.get_name(),
                                             args.extra_conf.get('org_email', 'ORG_EMAIL'),
                                             args.extra_conf.get('person', 'PERSON'),
                                             args.extra_conf.get('person_email', 'PERSON_EMAIL'))

    due_dil = args.ws_conn.get_due_diligence(token=args.scope_token)
    libs_from_lic_report = args.ws_conn.get_licenses(token=args.scope_token, full_spdx=True)
    doc.packages, pkgs_spdx_ids = create_packages(libs_from_lic_report, due_dil)

    for pkg_id in pkgs_spdx_ids:
        doc.relationships.append(Relationship(relationship=f"{pkg_id} {RelationshipType.DESCRIBED_BY.name} {doc_spdx_id}"))

    file_path = write_file(doc, args.type)
    logging.info("Finished report")

    return file_path


def create_document(scope_name: str, namespace) -> Document:
    logging.debug(f"Creating SBOM Document entity")
    doc_spdx_id = "SPDXRef-DOCUMENT"
    document = Document(name=f"WhiteSource {scope_name} SBOM report",
                        namespace=namespace,
                        spdx_id=doc_spdx_id,
                        version=version.Version(2, 2),
                        data_license=License.from_identifier("CC0-1.0"))
    logging.debug(f"Finished SBOM Document entity")

    return document, doc_spdx_id


def create_creation_info(org_name, org_email, person_name, person_email):
    logging.debug(f"Creating Creation Info entity")
    creation_info = CreationInfo()
    creation_info.set_created_now()
    org = creationinfo.Organization(org_name, org_email)
    tool = creationinfo.Tool("White Source SBOM Report Generator")
    person = creationinfo.Person(person_name, person_email)

    creation_info.add_creator(org)
    creation_info.add_creator(tool)
    creation_info.add_creator(person)
    logging.debug(f"Finished creating Creation Info entity")

    return creation_info


def create_packages(libs, due_dil) -> tuple:
    logging.debug(f"Creating Packages entity")
    for d in due_dil:
        d['library'] = d['library'].rstrip('*')
    dd_dict = ws_utilities.convert_dict_list_to_dict(lst=due_dil, key_desc=('library', 'name'))
    packages = []
    pkgs_spdx_ids = []

    for lib in libs:
        pkg, pkg_spdx_id = create_package(lib, dd_dict)
        packages.append(pkg)
        pkgs_spdx_ids.append(pkg_spdx_id)
    logging.debug(f"Finished creating Packages entity")

    return packages, pkgs_spdx_ids


def create_package(lib, dd_dict):
    pkg_spdx_id = f"SPDXRef-PACKAGE-{lib['filename']}"
    logging.debug(f"Creating Package {pkg_spdx_id}")
    lib_licenses = lib.get('licenses')
    dd_keys = [(lib.get('filename'), lic['name']) for lic in lib_licenses]
    dd_entities = [dd_dict.get(dd_key) for dd_key in dd_keys]
    originator = NoAssert()
    if dd_entities:
        author = dd_entities[0].get('author')
        if author:
            originator = creationinfo.Organization(author, NoAssert())
    else:
        logging.warning(f"Unable to find the author of library: {lib['name']} ")

    lib_copyrights = lib.get('copyrightReferences')
    copyrights = [c.get('copyright') for c in lib_copyrights]
    if not copyrights:
        logging.warning(f"No copyright info found for library: {lib['name']}")
        copyrights = SPDXNone()
    references = lib.get('references')
    if not references:
        logging.warning(f"No references were found for library: {lib['name']}")
    download_location = references.get('url', NoAssert()) if references else NoAssert()

    package = Package(name=lib["name"],
                      spdx_id=pkg_spdx_id,
                      download_location=download_location,
                      version=lib.get('version', UnKnown()),
                      file_name=lib.get('filename', UnKnown()),
                      supplier=originator,
                      originator=originator)

    package.files_analyzed = False
    package.homepage = download_location
    package.check_sum = Algorithm(identifier="SHA-1", value=lib['sha1'])

    licenses = [License(full_name=lic.get('name'), identifier=lic.get('spdxName')) for lic in lib_licenses]
    for lic in licenses:
        package.add_lics_from_file(lic)

    if len(licenses) > 1:
        logging.warning(f"Library {lib['name']} has {len(licenses)} licenses. Using the 1st one")

    if licenses:                                # TODO should be fixed in SPDX-TOOLS as it is possible to have multiple lics
        licenses = licenses[0]
    else:
        logging.warning(f"No license found for library: {lib['name']}")
        licenses = SPDXNone()

    package.conc_lics = licenses

    package.license_declared = licenses
    package.cr_text = copyrights                                        # TODO should be fixed in SPDX-TOOLS as is possible to have multiple copyrights
    logging.debug(f"Finished creating Package {pkg_spdx_id}")

    return package, pkg_spdx_id


def init():
    args.ws_conn = WS(url=args.ws_url,
                      user_key=args.ws_user_key,
                      token=args.ws_token,
                      tool_details=("ps-sbom-generator", VERSION))
    args.extra_conf = {}
    try:
        fp = open(args.extra, 'r')
        args.extra_conf = json.loads(fp.read())
    except FileNotFoundError:
        logging.warning(f"Extra configuration file: {args.extra} was not found")
    except json.JSONDecodeError:
        logging.error(f"Unable to parse file: {args.extra}")


def parse_args():
    parser = argparse.ArgumentParser(description='Utility to create SBOM from WhiteSource data')
    parser.add_argument('-u', '--userKey', help="WS User Key", dest='ws_user_key', required=True)
    parser.add_argument('-k', '--token', help="WS Organization Key", dest='ws_token', required=True)
    parser.add_argument('-s', '--scope', help="Scope token of SBOM report to generate", dest='scope_token', default=True)
    parser.add_argument('-a', '--wsUrl', help="WS URL", dest='ws_url', default="saas")
    parser.add_argument('-t', '--type', help="Output type", dest='type', choices=["tv", "json", "xml", "rdf", "yaml"], default='json')
    parser.add_argument('-e', '--extra', help="Extra configuration of SBOM", dest='extra', default='sbom_extra.json')
    parser.add_argument('-o', '--out', help="Output directory", dest='out_dir', default=os.getcwd())

    return parser.parse_args()


def replace_invalid_chars(filename: str) -> str:
    old_name = filename
    for char in ws_constants.INVALID_FS_CHARS:
        filename = filename.replace(char, "_")
    logging.debug(f"Original name:'{old_name}' Fixed filename: '{filename}'")

    return filename


def write_file(doc: Document, type: str) -> ():
    # Type: (suffix, module_name, f_open_flags, encoding)
    file_types = {"json": ("json", "spdx.writers.json", "w", None),
                  "tv": ("tv", "spdx.writers.tagvalue", "w", "utf-8"),
                  "rdf": ("xml", "spdx.writers.rdf", "wb", None),
                  "xml": ("xml", "spdx.writers.xml", "wb", None),
                  "yaml": ("yml", "spdx.writers.yaml", "wb", None)}

    report_file = replace_invalid_chars(f"{doc.name}-{doc.version}.{file_types[type][0]}")
    full_path = os.path.join(args.out_dir, report_file)
    import importlib

    module = importlib.import_module(file_types[type][1])  # Dynamically loading appropriate writer module
    logging.debug(f"Writing file: {full_path} in format: {type}")

    with open(full_path, file_types[type][2], encoding=file_types[type][3]) as fp:
        module.write_document(doc, fp)

    return full_path


def main():
    global args
    args = parse_args()
    file_path = create_sbom_doc()

    return file_path


if __name__ == '__main__':
    main()
