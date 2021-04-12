import json
import logging

import sys
from spdx import file, package, version, creationinfo
from spdx.checksum import Algorithm
from spdx.document import Document, License
from spdx.utils import NoAssert, SPDXNone
from ws_sdk import ws_utilities
from ws_sdk.web import WS

logging.basicConfig(level=logging.INFO,
                    stream=sys.stdout,
                    format='%(levelname)s %(asctime)s %(thread)d: %(message)s',
                    datefmt='%y-%m-%d %H:%M:%S')

args = ws_conn = extra_conf = None

ARCHIVE_SUFFICES = (".jar", ".zip", ".tar", ".gz", ".tgz")                   # TODO COMPILE LIST


def init():
    global ws_conn, extra_conf
    ws_conn = WS(url=args.ws_url, user_key=args.ws_user_key, token=args.ws_token)
    try:
        fp = open(args.extra).read()
        extra_conf = json.loads(fp)
    except FileNotFoundError:
        logging.warning(f"Extra configuration file: {args.extra} was not found")
    except json.JSONDecodeError:
        logging.error(f"Unable to parse file: {args.extra}")


def create_sbom_doc():
    global ws_conn, args
    init()
    scope = ws_conn.get_scope_by_token(args.scope_token)
    logging.info(f"Starting to work on SBOM Document of {scope['type']} {scope['name']} (token: {args.scope_token})")
    doc = create_document(args.scope_token)

    # Manually loading licenses file as built-in filter depracated licenses
    from spdx.config import _licenses, _exceptions
    with open(_licenses, "r") as fp:
        licenses = json.loads(fp.read())
    logging.debug(f"License List Version: {licenses['licenseListVersion']}")
    licenses_dict = ws_utilities.convert_dict_list_to_dict(lst=licenses['licenses'], key_desc='licenseId')
    doc.package = create_package(scope['name'], licenses_dict)
    doc.package.files, licenses_from_files, copyrights_from_files = create_files(args.scope_token, licenses_dict)

    # After file section creation
    doc.package.verif_code = doc.package.calc_verif_code()
    doc.package.licenses_from_files = licenses_from_files
    doc.package.cr_text =  ', '.join(copyrights_from_files)
    write_file(doc, args.type)

    logging.info("Finished report")


def create_document(token: str) -> Document:
    logging.debug(f"Creating SBOM Document section")
    global ws_conn
    scope_name = ws_conn.get_scope_name_by_token(token)
    document = Document(name=f"WhiteSource {scope_name} SBOM report",
                        namespace=extra_conf.get('namespace'),
                        spdx_id="SPDXRef-DOCUMENT",
                        version=version.Version(2, 2),
                        data_license=License.from_identifier("CC0-1.0"))

    logging.debug(f"Creating SBOM Creation Info section")
    document.creation_info.set_created_now()
    org = creationinfo.Organization(ws_conn.get_organization_name(), extra_conf.get('org_email'))
    tool = creationinfo.Tool("White Source SBOM Report Generator")
    person = creationinfo.Person(extra_conf.get('person'), extra_conf.get('person_email'))
    document.creation_info.add_creator(org)
    document.creation_info.add_creator(tool)
    document.creation_info.add_creator(person)
    logging.debug(f"Finished SBOM Document section")

    return document


def create_package(package_name: str, licenses_dict: dict) -> package.Package:
    logging.debug(f"Creating SBOM Package section")
    pkg = package.Package(name=package_name,
                          spdx_id="SPDXRef-PACKAGE-1",
                          download_location=extra_conf.get('package_location', NoAssert()))
    pkg.check_sum = Algorithm(identifier="SHA1", value=extra_conf.get('package_sha1', NoAssert()))
    pkg.license_declared = get_license_obj(extra_conf.get('package_license_identifier'), licenses_dict)
    pkg.conc_lics = get_license_obj(extra_conf.get('package_conc_licenses'), licenses_dict)
    pkg.cr_text = extra_conf.get('package_copyright_text', NoAssert())
    logging.debug(f"Finished SBOM package section")

    return pkg


def get_license_obj(lic_id: str, licenses_dict: dict) -> License:
    lic_id_dict = licenses_dict.get(lic_id)
    if lic_id_dict:
        lic_obj = License(full_name=lic_id_dict['name'], identifier=lic_id_dict['licenseId'])
    else:
        lic_obj = NoAssert()

    return lic_obj


def create_files(scope_token: str, licenses_dict):      # TODO SIMPLIFY THIS
    global ws_conn
    files = []
    all_licenses_from_files = set()
    all_copyright_from_files = set()
    dd_list = ws_conn.get_due_diligence(token=scope_token)
    dd_dict = ws_utilities.convert_dict_list_to_dict(lst=dd_list, key_desc=('library', 'name'))
    libs = ws_conn.get_licenses(token=scope_token)

    for i, lib in enumerate(libs):
        logging.debug(f"Handling library: {lib['name']}")
        spdx_file = file.File(name=lib['filename'],
                              spdx_id=f"SPDXRef-FILE-{i+1}",
                              chk_sum=Algorithm(identifier="SHA1", value=lib['sha1']))
        spdx_file.comment = lib.get('description')
        spdx_file.type = set_file_type(lib['type'], lib['filename'])

        file_license_copyright = set()
        licenses_in_file = set()
        for lic in lib['licenses']:
            # Handling license
            try:
                license_full_name = licenses_dict[lic['spdxName']]
                logging.debug(f"Found license: {license_full_name}")
                spdx_license = License(full_name=license_full_name, identifier=lic['spdxName'])
            except KeyError:
                logging.error(f"License with identifier: {lic['name']} was not found")
                spdx_license = NoAssert()

            all_licenses_from_files.add(spdx_license)

            # Handling Copyright license
            try:
                # license_copyright = f"{lic.get('name')} - {dd_dict[(lib['filename'], lic['name'])]['copyright']}"
                license_copyright = str(lib['copyrightReferences'])
                all_copyright_from_files.add(license_copyright)
                file_license_copyright.add(license_copyright)
                logging.debug(f"Found copyright: {license_copyright}")
            except KeyError:
                logging.error(f"Copyright of : ({lib['filename']}, {lic['name']}) was not found")

        # In case no licenses found on this lib
        if not licenses_in_file:
            licenses_in_file.add(NoAssert())

        spdx_file.copyright = ', '.join(file_license_copyright) if file_license_copyright else SPDXNone()
        spdx_file.conc_lics = SPDXNone()
        spdx_file.licenses_in_file = list(licenses_in_file)
        files.append(spdx_file)

    return files, all_licenses_from_files, all_copyright_from_files


def set_file_type(file_type: str, filename: str):                            # TODO ADDITIONAL TESTINGS
    if file_type == "Source Files":
        ret = file.FileType.SOURCE
        logging.debug(f"Type of file: {filename} is source file")
    elif filename.endswith(ARCHIVE_SUFFICES):
        logging.debug(f"Type of file: {filename} is archive")
        ret = file.FileType.ARCHIVE
    elif False:                                                               # TODO SEE IF WE CAN DISCOVER BINARIES
        logging.debug(f"Type of file: {filename} is binary")
        ret = file.FileType.BINARY
    else:
        logging.warning(f"File Type of {file_type} did not match. File will be marked as OTHER type")
        ret = file.FileType.OTHER

    return ret


def write_file(doc: Document, type: str):
                # Type: (suffix, module_name)
    file_types = {"json" : ("json", "spdx.writers.json"),
                  "tv" : ("tv", "spdx.writers.tagvalue"),
                  "rdf" : ("xml", "spdx.writers.rdf"),
                  "xml": ("xml", "spdx.writers.xml"),
                  "yaml": ("yml", "spdx.writers.yaml")}
    report_file = f"{doc.name}-{doc.version}.{file_types[type][0]}"
    import importlib
    module = importlib.import_module(file_types[type][1])           # Dynamically loading appropriate writer module
    logging.debug(f"Writing file: {report_file} in format: {type}")
    with open(report_file, "w") as fp:
        module.write_document(doc, fp)


def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description='Utility to create SBOM from WhiteSource data')
    parser.add_argument('-u', '--userKey', help="WS User Key", dest='ws_user_key', required=True)
    parser.add_argument('-o', '--token', help="WS Organization Key", dest='ws_token', required=True)
    parser.add_argument('-s', '--scope', help="Scope token of SBOM report to generate", dest='scope_token', default=True)
    parser.add_argument('-a', '--wsUrl', help="WS URL", dest='ws_url', default="saas")
    parser.add_argument('-t', '--type', help="Output type", dest='type', choices=["tv", "json", "xml", "rdf", "yaml"], default='json')
    parser.add_argument('-e', '--extra', help="Extra configuration of SBOM", dest='extra', default='sbom_extra.json')

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    create_sbom_doc()
