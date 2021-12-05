#!/usr/bin/env python
import importlib
import json
import logging
import os
import argparse
import sys
from enum import Enum


try:                                            # TODO TEMP SOLUTION UNTIL spdx-tools can be a dependency
    from spdx import version, creationinfo
    from spdx.checksum import Algorithm
    from spdx.creationinfo import CreationInfo
    from spdx.document import Document, License
    from spdx.package import Package
    from spdx.relationship import Relationship, RelationshipType
    from spdx.utils import SPDXNone, NoAssert
except ImportError:
    logging.error("SPDX package is missing")
    exit(-1)

from ws_sdk import ws_constants, WS, ws_utilities
from ws_sbom_generator._version import __version__, __tool_name__


logging.basicConfig(level=logging.DEBUG if os.environ.get("DEBUG") else logging.INFO,
                    handlers=[logging.StreamHandler(stream=sys.stdout)],
                    format='%(levelname)s %(asctime)s %(thread)d %(name)s: %(message)s',
                    datefmt='%y-%m-%d %H:%M:%S')
args = None


def create_sbom_doc(scope_token) -> Document:
    scope = args.ws_conn.get_scope_by_token(scope_token)
    logging.info(f"Creating SBOM Document from WhiteSource {scope['type']}: '{scope['name']}'")
    scope_name = args.ws_conn.get_scope_name_by_token(scope_token)
    namespace = args.extra_conf.get('namespace', 'https://[CreatorWebsite]/[pathToSpdx]/[DocumentName]-[UUID]')
    doc, doc_spdx_id = create_document(scope_name, namespace)

    doc.creation_info = create_creation_info(args.ws_conn.get_name(),
                                             args.extra_conf.get('org_email', 'ORG_EMAIL'),
                                             args.extra_conf.get('person', 'PERSON'),
                                             args.extra_conf.get('person_email', 'PERSON_EMAIL'))
    libs_from_lic_report = args.ws_conn.get_licenses(token=scope_token, full_spdx=True)
    file_path = None
    if libs_from_lic_report:
        logging.debug(f"Handling {len(libs_from_lic_report)} libraries in {scope['type']}: {scope['name']}")
        logging.info(f"Finished report: {scope['type']}: {scope['name']}")
        due_dil_report = args.ws_conn.get_due_diligence(token=scope_token)
        lib_hierarchy_report = args.ws_conn.get_inventory(token=scope_token, with_dependencies=True)
        doc.packages, pkgs_spdx_ids, pkg_relationships = create_packages(libs_from_lic_report, due_dil_report, lib_hierarchy_report)    # TODO SPDX Design issue - Relationship between packages should be on package level

        doc.relationships = get_document_relationships(pkgs_spdx_ids, doc_spdx_id)
        doc.relationships.extend(pkg_relationships)

        file_path = write_report(doc, args.type)
    else:
        logging.error(f"{scope['type'].capitalize()}: {scope['name']} Has no libraries. Report will not be generated")

        logging.info(f"Report saved at {file_path}")

    return file_path


def get_document_relationships(pkgs_spdx_ids: list, doc_spdx_id: str) -> list:
    doc_relationships = []
    for pkg_id in pkgs_spdx_ids:
        doc_relationships.append(Relationship(relationship=f"{pkg_id} {RelationshipType.DESCRIBED_BY.name} {doc_spdx_id}"))

    return doc_relationships


def create_document(scope_name: str, namespace) -> Document:
    logging.debug(f"Creating SBOM Document entity on: {scope_name}")
    doc_spdx_id = generate_spdx_id("SPDXRef-DOCUMENT")
    document = Document(name=f"WhiteSource {scope_name} SBOM report",
                        namespace=namespace,
                        spdx_id=doc_spdx_id,
                        version=version.Version(2, 2),
                        data_license=License.from_identifier("CC0-1.0"))
    logging.debug(f"Finished SBOM Document entity on {scope_name}")

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


def create_packages(libs, due_dil, lib_hierarchy) -> tuple:
    def should_replace_f(dict_a, dict_b):       # Handle case where duplicate lib returns, prefer the lib with dependencies
        if dict_a.get('dependencies'):
            return True
        else:
            return False

    logging.debug(f"Creating Packages entity")
    for d in due_dil:
        d['library'] = d['library'].rstrip('*')
    dd_dict = ws_utilities.convert_dict_list_to_dict(lst=due_dil, key_desc=('library', 'name'))
    libs_hierarchy_dict = ws_utilities.convert_dict_list_to_dict(lst=lib_hierarchy, key_desc='keyUuid', should_replace_f=should_replace_f)
    packages = []
    pkgs_spdx_ids = []
    pkgs_relationships = []
    for lib in libs:
        pkg, pkg_spdx_id, pkg_relationships = create_package(lib, dd_dict, libs_hierarchy_dict.get(lib['keyUuid'], {}))
        packages.append(pkg)
        pkgs_spdx_ids.append(pkg_spdx_id)
        pkgs_relationships.extend(pkg_relationships)
    logging.debug(f"Finished creating Packages entity")

    return packages, pkgs_spdx_ids, pkgs_relationships


def create_package(lib, dd_dict, lib_hierarchy_dict) -> tuple:
    def get_author_from_cr(copyright_references: list) -> str:
        authors = [a['author'] for a in copyright_references if a.get('author')]
        if len(authors) > 1:
            logging.warning(f"Found {len(authors)} authors on lib '{lib['name']}'. Report will contain one")
        elif not authors:
            logging.warning(f"No author data found on lib: '{lib['name']}'")

        return authors.pop() if authors else None

    pkg_spdx_id = generate_spdx_id(f"SPDXRef-PACKAGE-{lib['filename']}")
    logging.debug(f"Creating Package {pkg_spdx_id}")
    lib_licenses = lib.get('licenses')
    dd_keys = [(lib.get('filename'), lic['name']) for lic in lib_licenses]
    dd_entities = [dd_dict.get(dd_key) for dd_key in dd_keys]
    originator = NoAssert()
    lib_copyrights = lib.get('copyrightReferences')
    author = None

    if dd_entities:                                             # Trying to get Author from Due Diligence
        author = dd_entities[0].get('author')
    if not author:                                              # If failed from DD, trying from lib
        logging.debug("No author found from Due Diligence data. Trying to get copyright from library data")
        author = get_author_from_cr(lib_copyrights)
    if author:
        originator = creationinfo.Organization(author, NoAssert())
    else:
        logging.warning(f"Unable to find the author of library: {lib['name']} ")

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
                      version=lib.get('version', NoAssert()),
                      file_name=lib.get('filename', NoAssert()),
                      supplier=originator,
                      originator=originator)

    package.files_analyzed = False
    package.homepage = download_location
    package.check_sum = Algorithm(identifier="SHA-1", value=lib['sha1'])

    licenses = [License(full_name=lic.get('name'), identifier=lic.get('spdxName')) for lic in lib_licenses]
    package.licenses_from_files = licenses
    if len(licenses) > 1:
        logging.warning(f"Found {len(licenses)} licenses on library: {lib['name']}. Using the first one")
    if licenses:                         # TODO should be fixed in SPDX-TOOLS as it is possible to have multiple lics
        licenses = licenses[0]
    else:
        logging.warning(f"No license found for library: {lib['name']}")
        licenses = SPDXNone()

    package.conc_lics = licenses
    package.license_declared = licenses
    package.cr_text = copyrights         # TODO should be fixed in SPDX-TOOLS as is possible to have multiple copyrights
    pkg_relationships = get_pkg_relationships(lib_hierarchy_dict, pkg_spdx_id)

    logging.debug(f"Finished creating Package: {pkg_spdx_id}")

    return package, pkg_spdx_id, pkg_relationships


def get_pkg_relationships(lib_hierarchy_dict, pkg_spdx_id) -> list:
    pkg_relationships = []
    for dep_lib in lib_hierarchy_dict.get('dependencies', []):
        pkg_relationships.append(Relationship(relationship=f"{pkg_spdx_id} {RelationshipType.DEPENDS_ON.name} SPDXRef-PACKAGE-{dep_lib['filename']}"))

    return pkg_relationships


def init():
    args.ws_conn = WS(url=args.ws_url,
                      user_key=args.ws_user_key,
                      token=args.ws_token,
                      tool_details=(f"ps-{__tool_name__.replace('_','-')}", __version__))
    args.extra_conf = {}
    try:
        fp = open(args.extra, 'r')
        args.extra_conf = json.loads(fp.read())
    except FileNotFoundError:
        logging.warning(f'''{args.extra} configuration file was not found. Be sure to create a file in the following structure (-e/--extra):
            {{
                "namespace": "http://CreatorWebsite/pathToSpdx/DocumentName-UUID",
                "org_email": "org@email.address",
                "person": "person name",
                "person_email": "person@email.address"
            }}
        ''')
    except json.JSONDecodeError:
        logging.error(f"Unable to parse file: {args.extra}")


def parse_args():
    real_path = os.path.dirname(os.path.realpath(__file__))
    resource_real_path = os.path.join(real_path, "resources")
    parser = argparse.ArgumentParser(description='Utility to create SBOM from WhiteSource data')
    parser.add_argument('-u', '--userKey', help="WS User Key", dest='ws_user_key', default=os.environ.get("WS_USER_KEY"))
    parser.add_argument('-k', '--token', help="WS Organization Key", dest='ws_token', default=os.environ.get("WS_TOKEN"))
    parser.add_argument('-s', '--scope', help="Scope token of SBOM report to generate", dest='scope_token', default=os.environ.get("WS_SCOPE"))
    parser.add_argument('-a', '--wsUrl', help="WS URL", dest='ws_url', default=os.environ.get("WS_URL"))
    parser.add_argument('-t', '--type', help="Output type", dest='type', default=os.environ.get("WS_REPORT_TYPE", 'tv'),
                        choices=[f_t.lower() for f_t in SPDXFileType.__members__.keys()] + ["all"])
    parser.add_argument('-e', '--extra', help="Extra configuration of SBOM", dest='extra', default=os.path.join(resource_real_path, "sbom_extra.json"))
    parser.add_argument('-o', '--out', help="Output directory", dest='out_dir', default=os.getcwd())
    arguments = parser.parse_args()

    missing_arg = False
    if arguments.ws_user_key is None:
        logging.error("No User Key is specified")
        missing_arg = True
    if arguments.ws_token is None:
        logging.error("No Organization Token is specified")
        missing_arg = True

    if missing_arg:
        raise ValueError

    return arguments


def replace_invalid_chars(filename: str) -> str:
    old_name = filename
    for char in ws_constants.INVALID_FS_CHARS:
        filename = filename.replace(char, "_")
    logging.debug(f"Original name:'{old_name}' Fixed filename: '{filename}'")

    return filename


def write_report(doc: Document, file_type: str) -> str:
    f_types = [f_t.lower() for f_t in SPDXFileType.__members__.keys()] if file_type == "all" else [file_type]
    full_paths = []

    for f_type in f_types:
        full_path = write_file(SPDXFileType, doc, f_type)
        full_paths.append(full_path)

    return full_paths


def write_file(spdx_f_t_enum, doc, file_type) -> str:
    spdx_file_type = spdx_f_t_enum.get_file_type(file_type)
    report_filename = replace_invalid_chars(f"{doc.name}-{doc.version}.{spdx_file_type.suffix}")
    full_path = os.path.join(args.out_dir, report_filename)

    if not os.path.exists(args.out_dir):
        logging.info(f"Dir: {args.out_dir} does not exist. Creating it")
        os.mkdir(args.out_dir)

    module = importlib.import_module(spdx_file_type.module_classpath)  # Dynamically loading appropriate writer module
    logging.info(f"Writing file: {full_path} in format: {file_type}")
    with open(full_path, mode=spdx_file_type.f_flags, encoding=spdx_file_type.encoding) as fp:
        try:
            module.write_document(doc, fp)
        except TypeError:
            logging.exception("Error writing file")

    return full_path


class SPDXFileType(Enum):
    JSON = ("json", "spdx.writers.json", "w", None)  # TODO open spdx bug: Object of type NoAssert is not JSON serializable
    TV = ("tv", "spdx.writers.tagvalue", "w", "utf-8")
    RDF = ("xml", "spdx.writers.rdf", "wb", None)
    XML = ("xml", "spdx.writers.xml", "wb", None)
    YAML = ("yml", "spdx.writers.yaml", "wb", None)   # TODO: this will only work if  bug fix in spdx_tools: yaml.py -> write_document

    def __str__(self):
        return self.name

    @classmethod
    def get_file_type(cls, f_t: str):
        return cls.__dict__[f_t.upper()]

    @property
    def suffix(self):
        return self.value[0]

    @property
    def module_classpath(self):
        return self.value[1]

    @property
    def f_flags(self):
        return self.value[2]

    @property
    def encoding(self):
        return self.value[3]


def generate_spdx_id(id_val) -> str:
    spdx_id = id_val.replace(' ', '_')      # TODO SPDX issue: RELATIONSHIP are parsed as a text (better tuple it)
    logging.debug(f"Generating SPDX ID: Received value: '{id_val}'. ID value: '{spdx_id}'")

    return spdx_id


def main():
    global args
    file_paths = []
    try:
        args = parse_args()
        init()
        scope_type = None
        if ws_utilities.is_token(args.scope_token):
            scope_type = args.ws_conn.get_scope_type_by_token(args.scope_token)

        if scope_type == ws_constants.PROJECT:
            scopes = [args.ws_conn.get_scope_by_token(args.scope_token)]
        elif scope_type == ws_constants.PRODUCT:
            scopes = args.ws_conn.get_projects(product_token=args.scope_token)
            logging.info(f"Creating SBOM report per project in {scope_type}: {scopes[0]['productName']}")
        else:
            logging.info("Creating SBOM reports on all Organization Projects")
            scopes = args.ws_conn.get_projects()

        for scope in scopes:
            file_paths = create_sbom_doc(scope['token'])
    except ValueError:
        logging.error("Error running SBOM Generator")

    # return file_paths


if __name__ == '__main__':
    sys.exit(main())