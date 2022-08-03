import argparse
import importlib
import json
import logging
import os
import re
import sys
import urllib
from enum import Enum
import zipfile
import io

from spdx import version, creationinfo
from spdx.checksum import Algorithm
from spdx.creationinfo import CreationInfo
from spdx.document import Document, License, ExtractedLicense
from spdx.package import Package
from spdx.relationship import Relationship, RelationshipType
from spdx.utils import SPDXNone, NoAssert
from ws_sdk import ws_constants, ws_utilities, ws_errors ,web, WS

from ws_sbom_generator._version import __version__, __tool_name__

is_debug = logging.DEBUG if bool(os.environ.get("DEBUG", 0)) else logging.INFO

logger = logging.getLogger(__tool_name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(levelname)s %(asctime)s %(thread)d %(name)s: %(message)s')
s_handler = logging.StreamHandler()
s_handler.setFormatter(formatter)
s_handler.setLevel(is_debug)
logger.addHandler(s_handler)
logger.propagate = False

class License_(License):
    def __init__(self, full_name, identifier,text):
        self.text = text
        self._full_name = None
        self._identifier = None
        self.set_full_name(full_name)
        self.set_identifier(identifier)
        self.cross_ref = []
        self.comment = None


def create_sbom_doc(scope_token : str, scope_name :str) -> Document:
    def get_org_name():
        org_name = args.extra_conf.get('org_name')
        if org_name is None:
            try:
                org_name = args.ws_conn.get_name()
            except ws_errors.WsSdkServerError:
                org_name = "ORG_NAME"
                logger.error(f"Unable to get Organization name. Using: '{org_name}'")

        return org_name

    #scope = args.ws_conn.get_scope_by_token(scope_token)
    #logger.info(f"Creating SBOM Document from Mend {scope['type']}: '{scope['name']}'")
    logger.info(f"Creating SBOM Document from Mend '{scope_name}'")
    #scope_name = args.ws_conn.get_scope_name_by_token(scope_token) if args.outname == '' else args.outname
    scope_name = scope_name if args.outname == '' else args.outname
    namespace = args.extra_conf.get('namespace', 'https://[CreatorWebsite]/[pathToSpdx]/[DocumentName]-[UUID]')
    doc, doc_spdx_id = create_document(scope_name , namespace, args.outname != '')

    doc.creation_info = create_creation_info(get_org_name(),
                                             args.extra_conf.get('org_email', 'ORG_EMAIL'),
                                             args.extra_conf.get('person', 'PERSON'),
                                             args.extra_conf.get('person_email', 'PERSON_EMAIL'))
    libs_from_lic_report = args.ws_conn.get_licenses(token=scope_token, full_spdx=True)
    file_path = None
    if libs_from_lic_report:
        #logger.debug(f"Handling {len(libs_from_lic_report)} libraries in {scope['type']}: {scope['name']}")
        #logger.info(f"Finished report: {scope['type']}: {scope['name']}")

        logger.debug(f"Handling {len(libs_from_lic_report)} libraries in : {scope_name}")
        logger.info(f"Finished report: {scope_name}")
        due_dil_report = args.ws_conn.get_due_diligence(token=scope_token)

        inhouse_lib = args.ws_conn.get_in_house_libraries(token=scope_token)
        for inhouse_el in inhouse_lib:
            new_lib_due = {
                "library" : f"{inhouse_el['filename']}",
                "reference" : "No license was assigned",
                "projectName" : f"{inhouse_el['projectName']}",
                "productName": f"{inhouse_el['productName']}",
                "reference_type": "Other",
                "name" : "Unspecified License"
            }
            new_lib_lic = {
                "keyUuid" : f"{inhouse_el['keyUuid']}",
                "name" : f"{inhouse_el['filename']}",
                "filename": f"{inhouse_el['filename']}",
                "sha1": f"{inhouse_el['sha1']}",
                "artifactId": f"{inhouse_el['artifactId']}",
                "type": f"{inhouse_el['type']}",
                "version" : "",
                "licenses" : [{'name': 'Unspecified License',
                  'references': [{'referenceType': 'Other', 'reference': 'No license was assigned'}]}],
                "copyrightReferences" :[{'copyright': 'Unspecified Copyright. In-house library'}]
            }
            due_dil_report.append(new_lib_due)
            libs_from_lic_report.append(new_lib_lic)

        lib_hierarchy_report = args.ws_conn.get_inventory(token=scope_token, with_dependencies=True)
        doc.packages, pkgs_spdx_ids, pkg_relationships, doc.extracted_licenses = create_packages(libs_from_lic_report, due_dil_report, lib_hierarchy_report)  # TODO SPDX Design issue - Relationship between packages should be on package level

        doc.relationships = get_document_relationships(pkgs_spdx_ids, doc_spdx_id)
        doc.relationships.extend(pkg_relationships)

        file_path = write_report(doc, args.type)
    else:
        logger.error(f"{scope_name} Has no libraries. Report will not be generated")

    logger.info(f"Report saved at {file_path}")

    return file_path


def get_document_relationships(pkgs_spdx_ids: list, doc_spdx_id: str) -> list:
    logger.debug(f"Generating relationships to Document ID: '{doc_spdx_id}'")
    doc_relationships = []
    for pkg_id in pkgs_spdx_ids:
        doc_relationships.append(Relationship(relationship=f"{pkg_id} {RelationshipType.DESCRIBED_BY.name} {doc_spdx_id}"))
        doc_relationships.append(Relationship(relationship=f"{doc_spdx_id} {RelationshipType.DESCRIBES.name} {pkg_id}"))

    return doc_relationships


def create_document(scope_name: str, namespace, customname : bool = False) -> Document:
    logger.debug(f"Creating SBOM Document entity on: {scope_name}")
    filename = scope_name if customname else f"Mend {scope_name} SBOM report"
    doc_spdx_id = generate_spdx_id("SPDXRef-DOCUMENT")
    document = Document(name=filename,
                        namespace=namespace,
                        spdx_id=doc_spdx_id,
                        version=version.Version(2, 2),
                        data_license=License.from_identifier("CC0-1.0"))
    logger.debug(f"Finished SBOM Document entity on {scope_name}")

    return document, doc_spdx_id


def create_creation_info(org_name, org_email, person_name, person_email):
    logger.debug(f"Creating Creation Info entity")
    creation_info = CreationInfo()
    creation_info.set_created_now()
    org = creationinfo.Organization(org_name, org_email)
    tool = creationinfo.Tool("Mend SBOM Report Generator")
    person = creationinfo.Person(person_name, person_email)

    creation_info.add_creator(org)
    creation_info.add_creator(tool)
    creation_info.add_creator(person)
    logger.debug(f"Finished creating Creation Info entity")

    return creation_info


def create_packages(libs, due_dil, lib_hierarchy) -> tuple:
    def should_replace_f(dict_a, dict_b):  # Handle case where duplicate lib returns, prefer the lib with dependencies
        if dict_a.get('dependencies'):
            return True
        else:
            return False

    logger.debug(f"Creating Packages entity")
    for d in due_dil:
        d['library'] = d['library'].rstrip('*')
    dd_dict = ws_utilities.convert_dict_list_to_dict(lst=due_dil, key_desc=('library', 'name'))
    libs_hierarchy_dict = ws_utilities.convert_dict_list_to_dict(lst=lib_hierarchy, key_desc='keyUuid', should_replace_f=should_replace_f)
    packages = []
    pkgs_spdx_ids = []
    pkgs_relationships = []
    pkgs_extracted_licenses = []
    for lib in libs:
        pkg, pkg_spdx_id, pkg_relationships, pkg_extracted_licenses = create_package(lib, dd_dict, libs_hierarchy_dict.get(lib['keyUuid'], {}))
        packages.append(pkg)
        pkgs_spdx_ids.append(pkg_spdx_id)
        pkgs_relationships.extend(pkg_relationships)
        pkgs_extracted_licenses.extend(pkg_extracted_licenses)
    logger.debug(f"Finished creating Packages entity")

    return packages, pkgs_spdx_ids, pkgs_relationships, pkgs_extracted_licenses


def create_package(lib, dd_dict, lib_hierarchy_dict) -> tuple:
    def is_spdx_license(lic) -> bool:  # DUE TO WSA-8931
        return True if args.ws_conn.spdx_lic_dict.get(lic) else False

    def get_author_from_cr(copyright_references: list) -> str:
        authors = [a['author'] for a in copyright_references if a.get('author')]
        if len(authors) > 1:
            logger.warning(f"Found {len(authors)} authors on lib '{lib['name']}'. Report will contain one")
        elif not authors:
            logger.warning(f"No author data found on lib: '{lib['name']}'")

        return authors.pop() if authors else None

    def fix_license_id(license_name: str):  # TODO ADD TO upstream spdx-tools
        license_id = re.sub(r'(?![a-zA-Z0-9-.]).', '-', license_name)
        logger.debug(f"Converted license name '{license_name}' to {license_id}")

        return license_id

    def set_extra_lic_attributes(fname : str, spdx : str):
        license_o_ = ExtractedLicense(identifier=f"LicenseRef-{fix_license_id(fname)}")
        license_o_.full_name = license_o_.full_name.replace('Suspected-','')
        license_o_.identifier = license_o_.identifier.replace('Suspected-','')
        try:
            # Looking for license text in Mend by SPDX ID or Full Lic Name.
            # If not found then trying to get it from spdx.org
            lic_textfile = f"{spdx}.txt"
            if lic_textfile not in lic_filenames:
                find_susp_pos = license_o_.full_name.find('Suspected-')
                fname = license_o_.full_name[find_susp_pos + 10:] if find_susp_pos > -1 else license_o_.full_name
                find_lic_ref = fname.find("LicenseRef-")
                fname = fname if find_lic_ref == -1 else fname[find_lic_ref + 11:]
                lic_textfile = f"{fname}.txt"

            if lic_textfile in lic_filenames:
                license_o_.text = lic_filenames[lic_textfile]
            else:
                lic_textfile = lic_textfile.replace('-', '_')
                if lic_textfile in lic_filenames:
                    license_o_.text = lic_filenames[lic_textfile]
                else:
                    url = f'https://spdx.org/licenses/{spdx}.json'
                    response = urllib.request.urlopen(url)
                    data = json.loads(response.read())
                    license_o_.text = data['licenseText']
        except:
            license_o_.text = fname

        return license_o_

    def extract_licenses(lib_lics: list, lib_name: str) -> tuple:
        all_lics = []
        extracted_lics = []

        for lic in lib_lics:
            full_name = lic.get('name')
            spdx_lic_id = lic.get('spdxName')
            if spdx_lic_id and is_spdx_license(spdx_lic_id):
                logger.debug(f"Found SPDX license: '{spdx_lic_id}' on lib: '{lib_name}'")
                license_o = License(full_name=full_name, identifier=spdx_lic_id)
                if args.lictext:
                    extracted_lics.append(set_extra_lic_attributes(fname=full_name,spdx=spdx_lic_id))
            else:
                logger.debug(f"License: '{full_name}' on lib: '{lib_name}' is not a SPDX license:")
                license_o = set_extra_lic_attributes(fname=full_name,spdx=spdx_lic_id)
                extracted_lics.append(license_o)

            all_lics.append(license_o)

        return all_lics, extracted_lics

    def get_originator(dd_ents, lib_copyrights_l):
        author = get_author(dd_ents, lib_copyrights_l)

        return creationinfo.Organization(author, NoAssert()) if author else NoAssert()

    def get_author(dd_ent_l, lib_copyrights_l):
        author = None
        if dd_ent_l:  # Trying to get Author from Due Diligence
            author = dd_ent_l[0].get('author')
        if not author:  # If failed from DD, trying from lib
            logger.debug("No author found from Due Diligence data. Trying to get copyright from library data")
            author = get_author_from_cr(lib_copyrights_l)
        if not author:
            logger.warning(f"Unable to find the author of library: {lib['name']} ")

        return author

    pkg_spdx_id = generate_spdx_id(f"SPDXRef-PACKAGE-{lib['filename']}")
    logger.debug(f"Creating Package {pkg_spdx_id}")
    lib_licenses = lib.get('licenses')
    dd_keys = [(lib.get('filename'), lic['name']) for lic in lib_licenses]
    dd_entities = [dd_dict.get(dd_key) for dd_key in dd_keys]
    lib_copyrights = lib.get('copyrightReferences')
    copyrights = [c.get('copyright') for c in lib_copyrights]
    originator = get_originator(dd_entities, lib_copyrights)

    if not copyrights:
        logger.warning(f"No copyright info found for library: {lib['name']}")
        copyrights = SPDXNone()
    references = lib.get('references')
    if not references:
        logger.warning(f"No references were found for library: {lib['name']}")
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
    package.check_sum = Algorithm(identifier="SHA1", value=lib['sha1'])
    licenses, extracted_licenses = extract_licenses(lib_licenses, lib['name'])
    package.licenses_from_files = licenses

    if len(licenses) > 1:
        logger.warning(f"Found {len(licenses)} licenses on library: {lib['name']}. Using the first one")
    if licenses:  # TODO should be fixed in SPDX-TOOLS as it is possible to have multiple lics
        licenses = licenses[0]
    else:
        logger.warning(f"No license found for library: {lib['name']}")
        licenses = SPDXNone()

    package.conc_lics = licenses
    package.license_declared = licenses
    package.cr_text = copyrights  # TODO should be fixed in SPDX-TOOLS as is possible to have multiple copyrights
    pkg_relationships = get_pkg_relationships(lib_hierarchy_dict, pkg_spdx_id)

    logger.debug(f"Finished creating Package: {pkg_spdx_id}")

    return package, pkg_spdx_id, pkg_relationships, extracted_licenses


def get_pkg_relationships(lib_hierarchy_dict, pkg_spdx_id) -> list:
    logger.debug(f"Generating relationships to package ID: '{pkg_spdx_id}'")
    pkg_relationships = []
    for dep_lib in lib_hierarchy_dict.get('dependencies', []):
        dep_lib_name = normalize_spdx_enity(dep_lib['filename'])
        pkg_relationships.append(Relationship(relationship=f"{pkg_spdx_id} {RelationshipType.DEPENDS_ON.name} SPDXRef-PACKAGE-{dep_lib_name}"))

    return pkg_relationships


def normalize_spdx_enity(name : str) -> str:
    res_name = name.replace(' ', '-')
    res_name = res_name.replace('\\', '-')
    return re.sub('[!@#$%^&*()_/:+~?]', '-', res_name)


def get_prj_list(token : str) -> tuple:
    res_lic = dict()
    if token is None:
        prj_lst = web.WS.call_ws_api(self=args.ws_conn, request_type="getOrganizationProjectVitals")
    else:
        prj_lst = web.WS.call_ws_api(self=args.ws_conn, request_type="getProductProjectVitals",
                                     kv_dict={"productToken": token})  # if not Project Token, then Product Token

    for prj in prj_lst['projectVitals']:
        zipf = web.WS.call_ws_api(self=args.ws_conn, request_type="getProjectLicensesTextZip",
                                  kv_dict={"projectToken": prj['token']})
        file = io.BytesIO(zipf)
        with zipfile.ZipFile(file, 'r') as f:
            lic_filenames = f.namelist()
            for lname in lic_filenames:
                if lname not in res_lic:
                    with f.open(lname) as licfile:
                        res_lic[lname] = licfile.read().decode('utf-8')
            f.close()
    return res_lic


def prepare_lic_text(prj_token : str) -> tuple:
    try:
        all_lic_text = get_prj_list(prj_token)
    except:
        all_lic_text = dict()
        try:
            zipf = web.WS.call_ws_api(self=args.ws_conn, request_type="getProjectLicensesTextZip",
                                      kv_dict={"projectToken": prj_token})
            file = io.BytesIO(zipf)
            with zipfile.ZipFile(file, 'r') as f:
                lic_filenames = f.namelist()
                for lname in lic_filenames:
                    if lname not in all_lic_text:
                        with f.open(lname) as licfile:
                            all_lic_text[lname] = licfile.read().decode('utf-8') #prj_token
                f.close()
        except:
            pass
    return all_lic_text


def init():
    args.ws_conn = web.WSApp(url=args.ws_url,
                                    user_key=args.ws_user_key,
                                    token=args.ws_token,
                                    token_type=args.ws_token_type,
                                    tool_details=(f"ps-{__tool_name__.replace('_', '-')}", __version__))
    args.extra_conf = {}
    try:
        fp = open(args.extra, 'r')
        args.extra_conf = json.loads(fp.read())
    except FileNotFoundError:
        logger.warning(f'''{args.extra} configuration file was not found. Be sure to create a file in the following structure (-e/--extra):
            {{
                "namespace": "http://CreatorWebsite/pathToSpdx/DocumentName-UUID",
                "org_name": "Organization Name",
                "org_email": "org@email.address",
                "person": "person name",
                "person_email": "person@email.address"
            }}
        ''')
    except json.JSONDecodeError:
        logger.error(f"Unable to parse file: {args.extra}")


def parse_args():
    real_path = os.path.dirname(os.path.realpath(__file__))
    resource_real_path = os.path.join(real_path, "resources")
    parser = argparse.ArgumentParser(description='Utility to create SBOM from Mend data')
    parser.add_argument('-u', '--userKey', help="WS User Key", dest='ws_user_key', default=os.environ.get("WS_USER_KEY"), required=True if not os.environ.get("WS_USER_KEY") else False)
    parser.add_argument('-k', '--token', help="WS Key", dest='ws_token', default=os.environ.get("WS_TOKEN"), required=True if not os.environ.get("WS_TOKEN") else False)
    parser.add_argument('-s', '--scope', help="Scope token of SBOM report to generate", dest='scope_token', default=os.environ.get("WS_SCOPE_TOKEN"))
    parser.add_argument('-y', '--tokenType', help="Optional WS Token type to be stated in case WS userKey does not have organization level permissions",
                        dest='ws_token_type',
                        choices=[ws_constants.ScopeTypes.PRODUCT, ws_constants.ScopeTypes.ORGANIZATION],
                        default=os.environ.get("WS_TOKEN_TYPE", ws_constants.ScopeTypes.ORGANIZATION))
    parser.add_argument('-a', '--wsUrl', help="WS URL", dest='ws_url', default=os.environ.get("WS_URL", 'saas'))
    parser.add_argument('-t', '--type', help="Report type", dest='type', default=os.environ.get("WS_REPORT_TYPE", 'tv'),
                        choices=[f_t.lower() for f_t in SPDXFileType.__members__.keys()] + ["all"])
    parser.add_argument('-e', '--extra', help="Extra configuration of SBOM", dest='extra', default=os.path.join(resource_real_path, "sbom_extra.json"))
    parser.add_argument('-o', '--out', help="Output directory", dest='out_dir', default=os.getcwd())
    parser.add_argument('-lt', '--license_text', help="Include license text for each element", dest='lictext', default=False, type=bool)
    parser.add_argument('-on', '--out_file', help="Name of output file", dest='outname', default='')
    arguments = parser.parse_args()

    return arguments


def replace_invalid_chars(filename: str) -> str:
    old_name = filename
    for char in ws_constants.INVALID_FS_CHARS:
        filename = filename.replace(char, "_")

    logger.debug(f"Original name:'{old_name}' Fixed filename: '{filename}'")

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
        logger.info(f"Dir: {args.out_dir} does not exist. Creating it")
        os.mkdir(args.out_dir)

    module = importlib.import_module(spdx_file_type.module_classpath)  # Dynamically loading appropriate writer module
    logger.info(f"Writing file: {full_path} in format: {file_type}")
    with open(full_path, mode=spdx_file_type.f_flags, encoding=spdx_file_type.encoding) as fp:
        try:
            module.write_document(doc, fp)
        except TypeError:
            logging.exception("Error writing file")

    return full_path


class SPDXFileType(Enum):
    JSON = ("json", "spdx.writers.json", "w", None)  # TODO open spdx bug: Object of type NoAssert is not JSON serializable
    TV = ("tv", "spdx.writers.tagvalue", "w", "utf-8")
    RDF = ("rdf", "spdx.writers.rdf", "wb", None)
    XML = ("xml", "spdx.writers.xml", "wb", None)
    YAML = ("yml", "spdx.writers.yaml", "w", None)  # TODO: this will only work if  bug fix in spdx_tools: yaml.py -> write_document

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
    spdx_id = normalize_spdx_enity(id_val)
    logger.debug(f"Generating SPDX ID: Received value: '{id_val}'. ID value: '{spdx_id}'")
    return spdx_id


def get_scope_bytoken(prj_token : str):
    global args
    scopes = []
    try:
        rt = WS.call_ws_api(self=args.ws_conn, request_type="getProjectVitals",
                            kv_dict={"projectToken": prj_token})
        scopes.append({rt['projectVitals'][0]['token'] : rt['projectVitals'][0]['name']})
    except:
        try:
            rt = WS.call_ws_api(self=args.ws_conn, request_type="getProductProjectVitals",
                                kv_dict={"productToken": prj_token})
        except:
            try:
                rt = WS.call_ws_api(self=args.ws_conn, request_type="getOrganizationProjectVitals",
                                    kv_dict={"orgToken": args.ws_token})
            except:
                rt = WS.call_ws_api(self=args.ws_conn, request_type="getProductProjectVitals",
                                    kv_dict={"productToken": args.ws_token})
        for prj in rt['projectVitals']:
            scopes.append({prj['token']: prj['name']})

    return scopes


def main():
    global args
    global lic_filenames
    file_paths = []
    try:
        args = parse_args()
        init()
        lic_filenames = prepare_lic_text(args.scope_token)
        scopes = get_scope_bytoken(args.scope_token)
        '''
        if args.scope_token:
            scopes = [args.ws_conn.get_scope_by_token(args.scope_token)]

            if scopes[0].get('type') == ws_constants.ScopeTypes.PRODUCT:
                logger.info(f"Creating SBOM reports on all {scopes[0].get('name')}'s Projects")
                scopes = args.ws_conn.get_projects(product_token=scopes[0].get('token'))
        else:
            logger.info("Creating SBOM reports on all Organization's Projects")
            scopes = args.ws_conn.get_projects()
        '''
        args.outname = args.outname if len(scopes) == 1 else ''  # In case few files we can use just native names not customized
        for scope in scopes:
            #file_paths = create_sbom_doc(scope['token'])
            for key, value in scope.items():
                file_paths = create_sbom_doc(scope_token=key, scope_name=value)
    except ValueError:
        logger.error("Error running SBOM Generator")

    # return file_paths


if __name__ == '__main__':
    sys.exit(main())
