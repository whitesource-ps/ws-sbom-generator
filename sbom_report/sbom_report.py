import json
import logging
import os
import sys
from spdx import file, package, version, creationinfo
from spdx.checksum import Algorithm
from spdx.document import Document, License, ExtractedLicense
from spdx.utils import NoAssert, SPDXNone
from ws_sdk import ws_utilities, ws_constants
from ws_sdk.web import WS
import re

logging.basicConfig(level=logging.DEBUG if os.environ.get("DEBUG") else logging.INFO,
                    handlers=[logging.StreamHandler(stream=sys.stdout)],
                    format='%(levelname)s %(asctime)s %(thread)d: %(message)s',
                    datefmt='%y-%m-%d %H:%M:%S')

args = ws_conn = extra_conf = None

ARCHIVE_SUFFICES = (".jar", ".zip", ".tar", ".gz", ".tgz", ".gem", ".whl")
BIN_SUFFICES = (".dll", ".so", ".exe")
SOURCE_SUFFICES = ("JavaScript")


def init():
    global ws_conn, extra_conf
    ws_conn = WS(url=args.ws_url, user_key=args.ws_user_key, token=args.ws_token)
    extra_conf = {}
    try:
        fp = open(args.extra, 'r')
        extra_conf = json.loads(fp.read())
    except FileNotFoundError:
        logging.warning(f"Extra configuration file: {args.extra} was not found")
    except json.JSONDecodeError:
        logging.error(f"Unable to parse file: {args.extra}")


def filter_dups_and_sort(items: list) -> list:
    ret_list = {}
    for item in items:
        if isinstance(item, (NoAssert, SPDXNone)):
            ret_list[type(item).__name__] = item
        else:
            ret_list[item.full_name] = item
    ret_list = {k: v for k, v in sorted(ret_list.items())}

    return list(ret_list.values())


def create_sbom_doc():
    global ws_conn, args
    init()
    scope = ws_conn.get_scope_by_token(args.scope_token)
    logging.info(f"Starting to work on SBOM Document of {scope['type']} {scope['name']} (token: {args.scope_token})")
    doc = create_document(args.scope_token)

    # Manually loading licenses file as built-in filter deprecated licenses
    from spdx.config import _licenses                                # TODO: REMOVE AS UNNECESSARY STARTING FROM SDK 0.2
    with open(_licenses, "r") as fp:
        licenses = json.loads(fp.read())
    logging.debug(f"License List Version: {licenses['licenseListVersion']}")
    licenses_dict = ws_utilities.convert_dict_list_to_dict(lst=licenses['licenses'], key_desc='licenseId')
    doc.package = create_package(scope['name'], licenses_dict, 1)

    doc.package.files, licenses_from_files, copyrights_from_files, extracted_licenses_from_files = create_files(args.scope_token, licenses_dict)

    # After file section creation
    doc.package.verif_code = doc.package.calc_verif_code()
    doc.package.licenses_from_files = licenses_from_files
    doc.extracted_licenses = filter_dups_and_sort(extracted_licenses_from_files)
    doc.package.cr_text = ', '.join(sorted(list(copyrights_from_files)))
    file_path = write_file(doc, args.type)

    logging.info("Finished report")

    return file_path


def create_document(token: str) -> Document:
    logging.debug(f"Creating SBOM Document section")
    global ws_conn
    scope_name = ws_conn.get_scope_name_by_token(token)
    document = Document(name=f"WhiteSource {scope_name} SBOM report",
                        namespace=extra_conf.get('namespace', 'NAMESPACE'),
                        spdx_id="SPDXRef-DOCUMENT",
                        version=version.Version(2, 2),
                        data_license=License.from_identifier("CC0-1.0"))

    logging.debug(f"Creating SBOM Creation Info section")
    document.creation_info.set_created_now()
    org = creationinfo.Organization(ws_conn.get_name(), extra_conf.get('org_email'))
    tool = creationinfo.Tool("White Source SBOM Report Generator")
    person = creationinfo.Person(extra_conf.get('person'), extra_conf.get('person_email'))
    document.creation_info.add_creator(org)
    document.creation_info.add_creator(tool)
    document.creation_info.add_creator(person)
    logging.debug(f"Finished SBOM Document section")

    return document


def create_package(package_name: str,
                   licenses_dict: dict,
                   p_id: int) -> package.Package:
    logging.debug(f"Creating SBOM Package section")
    pkg = package.Package(name=package_name,
                          spdx_id=f"SPDXRef-PACKAGE-{p_id}",
                          download_location=extra_conf.get('package_location', NoAssert()))
    pkg.check_sum = Algorithm(identifier="SHA1", value=extra_conf.get('package_sha1', NoAssert()))
    pkg.license_declared = get_license_obj(extra_conf.get('package_license_identifier'), licenses_dict)
    pkg.conc_lics = get_license_obj(extra_conf.get('package_conc_licenses'), licenses_dict)
    pkg.cr_text = extra_conf.get('package_copyright_text', NoAssert())
    pkg.supplier = creationinfo.Person(extra_conf.get('package_supplier', SPDXNone()), extra_conf.get('package_supplier_email', SPDXNone()))

    logging.debug(f"Finished SBOM package section")

    return pkg


def get_license_obj(lic_id: str, licenses_dict: dict) -> License:
    lic_id_dict = licenses_dict.get(lic_id)
    if lic_id_dict:
        lic_obj = License(full_name=lic_id_dict['name'], identifier=lic_id_dict['licenseId'])
    else:
        lic_obj = NoAssert()

    return lic_obj


def create_files(scope_token: str,
                 licenses_dict: dict) -> tuple:
    # filter set to contain only a single of SPDXNone and NOASSERT
    def __filter_none_types__(in_set):
        out_set = set()
        no_assert_in_set = False
        spdx_none_int_set = False
        for ent in in_set:
            ent_is_no_assert = isinstance(ent, NoAssert)
            ent_is_spdx_none = isinstance(ent, SPDXNone)

            if not no_assert_in_set and ent_is_no_assert:
                no_assert_in_set = True
                out_set.add(ent)
            elif not spdx_none_int_set and ent_is_spdx_none:
                spdx_none_int_set = True
                out_set.add(ent)
            elif not ent_is_spdx_none and not ent_is_no_assert:
                out_set.add(ent)

        return out_set

    def __create_spdx_filename__(lib_name: str, l_loc: dict) -> str:
        path = ""
        locations = l_loc.get('locations')
        if len(locations):
            if len(locations) > 1:
                logging.warning(f"Found {len(l_loc['locations'])} locations for lib {lib_name}. Using the first one")
            location = locations[0]
            try:
                split_path = re.split('\\\\|\\|/|//|/', location['path'])
                path = f"../{split_path[-4]}/{split_path[-3]}/{split_path[-2]}/"
                logging.debug(f"Using {path} as file location")
            except KeyError:
                logging.error(f"No path value in lib: {lib_name} ")
            except IndexError:
                path = location['path']
                logging.warning(f"Unable to create path value from last 3 sections of: {path}")

        else:
            logging.warning(f"No locations found for lib {lib_name} ")

        rel_path = path + lib_name
        logging.debug(f"Received filename: {lib_name}. SPDX relative path: {rel_path}")

        return rel_path

    global ws_conn
    files = []
    all_licenses_from_files = set()
    all_copyright_from_files = set()
    all_extracted_licenses_from_files = list()
    dd_list = ws_conn.get_due_diligence(token=scope_token)
    dd_dict = ws_utilities.convert_dict_list_to_dict(lst=dd_list, key_desc=('library', 'name'))
    libs = ws_conn.get_licenses(token=scope_token)
    libs_loc_list = ws_conn.get_library_location(token=scope_token)
    libs_loc = ws_utilities.convert_dict_list_to_dict(libs_loc_list, 'keyUuid')
    lib_filenames = set()
    for i, lib in enumerate(libs):
        lib_loc = libs_loc[lib['keyUuid']]
        spdx_filename = __create_spdx_filename__(lib['filename'], lib_loc)
        if spdx_filename not in lib_filenames:
            lib_filenames.add(spdx_filename)                    # Tracking lib names as SPDX does not allow duplications
            logging.debug(f"Handling library (filename: {spdx_filename}")
            spdx_file = file.File(name=spdx_filename,
                                  spdx_id=f"SPDXRef-FILE-{i+1}",
                                  chk_sum=Algorithm(identifier="SHA1", value=lib['sha1']))
            spdx_file.comment = lib.get('description')
            spdx_file.type = set_file_type(lib['type'], spdx_filename)

            file_licenses, extracted_licenses = handle_file_licenses(lib['licenses'], licenses_dict)
            spdx_file.licenses_in_file = filter_dups_and_sort(file_licenses)

            all_licenses_from_files.update(file_licenses)
            all_extracted_licenses_from_files.extend(extracted_licenses)

            spdx_file.conc_lics = SPDXNone()

            file_copyrights = handle_file_copyright(lib['licenses'], lib, dd_dict)
            if file_copyrights:
                spdx_file.copyright = ', '.join(sorted(list(file_copyrights)))
                all_copyright_from_files.update(file_copyrights)
            else:
                spdx_file.copyright = NoAssert()

            files.append(spdx_file)
        else:
            logging.warning(f"Found duplicate library: {lib['name']}, filename: {spdx_filename} ID: {lib['keyUuid']}. Skipping")
            
    all_licenses_from_files = __filter_none_types__(all_licenses_from_files)

    return files, all_licenses_from_files, all_copyright_from_files, all_extracted_licenses_from_files


def handle_file_licenses(licenses: list,
                         licenses_dict: dict) -> tuple:
    def __create_ext_license__(name):
        ext_license = ExtractedLicense(identifier=name)
        ext_license.full_name = name
        ext_license.text = name

        return ext_license

    found_lics = set()
    extracted_licenses = list()
    for lic in licenses:
        fix_license(lic)                                        # TODO: MOVE TO SDK
        try:
            spdx_license_dict = licenses_dict[lic['spdxName']]
            logging.debug(f"Found license: {spdx_license_dict['licenseId']}")
            spdx_license = License(full_name=spdx_license_dict['licenseId'], identifier=lic['spdxName'])
            found_lics.add(spdx_license)
            if spdx_license_dict['isDeprecatedLicenseId']:
                logging.debug(f"License {lic['spdxName']} is deprecated")
                extracted_licenses.append(__create_ext_license__(lic['spdxName']))
        except KeyError:
            logging.warning(f"License with identifier: {lic['name']} was not found")
            __create_ext_license__(lic['name'])
            extracted_licenses.append(__create_ext_license__(lic['name']))

    if not found_lics:
        found_lics.add(NoAssert())

    return found_lics, extracted_licenses


def handle_file_copyright(licenses: list,
                          lib: dict,
                          dd_dict: dict) -> set:
    found_copyrights = set()

    for lic in licenses:                                                    # Searching for copyright on licenses
        dd_val = dd_dict.get((lib['filename'], lic['name']))
        if dd_val:
            dd_cr = dd_val.get('copyright')
            license_copyright = f"{lic.get('name')} - {dd_cr}"
            logging.debug(f"Found copyright on license: {license_copyright}")
            found_copyrights.add(license_copyright)

    if not found_copyrights and lib.get('copyrightReferences'):             # Searching for copyright on library
        for d in lib.get('copyrightReferences'):
            logging.debug(f"Found copyright on lib: {d['copyright']}")
            found_copyrights.add(d['copyright'])

    if not found_copyrights:
        logging.warning(f"Copyright on : ({lib['filename']}  was not found")

    return found_copyrights


def fix_license(lic: dict):     # TODO: ALREADY IN SDK TO BE REMOVED
    if not lic.get('spdxName'):
        if lic.get('name') == "Public Domain":
            lic['spdxName'] = "CC-PDDC"
        elif lic.get('name') == "AGPL":
            lic['spdxName'] = "AGPL-1.0"
        elif lic.get('name') == "BSD Zero":
            lic['spdxName'] = "0BSD"

        if lic.get('spdxName'):
            logging.info(f"Fixed spdxName of {lic['name']} to {lic['spdxName']}")
        else:
            logging.warning(f"Unable to fix spdxName of {lic['name']}")


def set_file_type(file_type: str, filename: str):
    if file_type == "Source Library" or file_type in SOURCE_SUFFICES:
        ret = file.FileType.SOURCE
        logging.debug(f"Type of file: {filename} is source file")
    elif filename.endswith(ARCHIVE_SUFFICES):
        logging.debug(f"Type of file: {filename} is archive")
        ret = file.FileType.ARCHIVE
    elif filename.endswith(BIN_SUFFICES):
        logging.debug(f"Type of file: {filename} is binary")
        ret = file.FileType.BINARY
    else:
        logging.warning(f"File Type of {file_type} did not match. File will be marked as OTHER type")
        ret = file.FileType.OTHER

    return ret


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
    module = importlib.import_module(file_types[type][1])           # Dynamically loading appropriate writer module
    logging.debug(f"Writing file: {full_path} in format: {type}")

    with open(full_path, file_types[type][2], encoding=file_types[type][3]) as fp:
        module.write_document(doc, fp)

    return full_path


def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description='Utility to create SBOM from WhiteSource data')
    parser.add_argument('-u', '--userKey', help="WS User Key", dest='ws_user_key', required=True)
    parser.add_argument('-k', '--token', help="WS Organization Key", dest='ws_token', required=True)
    parser.add_argument('-s', '--scope', help="Scope token of SBOM report to generate", dest='scope_token', default=True)
    parser.add_argument('-a', '--wsUrl', help="WS URL", dest='ws_url', default="saas")
    parser.add_argument('-t', '--type', help="Output type", dest='type', choices=["tv", "json", "xml", "rdf", "yaml"], default='json')
    parser.add_argument('-e', '--extra', help="Extra configuration of SBOM", dest='extra', default='sbom_extra.json')
    parser.add_argument('-o', '--out', help="Output directory", dest='out_dir', default=os.getcwd())

    return parser.parse_args()


def main():
    global args
    args = parse_args()
    file_path = create_sbom_doc()

    return file_path


if __name__ == '__main__':
    main()
