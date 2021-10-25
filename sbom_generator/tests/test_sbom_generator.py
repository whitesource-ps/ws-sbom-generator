from unittest.mock import patch

import pytest
from spdx import relationship, document, creationinfo, package

from sbom_generator import sbom_generator


# @pytest.fixture
# def setup():
#     ws_token = os.environ.get('WS_SCOPE_PROJ')
#     sbom_generator.parse_args = MagicMock()
#     sbom_generator.parse_args.return_value.ws_user_key = os.environ.get('WS_USER_KEY')
#     sbom_generator.parse_args.return_value.ws_token = os.environ.get('WS_SCOPE_ORG')
#     sbom_generator.parse_args.return_value.scope_token = os.environ.get('WS_SCOPE_PROJ')
#     sbom_generator.parse_args.return_value.ws_url = 'saas'
#     sbom_generator.parse_args.return_value.type = 'tv'
#     sbom_generator.parse_args.return_value.extra = os.path.join(os.getcwd(), 'sbom_report/sbom_extra.json')
#     sbom_generator.parse_args.return_value.out_dir = '.'

# @patch('sbom_generator.args.ws_conn.get_scope_by_token', return_value= {})
# def test_create_sbom_doc_project():
#
#     returned = sbom_generator.create_sbom_doc("PROJECT_TOKEN")
#
#     assert returned == "PATH_TO_REPORT"


def test_get_document_relationships():
    doc_spdx_id = "SPDX-DOC_ID"
    expected = [relationship.Relationship(relationship=f"SPDX-PKG_ID1 {relationship.RelationshipType.DESCRIBED_BY.name} {doc_spdx_id}"),
                relationship.Relationship(relationship=f"SPDX-PKG_ID2 {relationship.RelationshipType.DESCRIBED_BY.name} {doc_spdx_id}")]
    pkgs_spdx_ids = ["SPDX-PKG_ID1", "SPDX-PKG_ID2"]
    returned = sbom_generator.get_document_relationships(pkgs_spdx_ids, doc_spdx_id)

    assert returned == expected


def test_create_document():
    doc_spdx_id = "SPDXRef-DOCUMENT"
    returned = sbom_generator.create_document(doc_spdx_id, "NAMESPACE")

    assert (doc_spdx_id == returned[1] and isinstance(returned[0], document.Document))


def test_create_creation_info():
    org_name = "ORG_NAME"
    org_email = "ORG_EMAIL"
    person_name = "PERSON_NAME"
    person_email = "PERSON_EMAIL"
    returned = sbom_generator.create_creation_info(org_name, org_email, person_name, person_email)

    assert isinstance(returned, creationinfo.CreationInfo)


def test_create_packages():
    libs = []
    due_dil = []
    lib_hierarchy = []
    returned = sbom_generator.create_packages(libs, due_dil, lib_hierarchy)

    assert returned[0] == [] and returned[1] == [] and returned[2] == []


@patch('sbom_generator.sbom_generator.get_author_from_cr', return_value="AUTHOR")
def test_create_package(mock_get_author_from_cr):
    lib = {'name': "NAME",
           'filename': "FILENAME",
           'sha1': "SHA1",
           'licenses': [{'name': "LIC1"}],
           'copyrightReferences': []}
    dd_dict = {("FILENAME", "LIC1"): {}}
    lib_hierarchy_dict = {}
    returned = sbom_generator.create_package(lib, dd_dict, lib_hierarchy_dict)

    assert isinstance(returned[0], package.Package) and returned[1] == "SPDXRef-PACKAGE-FILENAME" and returned[2] == []


if __name__ == '__main__':
    pytest.main()
