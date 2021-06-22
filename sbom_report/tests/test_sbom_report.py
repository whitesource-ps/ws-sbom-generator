import os
import unittest
from unittest import TestCase
from unittest.mock import MagicMock

from sbom_report import sbom_report


class SbomReportTest(TestCase):
    ws_token = os.environ.get('WS_SCOPE_PROJ')
    sbom_report.parse_args = MagicMock()
    sbom_report.parse_args.return_value.ws_user_key = os.environ.get('WS_USER_KEY')
    sbom_report.parse_args.return_value.ws_token = os.environ.get('WS_SCOPE_ORG')
    sbom_report.parse_args.return_value.scope_token = os.environ.get('WS_SCOPE_PROJ')
    sbom_report.parse_args.return_value.ws_url = 'saas'
    sbom_report.parse_args.return_value.type = 'tv'
    sbom_report.parse_args.return_value.extra = os.path.join(os.getcwd(), 'sbom_report/sbom_extra.json')
    sbom_report.parse_args.return_value.out_dir = '.'

    def setUp(self) -> None:
        self.maxDiff = 2147483648

    def test_main(self):
        ret = sbom_report.main()
        compared_file = get_file(f'examples/{os.path.split(ret)[1]}')
        created_file = get_file(ret)
        import re
        expr = r'Created:\ .*'
        compared_str = re.sub(expr, '', compared_file)
        created_str = re.sub(expr, '', created_file)

        self.assertEqual(compared_str, created_str)


def get_file(file_path):
    with open(file_path, 'r') as fp:
        return fp.read()


if __name__ == '__main__':
    unittest.main()
