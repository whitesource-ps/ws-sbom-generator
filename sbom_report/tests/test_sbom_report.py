import os
import unittest
from unittest import TestCase
from unittest.mock import MagicMock

from sbom_report import sbom_report


class SbomReportTest(TestCase):
    user_key = os.environ.get('WS_USER_KEY')
    ws_token = os.environ.get('WS_SCOPE_PROJ')
    sbom_report.parse_args = MagicMock()

    def setUp(self) -> None:
        self.maxDiff = 2147483648

    def test_main(self):
        ret = sbom_report.main()
        compared = get_compared_file(ret[1])

        self.assertEqual(compared, ret[0])


def get_compared_file(filename):
    path = f'examples/{filename}'
    with open(path, 'r') as fp:
        return fp.read()


if __name__ == '__main__':
    unittest.main()
