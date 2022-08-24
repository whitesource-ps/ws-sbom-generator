import datetime
import json
import re
import base64


def extract_email(input_str: str):
    try:
        match = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', input_str)
        return match.group(0), re.search(r':(.+?) \(', input_str).group(1)
    except:
        return "no@email.com", input_str


class CycloneDx:
    def __init__(self, sbom_json, _ver):
        self.doc = sbom_json
        self.ts = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        self._ver = _ver
        self.bom = {
            "bomFormat": "CycloneDX",
            "specVersion": f"{self._ver}",
            "version": 1,
            "metadata": self.prepare_metadata(),
            "components": self.prepare_components()
        }

    def prepare_metadata(self):
        try:
            crt_org = extract_email(self.doc['creationInfo']['creators'][0])
        except:
            crt_org = ["no@email.com", ""]
        try:
            crt_tool = self.doc['creationInfo']['creators'][1]
        except:
            crt_tool = ["no@email.com", ""]
        try:
            crt_person = extract_email(self.doc['creationInfo']['creators'][2])
        except:
            crt_person = ["no@email.com", ""]

        meta_properties = [
            {
                "name": "spdx:spdxid",
                "value": "SPDXRef-DOCUMENT"
            },
            {
                "name": "spdx:document:spdx-version",
                "value": f"{self.doc['spdxVersion']}"
            },
            {
                "name": "spdx:document:name",
                "value": f"{self.doc['name']}"
            },
            {
                "name": "spdx:document:document-namespace",
                "value": f"{self.doc['documentNamespace']}"
            },
            {
                "name": "spdx:creation-info:creators-organization",
                "value": f"{crt_org[1]}"
            },
            {
                "name": "spdx:creation-info:license-list-version",
                "value": f"{self.doc['creationInfo']['licenseListVersion']}"
            }
        ]
        try:
            for doc_descr in self.doc['documentDescribes']:
                meta_properties.append({
                    "name": "spdx:document:describes",
                    "value": doc_descr
                })
        except:
            pass

        meta = {
            "timestamp": f"{self.ts}",
            "authors": [
                {
                    "name": f"{crt_org[1]}",
                    "email": f"{crt_org[0]}"
                },
                {
                    "name": f"{crt_person[1]}",
                    "email": f"{crt_person[0]}"
                }
            ],
            "properties": meta_properties
        }
        if crt_org[0] == "no@email.com":
            del meta['authors'][0]['email']
        if crt_person[0] == "no@email.com":
            del meta['authors'][1]['email']
        return meta

    def get_lic_from_file(self,lic_file, extra_lic):
        lic_text = ""
        comp = {}
        lics = []
        # for el_lic in lic_file:
        el_lic = lic_file.replace("SPDXRef-PACKAGE-", "LicenseRef-")  # Using FUll lib name from SPDXRef property
        for extra in extra_lic:
            if el_lic == extra['name']:
                lic_text = base64.b64encode(extra['extractedText'].encode('utf-8')).decode('utf-8')
                break
        if lic_text != "":
            lics.append(
                {
                    "license": {
                        "name": f"{extra['name']}",
                        "text": {
                            "contentType": "text/plain",
                            "encoding": "base64",
                            "content": f"{lic_text}"
                        }
                    }
                }
            )
        if lics:
            comp.update(
                {"evidence": {
                    "licenses": lics
                }
                })
        return comp

    def prepare_components(self):
        components = []
        for pkg in self.doc['packages']:
            hash_ = []
            try:
                for hsh in pkg['checksums']:
                    if hsh['checksumValue'] != "" and type(
                    hsh['checksumValue']).__name__ != "NoAssert":  # NoAssert is NOT JSON serializable type! :
                        hash_.append({
                            "alg": hsh['algorithm'] if hsh['algorithm'] != "SHA1" else "SHA-1",
                            "content": hsh['checksumValue']
                        })
            except:
                pass

            flag = True  # For Adding dynamically missed keys in tuple
            while flag:
                try:
                    comp = {
                        "type": "library",
                        "name": f"{pkg['name']}",
                        "hashes": hash_,
                        "licenses": [{
                            "expression": f"{pkg['licenseDeclared']}"
                        }],
                        "copyright": f"{pkg['copyrightText']}",
                        "externalReferences": [
                            {
                                "url": f"{pkg['downloadLocation']}",
                                "type": "distribution"
                            },
                            {
                                "url": f"{pkg['homepage']}",
                                "type": "website"
                            }
                        ],
                        "properties": [
                            {
                                "name": "spdx:spdxid",
                                "value": f"{pkg['SPDXID']}"
                            },
                            {
                                "name": "spdx:files-analyzed",
                                "value": f"{pkg['filesAnalyzed']}"
                            },
                            {
                                "name": "spdx:license-concluded",
                                "value": f"{pkg['licenseConcluded']}"
                            },
                            {
                                "name": "spdx:package:file-name",
                                "value": f"{pkg['packageFileName']}"
                            },
                            {
                                "name": "spdx:package:originator:organization",
                                "value": f"{extract_email(pkg['originator'])[1]}"
                            },
                            {
                                "name": "spdx:package:originator:email",
                                "value": f"{extract_email(pkg['originator'])[0]}"
                            },
                            {
                                "name": "spdx:package:supplier:organization",
                                "value": f"{pkg['supplier']}"
                            },
                            {
                                "name": "spdx:download-location",
                                "value": f"{pkg['downloadLocation']}"
                            },
                            {
                                "name": "spdx:homepage",
                                "value": f"{pkg['homepage']}"
                            }
                        ]
                    }
                    if comp['properties'][5]['value'] == "no@email.com":  # Just not keep empty emails fields
                        del comp['properties'][5]
                    flag = False
                except Exception as err:
                    pkg.update({err.args[0]: ""})
            try:
                version = pkg['versionInfo'] if pkg['versionInfo'] is not None else ""
            except:
                version = ""
            if version != "" and type(
                    pkg['versionInfo']).__name__ != "NoAssert":  # NoAssert is NOT JSON serializable type!
                comp.update({"version": version})

            try:
                # evidence = self.get_lic_from_file(pkg['licenseInfoFromFiles'], self.doc['hasExtractedLicensingInfos'])
                evidence = self.get_lic_from_file(pkg['SPDXID'], self.doc['hasExtractedLicensingInfos'])
                if evidence:
                    comp.update(evidence)
            except Exception as err:
                pass

            components.append(comp)

        return components

    def save_to_file(self, fname):
        try:
            with open(fname, 'w', encoding='utf-8') as outfile:
                json.dump(self.bom, outfile, indent=4)
        except Exception as err:
            print(err)
        return fname
