"""scripts/get-stalkerware-indicators.py writes the certificates the
AssoEchap list records for stalkerware to data/stalkerware-signers.csv."""

import csv
import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("yaml")

SCRIPT = (
    Path(__file__).resolve().parent.parent / "scripts" / "get-stalkerware-indicators.py"
)

IOC = """\
- name: VendorSpy
  type: stalkerware
  packages: [com.vendor.spy]
  certificates:
  - 31a6ececd97cf39bc4126b8745cd94a7c30bf81c
  - "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
  - not-a-fingerprint
- name: OtherSpy
  type: stalkerware
  certificates: [31A6ECECD97CF39BC4126B8745CD94A7C30BF81C]
- name: SomeWatch
  type: watchware
  certificates: [1111111111111111111111111111111111111111]
- name: NoCerts
  type: stalkerware
  packages: [com.nocerts]
"""


@pytest.fixture(scope="module")
def script():
    spec = importlib.util.spec_from_file_location("indicators", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_signers_are_parsed_and_normalised(script, tmp_path):
    ioc = tmp_path / "ioc.yaml"
    ioc.write_text(IOC)
    assert script.parse_signers(ioc) == {
        "31A6ECECD97CF39BC4126B8745CD94A7C30BF81C": "OtherSpy / VendorSpy",
        "AABBCCDDEEFF00112233445566778899AABBCCDD": "VendorSpy",
    }


def test_signers_file_is_sorted_and_loads(script, tmp_path, monkeypatch):
    out = tmp_path / "stalkerware-signers.csv"
    script.write_signers({"BB" * 20: "B", "AA" * 20: "A"}, out)
    with out.open() as f:
        rows = list(csv.reader(f))
    assert rows == [["sha1", "app"], ["AA" * 20, "A"], ["BB" * 20, "B"]]
    from isdi.scanner import blocklist

    assert blocklist._load_signers(out) == {"AA" * 20: "A", "BB" * 20: "B"}
    assert blocklist._load_signers(tmp_path / "missing.csv") == {}
