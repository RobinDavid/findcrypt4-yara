import yara
import lief
from pathlib import Path
from typing import TYPE_CHECKING
from dataclasses import dataclass

__version__ = 0.4

if TYPE_CHECKING:
    from yara import Rules, Match, StringMatch, StringMatchInstance

RULES_DIR = Path(__file__).parent / "rules"

RULES = None


def _load_rules():
    global RULES, RULES_DIR
    # TODO: Load rules in the directory
    rules_filepaths = {}
    for file in RULES_DIR.iterdir():
        rules_filepaths[file.with_suffix("").name] = str(file)
    RULES = yara.compile(filepaths=rules_filepaths)


def add_rule(rule_file: str) -> bool:
    in_file = Path(rule_file)
    out_file = RULES_DIR / in_file.name
    if out_file.exists():  # the file already exists
        return False
    else:
        out_file.write_bytes(in_file.read_bytes())
        return True


@dataclass
class CryptoMatch:
    offset: int
    data: bytes
    identifier: str  # string identifier (label) within the rule
    namespace: str   # rule namespace
    rule: str        # rule name


def search(data: bytes) -> list[CryptoMatch]:
    # If rules are not loaded load them
    if RULES is None:
        _load_rules()

    values = list()
    matches = RULES.match(data=data)

    for match in matches:  # Match object
        for string in match.strings:  # StringMatch object
            for instance in string.instances:  # StringMatchInstance object
                cmatch = CryptoMatch(instance.offset,
                                     instance.matched_data,
                                     string.identifier,
                                     match.namespace,
                                     match.rule)
                values.append(cmatch)
    return values


@dataclass
class ExeCryptoMatch(CryptoMatch):
    address: int

def file_search(filepath: str) -> list[CryptoMatch|ExeCryptoMatch]:
    content = Path(filepath).read_bytes()
    try:
        p = lief.parse(filepath)
        if p is None:
            return search(content)
        else:
            return [ExeCryptoMatch(x.offset,
                                   x.data,
                                   x.identifier,
                                   x.namespace,
                                   x.rule,
                                   p.offset_to_virtual_address(x.offset)) for x in search(content)]
    except:
        return search(content)
