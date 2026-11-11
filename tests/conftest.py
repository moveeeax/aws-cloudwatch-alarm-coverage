import copy
import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name):
    with open(FIXTURES / name, encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture
def account():
    """The reference account payload, copied so a test can mutate it freely."""
    return copy.deepcopy(load_fixture("account.json"))


@pytest.fixture
def fixtures_dir():
    return FIXTURES
