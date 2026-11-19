from __future__ import annotations

import dataclasses
import re

import pytest

from dtls_interop import scenarios
from dtls_interop.implementations import REPO_ROOT
from dtls_interop.scenarios import EMPTY_KEY_SHARE, SCENARIOS, Impairment, Transport

KNOWN_GROUPS = {
    scenarios.X25519,
    scenarios.X25519MLKEM768,
    scenarios.MLKEM512X25519,
    scenarios.SECP256R1MLKEM768,
}


def _matrix_table() -> dict[str, str]:
    text = (REPO_ROOT / "docs" / "test-matrix.md").read_text()
    rows = re.findall(r"^\| ([ST]\d\d) \| (.+?) \|", text, flags=re.MULTILINE)
    return {sid: description.replace("`", "") for sid, description in rows}


def test_ids_and_descriptions_match_test_matrix_doc():
    assert {s.id: s.description for s in SCENARIOS} == _matrix_table()


def test_ids_are_unique():
    ids = [s.id for s in SCENARIOS]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_scenario_is_consistent(scenario):
    client, server = scenario.client, scenario.server
    assert set(client.groups) <= KNOWN_GROUPS
    assert set(server.groups) <= KNOWN_GROUPS
    assert client.key_share == EMPTY_KEY_SHARE or client.key_share in client.groups
    assert client.mtu == server.mtu == scenario.path.pmtu
    if scenario.expected.group is not None:
        assert scenario.expected.group in set(client.groups) & set(server.groups)
    assert scenario.expected.version == (
        "DTLSv1.3" if scenario.transport is Transport.DTLS else "TLSv1.3"
    )


def test_scenarios_are_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        SCENARIOS[0].id = "X"  # type: ignore[misc]


def test_impairments_only_where_the_matrix_says():
    impaired = {s.id: s.path.impairments for s in SCENARIOS if s.path.impairments}
    assert impaired == {
        "S08": (Impairment.REORDER_CH1,),
        "S09": (Impairment.DROP_FIRST_CH1_FRAGMENT,),
    }


def test_hrr_scenarios():
    # Cookie validation, an empty share and a wrong guess all force a HelloRetryRequest.
    hrr = {s.id for s in SCENARIOS if s.expected.hrr}
    assert hrr == {"S04", "S05", "S06", "S07", "S08", "S09", "S10", "T01"}


def test_get_is_case_insensitive_and_rejects_unknown():
    assert scenarios.get("s03").id == "S03"
    with pytest.raises(KeyError, match="unknown scenario 'S99'"):
        scenarios.get("S99")
