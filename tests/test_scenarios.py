from __future__ import annotations

import dataclasses
import re

import pytest

from dtls_interop import scenarios
from dtls_interop.implementations import REPO_ROOT
from dtls_interop.scenarios import EMPTY_KEY_SHARE, SCENARIOS, Impairment, Transport, Validate

KNOWN_GROUPS = {
    scenarios.X25519,
    scenarios.X25519MLKEM768,
    scenarios.MLKEM512X25519,
    scenarios.SECP256R1MLKEM768,
}


def _matrix_table() -> dict[str, str]:
    text = (REPO_ROOT / "docs" / "test-matrix.md").read_text()
    rows = re.findall(r"^\| ([ST]\d\d(?:\+split)?) \| (.+?) \|", text, flags=re.MULTILINE)
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
    if scenario.path.split_ch1 is None:
        assert client.mtu == server.mtu == scenario.path.pmtu
    else:
        assert client.mtu == scenario.path.pmtu
    if scenario.expected.group is not None:
        assert scenario.expected.group in set(client.groups) & set(server.groups)
    exp = scenario.expected
    if exp.hrr is False:
        assert exp.hrr_cookie is False and exp.hrr_group is False
    if scenario.server.validate is Validate.COOKIE:
        assert exp.hrr is True and exp.hrr_cookie is True
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
        "S08+split": (Impairment.REORDER_CH1,),
        "S09+split": (Impairment.DROP_FIRST_CH1_FRAGMENT,),
    }


def test_split_rows_change_only_the_mtu_path_and_ch1_expectation():
    split = [s for s in SCENARIOS if s.path.split_ch1 is not None]
    assert [s.id for s in split] == ["S03+split", "S04+split", "S08+split", "S09+split"]
    for s in split:
        base = scenarios.get(s.id.removesuffix("+split"))
        assert base.expected.ch1_fragmented is True and base.path.split_ch1 is None
        assert s.path == dataclasses.replace(base.path, pmtu=1500, split_ch1=2)
        assert s.client == dataclasses.replace(base.client, mtu=1500)
        assert s.server == dataclasses.replace(base.server, mtu=1500)
        assert s.expected.ch1_fragmented is None
        assert dataclasses.replace(s.expected, summary="", ch1_fragmented=True) == (
            dataclasses.replace(base.expected, summary="")
        )


def test_hrr_scenarios():
    # Cookie validation, an empty share and a wrong guess all force a HelloRetryRequest.
    hrr = {s.id for s in SCENARIOS if s.expected.hrr}
    base = {"S04", "S05", "S06", "S07", "S08", "S09", "S10", "T01"}
    assert hrr == base | {"S04+split", "S08+split", "S09+split"}


def test_get_is_case_insensitive_and_rejects_unknown():
    assert scenarios.get("s03").id == "S03"
    assert scenarios.get("s03+SPLIT").id == "S03+split"
    with pytest.raises(KeyError, match="unknown scenario 'S99'"):
        scenarios.get("S99")
