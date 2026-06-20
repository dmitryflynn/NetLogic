"""Tests for the reality-wrapper JSON robustness (src/fusion/ai.py). Offline."""

from src.fusion.ai import robust_json_array


def test_plain_array():
    assert robust_json_array('[{"id":0,"verdict":"real"}]') == [{"id": 0, "verdict": "real"}]


def test_strips_json_code_fence():
    text = '```json\n[{"id":1,"verdict":"false_positive"}]\n```'
    assert robust_json_array(text) == [{"id": 1, "verdict": "false_positive"}]


def test_strips_bare_code_fence():
    assert robust_json_array('```\n[{"id":2}]\n```') == [{"id": 2}]


def test_extracts_array_from_surrounding_prose():
    text = 'Sure, here is the result:\n[{"id":0,"verdict":"uncertain"}]\nLet me know if you need more.'
    assert robust_json_array(text) == [{"id": 0, "verdict": "uncertain"}]


def test_tolerates_trailing_commas():
    text = '[{"id":0,"verdict":"real",},{"id":1,"verdict":"false_positive",},]'
    out = robust_json_array(text)
    assert out is not None and len(out) == 2 and out[1]["id"] == 1


def test_returns_none_on_garbage():
    assert robust_json_array("the model refused to answer") is None
    assert robust_json_array("") is None
    assert robust_json_array("{not even an array}") is None


def test_object_not_array_is_rejected():
    # We require an array; a bare object is not a valid adjudication response.
    assert robust_json_array('{"id":0,"verdict":"real"}') is None
