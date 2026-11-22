"""Domain input handling: shared-fixture table, API behavior, batch, payload limits."""

import json
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from backend.src.domain_validation import DomainError, MESSAGES, normalize_and_validate
from backend.tests.test_api import mock_model_artifacts  # noqa: F401  (autouse fixture)

CASES = json.loads((Path(__file__).resolve().parents[2] / "shared" / "domain_cases.json").read_text("utf-8"))


def _id(case):
    return repr(case["input"][:40])


@pytest.mark.parametrize("case", CASES, ids=_id)
def test_fixture_cases(case):
    if case["code"]:
        with pytest.raises(DomainError) as exc:
            normalize_and_validate(case["input"])
        assert exc.value.code == case["code"]
        assert exc.value.message == MESSAGES[case["code"]]
        return
    info = normalize_and_validate(case["input"])
    assert info.ascii == case["ascii"]
    assert info.display == case["display"]
    assert info.notes == case["notes"]
    assert info.warnings == case["warnings"]


def test_fixture_covers_every_code():
    codes = {c["code"] for c in CASES if c["code"]}
    assert codes >= set(MESSAGES) - {"EMPTY_BATCH", "TOO_MANY_DOMAINS"}


def test_registrable_fields():
    i = normalize_and_validate("a.b.foo.co.uk")
    assert (i.registrable_domain, i.subdomain_depth) == ("foo.co.uk", 2)
    i = normalize_and_validate("user.github.io")
    assert i.registrable_domain == "user.github.io" and "PRIVATE_SUFFIX" in i.warnings
    assert normalize_and_validate("xn--mller-kva.de").is_punycode


@pytest.mark.parametrize("d", ["a.com", "1.com", "12345.com", "xn--80a.com", "co.uk", "xn--mller-kva.de"])
def test_feature_extraction_does_not_crash(d):
    from backend.src.features import extract_features

    assert extract_features(d)["length"] >= 1


@pytest.fixture
def client():
    from backend.src.api.main import app

    return TestClient(app)


def test_single_422_body_shape(client):
    r = client.post("/predict", json={"domain": "<script>a@b.com"})
    assert r.status_code == 422
    b = r.json()
    assert set(b) == {"code", "message", "input"}
    assert b["code"] == "EMAIL_ADDRESS"
    assert "<" not in b["input"] and ">" not in b["input"]


def test_single_null_byte_escaped(client):
    r = client.post("/predict", json={"domain": "a\u0000b.com"})
    assert r.status_code == 422 and "\x00" not in r.text and r.json()["code"] == "INVALID_CHARACTER"


def test_single_success_adds_fields(client):
    r = client.post("/predict", json={"domain": "HTTPS://Müller.de:443/x"})
    assert r.status_code == 200
    p = r.json()["prediction"]
    assert p["domain"] == "müller.de" and p["ascii"] == "xn--mller-kva.de"
    assert p["original"] == "HTTPS://Müller.de:443/x"
    assert "EXTRACTED_FROM_URL" in p["notes"] and p["is_punycode"] is True


def test_underscore_is_warning(client):
    r = client.post("/predict", json={"domain": "_dmarc.mysite.com"})
    assert r.status_code == 200 and "UNDERSCORE" in r.json()["prediction"]["warnings"]


def test_batch_mixed_and_dedup(client):
    r = client.post(
        "/predict/batch",
        json={"domains": ["google.com", "bad..com", "GOOGLE.com.", "127.0.0.1", "xn--mller-kva.de", "müller.de"]},
    )
    assert r.status_code == 200
    b = r.json()
    assert b["total"] == 2 and len(b["predictions"]) == 2
    assert b["duplicates_removed"] == 2
    status = [(x["status"], (x["error"] or {}).get("code")) for x in b["results"]]
    assert status == [
        ("ok", None), ("error", "EMPTY_LABEL"), ("error", "DUPLICATE"),
        ("error", "IS_IP_ADDRESS"), ("ok", None), ("error", "DUPLICATE"),
    ]
    assert b["results"][0]["prediction"]["domain"] == "google.com"


def test_batch_limits(client):
    assert client.post("/predict/batch", json={"domains": []}).json()["code"] == "EMPTY_BATCH"
    r = client.post("/predict/batch", json={"domains": [f"d{i}.com" for i in range(101)]})
    assert r.status_code == 422 and r.json()["code"] == "TOO_MANY_DOMAINS"
    r = client.post("/predict/batch", json={"domains": [f"d{i}.com" for i in range(100)]})
    assert r.status_code == 200


def test_large_payload_rejected(client):
    r = client.post("/predict", json={"domain": "a" * 200_000})
    assert r.status_code == 413 and r.json()["code"] == "PAYLOAD_TOO_LARGE"
    r = client.post("/predict/batch", content=b'{"domains": ["' + b"a" * 200_000 + b'.com"]}',
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_invalid_input_not_logged_above_debug(client, caplog):
    import logging

    with caplog.at_level(logging.INFO):
        client.post("/predict", json={"domain": "secret@@weird"})
    assert "secret" not in caplog.text
