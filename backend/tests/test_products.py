"""Products group assets; environments say where they run. Both filter, and neither widens scope."""

import pytest

from app.models import Asset, Team
from app.services.ingestion import IngestOptions, ingest_report
from tests.conftest import sample


@pytest.fixture
def checkout(client, auth, db):
    r = client.post("/api/v1/products", json={"name": "Checkout", "description": "Buying things"},
                    headers=auth["manager"])  # fmt: skip
    assert r.status_code == 201, r.text
    product = r.json()
    team = Team(name="payments", description="")
    db.add(team)
    db.flush()
    api = Asset(name="checkout-api", tags=[], product_id=product["id"], environment="production")
    web = Asset(name="checkout-web", tags=[], product_id=product["id"], environment="staging")
    hidden = Asset(name="checkout-ledger", tags=[], product_id=product["id"], team_id=team.id)
    other = Asset(name="blog", tags=[])
    db.add_all([api, web, hidden, other])
    db.commit()
    for a in (api, web, hidden, other):
        ingest_report(db, sample("osv.json"), a, None, IngestOptions())
    return product


def test_a_product_counts_only_what_you_can_see(client, auth, checkout):
    (p,) = client.get("/api/v1/products", headers=auth["viewer"]).json()
    assert (p["name"], p["assets"], p["open_total"]) == ("Checkout", 2, 4)
    (everything,) = client.get("/api/v1/products", headers=auth["admin"]).json()
    assert everything["assets"] == 3


def test_filters_by_product_and_environment(client, auth, checkout):
    def names(path, **params):
        items = client.get(path, params=params, headers=auth["viewer"]).json()["items"]
        return {i["asset"]["name"] if "asset" in i else i["name"] for i in items}

    assert names("/api/v1/findings", product_id=checkout["id"]) == {"checkout-api", "checkout-web"}
    assert names("/api/v1/findings", environment="production") == {"checkout-api"}
    assert names("/api/v1/assets", product_id=checkout["id"]) == {"checkout-api", "checkout-web"}
    assert names("/api/v1/assets", environment="staging") == {"checkout-web"}


def test_assets_join_and_leave_products(client, auth, db, checkout):
    blog = db.query(Asset).filter_by(name="blog").one()
    r = client.patch(f"/api/v1/assets/{blog.id}", json={"product_id": checkout["id"], "environment": "test"},
                     headers=auth["manager"])  # fmt: skip
    assert r.status_code == 200 and r.json()["environment"] == "test"
    assert client.patch(f"/api/v1/assets/{blog.id}", json={"product_id": 999999},
                        headers=auth["manager"]).status_code == 422  # fmt: skip

    assert client.delete(f"/api/v1/products/{checkout['id']}", headers=auth["manager"]).status_code == 204
    db.expire_all()
    assert db.get(Asset, blog.id).product_id is None, "the assets stay, ungrouped"


def test_managing_products(client, auth, checkout):
    assert client.post("/api/v1/products", json={"name": "x"}, headers=auth["analyst"]).status_code == 403
    same = {"name": "checkout"}  # names are unique whatever their case
    assert client.post("/api/v1/products", json=same, headers=auth["manager"]).status_code == 409
    renamed = {"name": "Checkout v2"}
    r = client.patch(f"/api/v1/products/{checkout['id']}", json=renamed, headers=auth["manager"])
    assert r.json()["name"] == "Checkout v2"
