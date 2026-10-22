"""The management commands: the documented way to create an administrator, recover an account, and
run housekeeping by hand. None of them had a test."""

import json
import sys

import pytest
from sqlalchemy import select

from app import cli
from app.core.config import settings
from app.core.security import verify_password
from app.models import AuditLog, RecoveryCode, User
from app.models.base import utcnow
from tests.conftest import PASSWORD, make_user


def run(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["guardiano", *argv])
    cli.main()


def _user(db, email):
    db.expire_all()
    return db.scalar(select(User).where(User.email == email))


def test_create_admin_asks_for_the_password(db, monkeypatch, capsys):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "a-long-enough-password")
    run(monkeypatch, "create-admin", "Root@Example.test")
    user = _user(db, "root@example.test")
    assert user.role == "admin" and verify_password("a-long-enough-password", user.password_hash)
    assert "ready" in capsys.readouterr().out


def test_create_admin_refuses_a_short_password(db, monkeypatch):
    with pytest.raises(SystemExit):
        run(monkeypatch, "create-admin", "root@example.test", "--password", "short")
    assert _user(db, "root@example.test") is None


def test_create_admin_recovers_an_existing_locked_out_account(db, monkeypatch):
    """The way back in for an administrator: promoted, reactivated, other sessions signed out, and
    no longer locked out by whoever was guessing their password."""
    user = make_user(db, "someone@test.io", "viewer")
    user.is_active, user.failed_logins, user.locked_until = False, 12, utcnow().replace(year=2099)
    version = user.token_version
    db.commit()

    run(monkeypatch, "create-admin", "someone@test.io", "--password", "a-brand-new-password")
    user = _user(db, "someone@test.io")
    assert (user.role, user.is_active) == ("admin", True)
    assert user.token_version == version + 1
    assert user.locked_until is None and user.failed_logins == 0


def test_reset_mfa_clears_the_second_factor(db, monkeypatch):
    user = make_user(db, "phone-lost@test.io", "analyst")
    user.mfa_enabled, user.mfa_secret = True, "encrypted"
    db.add(RecoveryCode(user_id=user.id, code_hash="x" * 64))
    db.commit()
    run(monkeypatch, "reset-mfa", "phone-lost@test.io")
    user = _user(db, "phone-lost@test.io")
    assert not user.mfa_enabled and user.mfa_secret is None
    assert db.scalars(select(RecoveryCode).where(RecoveryCode.user_id == user.id)).all() == []


def test_reset_mfa_for_an_unknown_account_fails(monkeypatch):
    with pytest.raises(SystemExit) as exit_:
        run(monkeypatch, "reset-mfa", "nobody@test.io")
    assert "No account" in str(exit_.value.code)


def test_prune_does_nothing_without_a_rule(monkeypatch, capsys):
    run(monkeypatch, "prune")
    assert "No retention rule is configured" in capsys.readouterr().out


def test_a_dry_run_prune_changes_nothing(db, monkeypatch):
    from datetime import timedelta

    monkeypatch.setattr(settings, "retention_audit_days", 30)
    db.add(AuditLog(action="user.create", created_at=utcnow() - timedelta(days=90)))
    db.commit()
    run(monkeypatch, "prune", "--dry-run")
    db.expire_all()
    assert len(db.scalars(select(AuditLog)).all()) == 1
    run(monkeypatch, "prune")
    db.expire_all()
    assert db.scalars(select(AuditLog)).all() == []


def test_demo_data_is_refused_in_production(monkeypatch):
    monkeypatch.setattr(settings, "env", "production")
    with pytest.raises(SystemExit) as exit_:
        run(monkeypatch, "seed-demo")
    assert "Refusing" in str(exit_.value.code)


def test_bootstrap_creates_the_first_admin_once(db, monkeypatch):
    monkeypatch.setattr(settings, "guardiano_admin_email", "first@test.io")
    monkeypatch.setattr(settings, "guardiano_admin_password", PASSWORD)
    run(monkeypatch, "bootstrap")
    run(monkeypatch, "bootstrap")  # idempotent: the users table is no longer empty
    assert [u.email for u in db.scalars(select(User))] == ["first@test.io"]


def test_openapi_writes_the_schema(tmp_path, monkeypatch):
    out = tmp_path / "openapi.json"
    run(monkeypatch, "openapi", str(out))
    assert "/api/v1/findings" in json.loads(out.read_text())["paths"]


def test_demo_seed_does_not_print_credentials(db, monkeypatch, capsys):
    from app.services import seed

    monkeypatch.setattr(seed, "ASSETS", [])
    seed.seed_demo(db)
    output = capsys.readouterr().out
    assert "Demo data loaded" in output
    assert seed.DEMO_PASSWORD not in output
    assert all(email not in output for email, *_ in seed.DEMO_USERS)
