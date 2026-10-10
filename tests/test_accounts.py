"""Account records, Fernet-encrypted secrets, temporary credential parsing and log redaction.

Fake credentials only."""

import json
import logging
from datetime import UTC, datetime, timedelta

import pytest

from rolelens.accounts import AccountStore, MemoryVault, parse_temporary_credentials
from rolelens.crypto import SecretBox
from rolelens.logging_setup import configure_logging, read_log, redact

FAKE_KEY_ID = "AKIAEXAMPLEEXAMPLE00"
FAKE_TEMP_KEY_ID = "ASIAEXAMPLEEXAMPLE00"
FAKE_SECRET = "example/secret/value/for/tests/only/0000"
FAKE_SESSION_TOKEN = "FakeSessionTokenForTestsOnly0000000000000000000000Example"


@pytest.fixture
def store(db_path, tmp_path):
    return AccountStore(db_path, SecretBox.from_path(tmp_path / "secret.key"), MemoryVault())


def test_secret_box_key_from_env(monkeypatch, tmp_path):
    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    monkeypatch.setenv("ROLELENS_SECRET_KEY", key.decode())
    box = SecretBox.from_path(tmp_path / "unused.key")
    assert not (tmp_path / "unused.key").exists()
    assert SecretBox(key).decrypt(box.encrypt("value")) == "value"
    assert "redacted" in repr(box)


def test_key_file_is_private(tmp_path):
    SecretBox.from_path(tmp_path / "secret.key")
    assert (tmp_path / "secret.key").stat().st_mode & 0o777 == 0o600


def test_keys_are_encrypted_and_blank_fields_keep_them(store, db_path):
    acct_id = store.save(
        None,
        display_name="example",
        region="us-east-1",
        auth_mode="keys",
        access_key_id=FAKE_KEY_ID,
        secret_access_key=FAKE_SECRET,
    )
    assert FAKE_SECRET.encode() not in db_path.read_bytes()
    store.save(acct_id, display_name="renamed", region="us-east-1", auth_mode="keys")
    acct = store.get(acct_id, with_secret=True)
    assert (acct.display_name, acct.secret_access_key) == ("renamed", FAKE_SECRET)
    public = json.dumps(acct.public_dict())
    assert FAKE_SECRET not in public and FAKE_KEY_ID not in public
    # switching to a mode without secrets drops them
    store.save(acct_id, display_name="renamed", region="us-east-1", auth_mode="env")
    assert store.get(acct_id, with_secret=True).secret_access_key == ""


def test_memory_only_credentials_are_never_written(store, db_path):
    expires = (datetime.now(UTC) + timedelta(hours=1)).isoformat(timespec="seconds")
    paste = json.dumps(
        {
            "Credentials": {
                "AccessKeyId": FAKE_TEMP_KEY_ID,
                "SecretAccessKey": FAKE_SECRET,
                "SessionToken": FAKE_SESSION_TOKEN,
                "Expiration": expires,
            }
        }
    )
    acct_id = store.save(
        None,
        display_name="",
        region="us-east-1",
        auth_mode="temporary",
        paste=paste,
        memory_only=True,
    )
    for path in db_path.parent.glob(db_path.name + "*"):
        data = path.read_bytes()
        assert FAKE_SECRET.encode() not in data and FAKE_SESSION_TOKEN.encode() not in data
    acct = store.get(acct_id, with_secret=True)
    assert acct.session_token == FAKE_SESSION_TOKEN
    assert acct.status_text().startswith("expires in")


@pytest.mark.parametrize(
    "text",
    [
        f"{FAKE_TEMP_KEY_ID} {FAKE_SECRET} {FAKE_SESSION_TOKEN}",
        f"export AWS_ACCESS_KEY_ID={FAKE_TEMP_KEY_ID}\n"
        f"export AWS_SECRET_ACCESS_KEY={FAKE_SECRET}\n"
        f'export AWS_SESSION_TOKEN="{FAKE_SESSION_TOKEN}"',
    ],
)
def test_parse_temporary_credentials(text):
    creds = parse_temporary_credentials(text)
    assert (creds.access_key_id, creds.secret_access_key, creds.session_token) == (
        FAKE_TEMP_KEY_ID,
        FAKE_SECRET,
        FAKE_SESSION_TOKEN,
    )


def test_parse_errors_never_echo_the_input():
    with pytest.raises(ValueError) as exc:
        parse_temporary_credentials(f"{FAKE_TEMP_KEY_ID} {FAKE_SECRET}")
    assert FAKE_SECRET not in str(exc.value)


def test_log_redaction(tmp_path):
    assert "[REDACTED-KEY-ID]" in redact(f"key {FAKE_KEY_ID}")
    assert FAKE_SECRET not in redact(f"secret={FAKE_SECRET}")
    configure_logging(tmp_path)
    logging.getLogger("rolelens.test").warning("token: %s", FAKE_SESSION_TOKEN)
    entries = read_log(tmp_path)
    assert entries and FAKE_SESSION_TOKEN not in entries[0]["msg"]
