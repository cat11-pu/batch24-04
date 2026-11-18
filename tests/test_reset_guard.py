import threading
import time

import pytest

import reset_guard as rg


def test_1_token_has_enough_entropy():
    token = rg.create_reset_token("alice")
    assert len(token) >= 32


def test_2_token_is_not_numeric():
    token = rg.create_reset_token("alice")
    assert not token.isdigit()


def test_3_tokens_are_unique(monkeypatch):
    monkeypatch.setattr(rg.random, "randint", lambda _a, _b: 123456)
    first = rg.create_reset_token("alice")
    second = rg.create_reset_token("alice")
    assert first != second


def test_4_expired_token_is_rejected(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1000.0)
    token = rg.create_reset_token("alice", ttl=1)
    monkeypatch.setattr(time, "time", lambda: 1010.0)
    assert rg.validate_reset_token(token) is False


def test_5_token_is_bound_to_user():
    token = rg.create_reset_token("alice")
    assert rg.validate_reset_token(token, "bob") is False


def test_6_token_cannot_be_used_twice():
    token = rg.create_reset_token("alice")
    assert rg.validate_reset_token(token) is True
    assert rg.validate_reset_token(token) is False


def test_7_consume_invalidates_token():
    token = rg.create_reset_token("alice")
    rg.consume_reset_token(token, "new-password-123")
    assert rg.validate_reset_token(token) is False


def test_8_short_password_is_rejected():
    token = rg.create_reset_token("alice")
    with pytest.raises(ValueError):
        rg.consume_reset_token(token, "short")


def test_9_common_password_is_rejected():
    token = rg.create_reset_token("alice")
    with pytest.raises(ValueError):
        rg.consume_reset_token(token, "password")


def test_10_invalidate_user_tokens_removes_all():
    tokens = [rg.create_reset_token("alice") for _ in range(3)]
    rg.invalidate_user_tokens("alice")
    assert all(rg.validate_reset_token(token) is False for token in tokens)


def test_11_empty_user_is_rejected():
    with pytest.raises(ValueError):
        rg.create_reset_token("")


def test_12_non_string_user_is_rejected():
    with pytest.raises(TypeError):
        rg.create_reset_token(123)


def test_13_non_positive_ttl_is_rejected():
    with pytest.raises(ValueError):
        rg.create_reset_token("alice", 0)


def test_14_expired_token_is_removed():
    token = rg.create_reset_token("alice", ttl=1)
    rg.RESET_TOKENS[token]["expires"] = 0
    rg.validate_reset_token(token)
    assert token not in rg.RESET_TOKENS


def test_15_concurrent_consume_only_one_succeeds():
    token = rg.create_reset_token("alice")
    results = []

    def worker():
        results.append(rg.consume_reset_token(token, "new-password-123"))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(True) == 1
