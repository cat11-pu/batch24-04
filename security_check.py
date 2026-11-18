"""Extra security verification for reset_guard.

Run: python3 security_check.py
Exits non-zero if any invariant is violated.
"""

import random
import string
import threading
import time
import uuid

import reset_guard as rg


GOOD_PASSWORD = "Sup3r-Secret!"


def _reset_state():
    with rg._lock:
        rg.RESET_TOKENS.clear()


def _random_guess(rng):
    length = rng.randint(0, 80)
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(rng.choice(alphabet) for _ in range(length))


def check_randomized_fuzz(rounds=1000):
    rng = random.Random(20261119)
    _reset_state()
    for _ in range(rounds):
        user = "user-" + uuid.UUID(int=rng.getrandbits(128), version=4).hex
        ttl = rng.randint(1, 3600)
        token_a = rg.create_reset_token(user, ttl=ttl)
        token_b = rg.create_reset_token(user)
        assert len(token_a) >= 32 and not token_a.isdigit()
        assert token_a != token_b

        # Guessed / malformed tokens never resolve to a valid record.
        for _ in range(8):
            guess = _random_guess(rng)
            assert rg.validate_reset_token(guess, user) is False
            assert rg.validate_reset_token(guess) is False
            assert rg.consume_reset_token(guess, GOOD_PASSWORD) is False

        # Token is bound to its user; another user cannot consume it.
        stranger = "stranger-" + uuid.UUID(int=rng.getrandbits(128), version=4).hex
        assert rg.validate_reset_token(token_b, stranger) is False

        if rng.random() < 0.5:
            # Validation path: single use, then invalid.
            assert rg.validate_reset_token(token_a, user) is True
            assert rg.validate_reset_token(token_a, user) is False
            assert token_a not in rg.RESET_TOKENS
            # Password change via consume invalidates every token of the user.
            assert rg.consume_reset_token(token_b, GOOD_PASSWORD) is True
            assert rg.consume_reset_token(token_b, GOOD_PASSWORD) is False
        else:
            # Consume path: one success, replay fails, sibling token dies too.
            assert rg.consume_reset_token(token_a, GOOD_PASSWORD) is True
            assert rg.validate_reset_token(token_a, user) is False
            assert rg.validate_reset_token(token_b, user) is False

        # Replay after password change never works.
        assert rg.consume_reset_token(token_a, GOOD_PASSWORD) is False
        assert rg.validate_reset_token(token_b, user) is False
        assert rg.RESET_TOKENS == {} or all(
            record["user"] != user for record in rg.RESET_TOKENS.values()
        )


def check_entropy_under_seeded_rng():
    _reset_state()
    saved_randint = rg.random.randint
    rg.random.randint = lambda _a, _b: 123456
    try:
        tokens = {rg.create_reset_token("alice") for _ in range(1000)}
    finally:
        rg.random.randint = saved_randint
    assert len(tokens) == 1000
    assert all(len(token) >= 32 and not token.isdigit() for token in tokens)


def check_boundaries():
    _reset_state()

    for bad_user in ("", None, 123, b"alice", [], {}):
        try:
            rg.create_reset_token(bad_user)
        except (ValueError, TypeError):
            pass
        else:
            raise AssertionError("bad user accepted: %r" % (bad_user,))
    try:
        rg.create_reset_token("alice")
    except TypeError:
        raise AssertionError("plain string user must be accepted")

    for bad_ttl in (0, -1, -0.5):
        try:
            rg.create_reset_token("alice", bad_ttl)
        except ValueError:
            pass
        else:
            raise AssertionError("bad ttl accepted: %r" % (bad_ttl,))

    # Expiry boundary: expires == now is already expired (>= semantics).
    token = rg.create_reset_token("alice", ttl=1)
    now = time.time()
    rg.RESET_TOKENS[token]["expires"] = now + 0.05
    assert rg.validate_reset_token(token) is True
    token = rg.create_reset_token("bob", ttl=1)
    rg.RESET_TOKENS[token]["expires"] = time.time()
    assert rg.validate_reset_token(token) is False
    assert token not in rg.RESET_TOKENS

    # TTL expiry with mocked clock and automatic cleanup.
    real_time = time.time
    clock = [1000.0]
    time.time = lambda: clock[0]
    try:
        token = rg.create_reset_token("carol", ttl=10)
        clock[0] = 1009.9
        assert rg.validate_reset_token(token, "carol") is True
        token = rg.create_reset_token("carol", ttl=0.1)
        clock[0] = 1010.0
        assert rg.validate_reset_token(token, "carol") is False
        assert token not in rg.RESET_TOKENS
    finally:
        time.time = real_time

    # Bad passwords raise and leave the token usable for a retry.
    token = rg.create_reset_token("dave")
    for bad_password in ("short", "password", "  PASSWORD  ", "", "1234567"):
        try:
            rg.consume_reset_token(token, bad_password)
        except ValueError:
            pass
        else:
            raise AssertionError("bad password accepted: %r" % (bad_password,))
    assert rg.consume_reset_token(token, GOOD_PASSWORD) is True
    assert rg.consume_reset_token(token, GOOD_PASSWORD) is False

    # Logout / explicit invalidation removes every token of the user.
    tokens = [rg.create_reset_token("erin") for _ in range(5)]
    other = rg.create_reset_token("frank")
    rg.invalidate_user_tokens("erin")
    assert all(rg.validate_reset_token(token) is False for token in tokens)
    assert rg.validate_reset_token(other, "frank") is True


def check_concurrent_consume(rounds=100, threads_count=32):
    _reset_state()
    barrier = threading.Barrier(threads_count)
    for _ in range(rounds):
        token = rg.create_reset_token("grace")
        results = []

        def worker():
            barrier.wait()
            results.append(rg.consume_reset_token(token, GOOD_PASSWORD))

        threads = [threading.Thread(target=worker) for _ in range(threads_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert results.count(True) == 1, results
        assert results.count(False) == threads_count - 1
        assert token not in rg.RESET_TOKENS


def main():
    check_randomized_fuzz()
    check_entropy_under_seeded_rng()
    check_boundaries()
    check_concurrent_consume()
    print("all security checks passed")


if __name__ == "__main__":
    main()
