import random  # retained for API compatibility; never used for token generation
import secrets
import threading
import time

RESET_TOKENS = {}

_TOKEN_BYTES = 32
_MIN_PASSWORD_LENGTH = 8
_COMMON_PASSWORDS = frozenset(
    [
        "password",
        "password1",
        "password123",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty123",
        "qwertyuiop",
        "iloveyou",
        "admin123",
        "administrator",
        "letmein1",
        "welcome1",
        "monkey123",
        "dragon123",
        "football1",
        "baseball1",
        "abc12345",
        "changeme",
        "passw0rd",
        "sunshine1",
        "princess1",
        "master123",
        "shadow123",
        "superman1",
        "trustno1",
    ]
)

_lock = threading.RLock()


def _validate_user(user):
    if not isinstance(user, str):
        raise TypeError("user must be a string")
    if not user:
        raise ValueError("user must not be empty")


def _validate_ttl(ttl):
    if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or ttl <= 0:
        raise ValueError("ttl must be a positive number")


def _validate_password(new_password):
    if not isinstance(new_password, str) or len(new_password) < _MIN_PASSWORD_LENGTH:
        raise ValueError(
            "password must be a string of at least %d characters" % _MIN_PASSWORD_LENGTH
        )
    if not new_password.strip() or new_password.strip().lower() in _COMMON_PASSWORDS:
        raise ValueError("password is too common or empty")


def _purge_expired(now):
    expired = [token for token, record in RESET_TOKENS.items() if now >= record["expires"]]
    for token in expired:
        del RESET_TOKENS[token]


def create_reset_token(user, ttl=900):
    _validate_user(user)
    _validate_ttl(ttl)
    with _lock:
        now = time.time()
        _purge_expired(now)
        token = secrets.token_urlsafe(_TOKEN_BYTES)
        while token in RESET_TOKENS:
            token = secrets.token_urlsafe(_TOKEN_BYTES)
        RESET_TOKENS[token] = {
            "user": user,
            "created": now,
            "expires": now + ttl,
            "used": False,
        }
        return token


def validate_reset_token(token, user=None):
    if not isinstance(token, str) or not token:
        return False
    with _lock:
        record = RESET_TOKENS.get(token)
        if record is None:
            return False
        now = time.time()
        if now >= record["expires"] or record["used"]:
            RESET_TOKENS.pop(token, None)
            return False
        if user is not None and record["user"] != user:
            return False
        record["used"] = True
        return True


def consume_reset_token(token, new_password):
    _validate_password(new_password)
    with _lock:
        record = RESET_TOKENS.get(token)
        if record is None or record["used"] or time.time() >= record["expires"]:
            RESET_TOKENS.pop(token, None)
            return False
        user = record["user"]
        for issued_token in [
            issued for issued, entry in RESET_TOKENS.items() if entry["user"] == user
        ]:
            del RESET_TOKENS[issued_token]
        return True


def invalidate_user_tokens(user):
    with _lock:
        for issued_token in [
            issued for issued, entry in RESET_TOKENS.items() if entry["user"] == user
        ]:
            del RESET_TOKENS[issued_token]
    return None
