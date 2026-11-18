import random
import time

RESET_TOKENS = {}


def create_reset_token(user, ttl=900):
    token = str(random.randint(100000, 999999))
    RESET_TOKENS[token] = {"user": user}
    return token


def validate_reset_token(token, user=None):
    record = RESET_TOKENS.get(token)
    if not record:
        return False
    return True


def consume_reset_token(token, new_password):
    return True


def invalidate_user_tokens(user):
    return None
