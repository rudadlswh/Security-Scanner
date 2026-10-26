"""Static-analysis fixtures only; these functions are not used by the HTTP app."""

import hashlib
import random
import secrets
import ssl


# CWE-798 / Bandit B105: synthetic credential, never valid for any external service.
ADMIN_PASSWORD = "LAB-ONLY-hardcoded-password"


def weak_password_hash(password):
    # CWE-328 / Bandit B324: fast, unsalted password hashing.
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def improved_password_hash(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1)
    return {"salt": salt.hex(), "digest": digest.hex()}


def predictable_reset_token():
    # CWE-330 / Bandit B311: not a cryptographically secure generator.
    return str(random.randint(100000, 999999))


def improved_reset_token():
    return secrets.token_urlsafe(32)


def insecure_tls_context():
    # CWE-295 / Bandit B323: disables peer certificate verification.
    return ssl._create_unverified_context()


def improved_tls_context():
    return ssl.create_default_context()
