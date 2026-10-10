"""Authentication primitives: password hashing, access tokens, TOTP, and rate limiting."""

from __future__ import annotations

import hmac
import re
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from nimbusvpn.crypto import derive_key

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
TOTP_ISSUER = "NimbusVPN"
TOTP_STEP_SECONDS = 30
_JWT_ALGORITHM = "HS256"
_JWT_ISSUER = "nimbusvpn"

# Argon2id with the library's defaults (t=3, m=64 MiB, p=4) - the OWASP-recommended choice.
_hasher = PasswordHasher()
# Verified against when the username does not exist, so response time does not reveal
# which usernames are registered.
_DUMMY_HASH = _hasher.hash("nimbusvpn-timing-equaliser")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def password_problems(password: str, username: str, min_length: int) -> list[str]:
    problems = []
    if len(password) < min_length:
        problems.append(f"must be at least {min_length} characters")
    if len(password) > 256:
        problems.append("must be at most 256 characters")
    if username and username.lower() in password.lower():
        problems.append("must not contain the username")
    if len(set(password)) < 5:
        problems.append("must contain at least 5 distinct characters")
    return problems


# --- Access tokens --------------------------------------------------------------------------


@dataclass(frozen=True)
class TokenClaims:
    user_id: int
    token_version: int


class TokenService:
    """Short-lived HS256 JWTs. Revocation works by bumping ``User.token_version``."""

    def __init__(self, master_secret: str, ttl_minutes: int):
        self._key = derive_key(master_secret, "jwt-signing")
        self.ttl = timedelta(minutes=ttl_minutes)

    def issue(self, user_id: int, token_version: int) -> str:
        now = datetime.now(UTC)
        payload = {
            "iss": _JWT_ISSUER,
            "sub": str(user_id),
            "tv": token_version,
            "iat": now,
            "nbf": now,
            "exp": now + self.ttl,
        }
        return jwt.encode(payload, self._key, algorithm=_JWT_ALGORITHM)

    def verify(self, token: str) -> TokenClaims | None:
        try:
            payload = jwt.decode(
                token,
                self._key,
                algorithms=[_JWT_ALGORITHM],
                issuer=_JWT_ISSUER,
                options={"require": ["exp", "iat", "sub", "iss"]},
            )
            return TokenClaims(user_id=int(payload["sub"]), token_version=int(payload["tv"]))
        except (jwt.PyJWTError, KeyError, TypeError, ValueError):
            return None


# --- TOTP (RFC 6238) ------------------------------------------------------------------------


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=TOTP_ISSUER)


def verify_totp(secret: str, code: str, last_step: int, now: float | None = None) -> int | None:
    """Return the matched time step, or ``None``.

    Accepts one step of clock drift either side and rejects any step at or before
    ``last_step``, so a code can never be replayed.
    """
    code = code.strip().replace(" ", "")
    if not re.fullmatch(r"\d{6}", code):
        return None
    totp = pyotp.TOTP(secret)
    current = int((now if now is not None else time.time()) // TOTP_STEP_SECONDS)
    for step in (current - 1, current, current + 1):
        if step <= last_step:
            continue
        if hmac.compare_digest(totp.at(step * TOTP_STEP_SECONDS), code):
            return step
    return None


# --- Rate limiting --------------------------------------------------------------------------


class SlidingWindowLimiter:
    """In-memory sliding-window limiter keyed by e.g. client IP."""

    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> bool:
        """Record an attempt; return ``False`` when the key is over its limit."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= now - self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            if len(self._hits) > 10_000:
                self._prune(now)
            return True

    def _prune(self, now: float) -> None:
        for key in [k for k, v in self._hits.items() if not v or v[-1] <= now - self.window]:
            del self._hits[key]
