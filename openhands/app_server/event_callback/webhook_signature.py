"""HMAC signature verification for inbound webhook callbacks (MT-002).

The webhook endpoints accept payloads that drive agent automation — saving
events, updating conversation state, and dispatching callbacks that can run
agent code. Session API key authentication proves only that the caller holds a
sandbox key; it says nothing about the integrity of the body, so anyone able to
replay or obtain a key can forge payloads that look like legitimate
third-party events.

This module adds payload authentication: an HMAC-SHA256 over the request body,
bound to a timestamp so a captured request cannot be replayed indefinitely.
Verification is deny-by-default — if no signing secret is configured the
endpoints refuse to serve rather than silently accepting unauthenticated
payloads.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import threading
import time

from fastapi import HTTPException, Request, status


_logger = logging.getLogger(__name__)

SIGNATURE_HEADER = 'X-Webhook-Signature-256'
TIMESTAMP_HEADER = 'X-Webhook-Timestamp'
SECRET_ENV_VAR = 'OPENHANDS_WEBHOOK_SIGNING_SECRET'

# A signed request older than this is refused even when the signature is
# valid, so a payload captured off the wire has a bounded window of use.
MAX_TIMESTAMP_SKEW_SECONDS = 300

_SIGNATURE_PREFIX = 'sha256='

# Seen signatures, so a captured request cannot be replayed inside its own
# validity window. The signature is a sound idempotency key: it covers the
# timestamp and the exact body, so two genuinely distinct deliveries cannot
# collide and a replay is byte-identical by definition.
#
# Entries are dropped once older than the skew window: past that the timestamp
# check rejects the request anyway, so keeping them buys nothing and would let
# the cache grow without bound on a public endpoint.
_seen_signatures: dict[str, float] = {}
_seen_lock = threading.Lock()


def _claim_signature(signature: str, now: float) -> bool:
    """Record ``signature`` as used. False if already seen — i.e. a replay."""
    with _seen_lock:
        cutoff = now - MAX_TIMESTAMP_SKEW_SECONDS
        for stale in [sig for sig, seen_at in _seen_signatures.items() if seen_at < cutoff]:
            del _seen_signatures[stale]
        if signature in _seen_signatures:
            return False
        _seen_signatures[signature] = now
        return True


def _signing_secret() -> str:
    secret = os.environ.get(SECRET_ENV_VAR, '')
    if not secret:
        # Fail closed. An unset secret is a deployment error, and accepting
        # unsigned payloads because of it would reintroduce exactly the
        # forgery this check exists to prevent.
        _logger.error(
            'Webhook signing secret is not configured; refusing webhook. '
            'Set %s to enable webhook processing.',
            SECRET_ENV_VAR,
        )
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='Webhook signature verification is not configured',
        )
    return secret


def expected_signature(secret: str, timestamp: str, body: bytes) -> str:
    """The signature a legitimate sender computes for this request.

    The timestamp is inside the signed material, not merely compared
    alongside it — otherwise an attacker could keep a valid body signature and
    substitute a fresh timestamp to defeat the replay window.
    """
    payload = timestamp.encode('utf-8') + b'.' + body
    digest = hmac.new(secret.encode('utf-8'), payload, hashlib.sha256).hexdigest()
    return _SIGNATURE_PREFIX + digest


def _reject(reason: str) -> HTTPException:
    _logger.warning('Rejected webhook: %s', reason)
    # The response stays generic: telling a caller which half of the check
    # failed helps them iterate toward a forgery.
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        detail='Invalid webhook signature',
    )


async def verify_webhook_signature(request: Request) -> None:
    """FastAPI dependency enforcing payload authenticity.

    Reads the raw body before any model parsing, because the signature covers
    the exact bytes sent — re-serialising a parsed model would produce
    different bytes and a spurious mismatch.
    """
    secret = _signing_secret()

    signature = request.headers.get(SIGNATURE_HEADER)
    if not signature:
        raise _reject(f'missing {SIGNATURE_HEADER}')

    timestamp = request.headers.get(TIMESTAMP_HEADER)
    if not timestamp:
        raise _reject(f'missing {TIMESTAMP_HEADER}')

    try:
        sent_at = int(timestamp)
    except ValueError:
        raise _reject('timestamp is not an integer') from None

    if abs(time.time() - sent_at) > MAX_TIMESTAMP_SKEW_SECONDS:
        raise _reject('timestamp outside the accepted window')

    body = await request.body()
    expected = expected_signature(secret, timestamp, body)

    # Constant-time comparison: a byte-by-byte equality check leaks how much
    # of a guessed signature was correct, which is enough to forge one.
    if not hmac.compare_digest(expected, signature):
        raise _reject('signature mismatch')

    # Authentic, but possibly a replay: a signature stays valid for the whole
    # skew window, so without this an attacker who captured one delivery could
    # resend it repeatedly and have every copy processed as a fresh event.
    if not _claim_signature(signature, time.time()):
        raise _reject('duplicate delivery (replayed signature)')

# webhook signing secret rotation reviewed 2026-08-05
