"""Redact credentials from agent output before it is logged or displayed (MT-006).

Agent tool output is attacker-reachable in both directions: the agent reads
untrusted repository content and executes commands whose stdout can echo the
environment it runs in. Logging that verbatim writes live credentials into a
store with a different, usually longer, retention and a wider audience than the
conversation itself — so a leak here outlives the session that caused it.

Redaction is deliberately pattern-based and conservative in one direction only:
a false positive costs a masked string in a log, while a false negative writes a
usable credential to disk. Where the two conflict, prefer masking.
"""

from __future__ import annotations

import re

REDACTION_MARKER = '[REDACTED]'

# Ordered most-specific first: a GitHub token also matches the generic
# `key=<value>` shape, and the specific pattern gives a better log.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ('github_token', re.compile(r'\bgh[pusor]_[A-Za-z0-9]{16,}\b')),
    ('openai_key', re.compile(r'\bsk-[A-Za-z0-9_-]{16,}\b')),
    ('slack_token', re.compile(r'\bxox[abprs]-[A-Za-z0-9-]{10,}\b')),
    ('aws_access_key', re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b')),
    ('bearer', re.compile(r'(?i)\b(bearer\s+)[A-Za-z0-9._~+/-]{16,}=*')),
    ('private_key', re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----')),
    # Assignment forms: key=value, "key": "value", key: value.
    (
        'assigned_secret',
        re.compile(
            r'(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|token|authorization)\b'
            r'(\s*[:=]\s*["\']?)([^\s"\',;&]{6,})'
        ),
    ),
)


def redact_secrets(text: str | None) -> str | None:
    """Return `text` with recognised credentials replaced by the marker.

    `None` and empty input pass through untouched so callers can wrap a value
    unconditionally without special-casing.

    Never raises. A redactor that threw on odd input would take down the very
    logging path it protects, so each pattern is applied independently: one
    failing cannot suppress the others, and the output is still redacted by
    every pattern that did work.
    """
    if not text:
        return text
    out = text
    for name, pattern in _PATTERNS:
        try:
            if name == 'bearer':
                out = pattern.sub(rf'\1{REDACTION_MARKER}', out)
            elif name == 'assigned_secret':
                out = pattern.sub(rf'\1\2{REDACTION_MARKER}', out)
            else:
                out = pattern.sub(REDACTION_MARKER, out)
        except re.error:  # pragma: no cover — defensive; one bad pattern must not disable the rest
            continue
    return out


def redact_mapping(values: dict[str, object]) -> dict[str, object]:
    """Redact every string value in a flat mapping (e.g. log `extra=`)."""
    return {k: (redact_secrets(v) if isinstance(v, str) else v) for k, v in values.items()}
