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

import logging
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
    # Bounded: an unbounded lazy [\s\S]*? between anchors backtracks
    # catastrophically on a crafted log line that opens a PEM block and never
    # closes it. This runs on a LOGGING path, where attacker-controlled text is
    # exactly what arrives.
    ('private_key', re.compile(r'-----BEGIN [A-Z ]{0,32}PRIVATE KEY-----[\s\S]{0,8192}?-----END [A-Z ]{0,32}PRIVATE KEY-----')),
    # Assignment forms: key=value, "key": "value", key: value.
    (
        'assigned_secret',
        re.compile(
            r'(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|token|authorization)\b'
            r'(\s{0,4}[:=]\s{0,4}["\']?)([^\s"\',;&]{6,4096})'
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


class SecretRedactingFilter(logging.Filter):
    """Redact credentials from every log record passing through a logger.

    Wiring redaction call-by-call cannot satisfy "filter agent tool output
    before logging": any `logger.*` added later bypasses it, and the failure is
    silent. A filter on the handler covers every path by construction, including
    the ones nobody remembered.

    Both the format string and its args are redacted, because a credential
    usually arrives through `%s` interpolation rather than in the literal.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_secrets(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = redact_mapping(record.args)
            else:
                record.args = tuple(
                    redact_secrets(a) if isinstance(a, str) else a for a in record.args
                )
        return True  # never drop a record; redaction must not cost observability


def install_secret_redaction(logger: logging.Logger | None = None) -> None:
    """Attach the redacting filter once to `logger` (root when omitted)."""
    target = logger or logging.getLogger()
    if any(isinstance(f, SecretRedactingFilter) for f in target.filters):
        return
    target.addFilter(SecretRedactingFilter())
