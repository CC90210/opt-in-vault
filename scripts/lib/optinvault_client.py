"""Dependency-free client for Opt-in Vault public consent capture."""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen


_SITE_KEY = re.compile(r"^oiv_pk_[A-Za-z0-9_-]{43}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


class OptInVaultError(RuntimeError):
    """A fail-closed Opt-in Vault request failure."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def _http_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("base_url must be an HTTP(S) URL without credentials, query, or fragment")
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("base_url must use HTTPS (HTTP is allowed only on loopback)")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _header_value(name: str, value: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or re.search(r"[\r\n\x00]", value):
        raise ValueError(f"{name} is invalid")
    return value


class OptInVaultClient:
    """Small stdlib client for server-side consent capture integrations."""

    def __init__(
        self,
        base_url: str,
        *,
        site_key: str,
        timeout: float = 10.0,
        opener: Callable[..., Any] = urlopen,
    ) -> None:
        self.base_url = _http_base_url(base_url)
        if not _SITE_KEY.fullmatch(site_key):
            raise ValueError("site_key is not a publishable Opt-in Vault key")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.site_key = site_key
        self.timeout = timeout
        self._opener = opener

    def log_consent(
        self,
        *,
        origin: str,
        disclosure_version: str,
        affirmative_action: str,
        form_url: str,
        email: str | None = None,
        phone: str | None = None,
        occurred_at: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Record an affirmative consent event and return its evidence identifiers."""
        if not email and not phone:
            raise ValueError("email or phone is required")
        key = idempotency_key or str(uuid.uuid4())
        if not _IDEMPOTENCY_KEY.fullmatch(key):
            raise ValueError("idempotency_key is invalid")

        payload: dict[str, Any] = {
            "disclosure_version": disclosure_version,
            "affirmative_action": affirmative_action,
            "form_url": form_url,
        }
        if email is not None:
            payload["email"] = email
        if phone is not None:
            payload["phone"] = phone
        if occurred_at is not None:
            payload["occurred_at"] = occurred_at

        request = Request(
            f"{self.base_url}/api/v1/consent/log",
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Origin": _header_value("origin", origin, 512),
                "Idempotency-Key": _header_value("idempotency_key", key, 128),
                "X-OptInVault-Site-Key": self.site_key,
            },
            method="POST",
        )
        try:
            with self._opener(request, timeout=self.timeout) as response:
                raw = response.read(1_048_577)
                if len(raw) > 1_048_576:
                    raise OptInVaultError("Opt-in Vault response exceeded 1 MiB")
                decoded = json.loads(raw.decode("utf-8"))
                if not isinstance(decoded, dict):
                    raise OptInVaultError("Opt-in Vault returned a non-object response")
                return decoded
        except HTTPError as error:
            raise OptInVaultError(
                f"Opt-in Vault rejected the consent event with HTTP {error.code}",
                status=error.code,
            ) from error
        except URLError as error:
            raise OptInVaultError("Opt-in Vault could not be reached") from error
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise OptInVaultError("Opt-in Vault returned invalid JSON") from error
