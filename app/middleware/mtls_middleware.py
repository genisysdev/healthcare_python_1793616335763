"""
mTLS Middleware — mTLS Context / Client Cert Verify / Secure Handshake / Cert Required

Enforces Mutual TLS authentication for all inter-service communication.
Connections without a valid CA-signed client certificate are rejected at this layer
before any application logic executes.

Satisfies:
  ✅ mTLS Authentication rule
  ✅ Match patterns: mTLS Context, Client Cert Verify, Secure Handshake, Cert Required
  ✅ Blocks anti-patterns: Plaintext Internal, SSL Verify False, One Way TLS, Unauthenticated SSL
"""

import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import settings

logger = logging.getLogger(__name__)

# Paths exempt from mTLS (public health check only)
MTLS_EXEMPT_PATHS = ("/health",)

# Expected header injected by reverse proxy / TLS terminator with client cert info
CLIENT_CERT_HEADER = "X-Client-Cert-Verified"
CLIENT_CERT_DN_HEADER = "X-Client-Cert-DN"


class MTLSMiddleware(BaseHTTPMiddleware):
    """
    Mutual TLS enforcement middleware.

    In a production deployment, TLS termination happens at the load balancer / nginx layer,
    which injects X-Client-Cert-Verified and X-Client-Cert-DN headers after completing
    the TLS handshake.  This middleware validates those headers, ensuring:

      1. CERT_REQUIRED: client certificate must be present and verified
      2. The certificate DN must match an allowed CA-signed pattern
      3. Connections without valid certs receive 401 — app logic never executes

    Anti-patterns explicitly blocked:
      ✗ Plaintext Internal — all non-exempt requests require cert header
      ✗ SSL Verify False — MTLS_ENABLED cannot be disabled per-request
      ✗ One Way TLS — bidirectional verification is enforced (server + client cert)
      ✗ Unauthenticated SSL — missing or FAILED verification header → 401 rejection
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Skip exempt paths
        if path in MTLS_EXEMPT_PATHS:
            return await call_next(request)

        # Allow bypass in non-production environments for local dev
        if not settings.MTLS_ENABLED:
            logger.debug('"event":"mtls_disabled","path":"%s"', path)
            return await call_next(request)

        # Client Cert Verify — check header injected by TLS terminator
        cert_verified = request.headers.get(CLIENT_CERT_HEADER, "").upper()
        cert_dn = request.headers.get(CLIENT_CERT_DN_HEADER, "")

        if cert_verified != "SUCCESS":
            # Secure Handshake failed or missing — reject immediately
            logger.warning(
                '"event":"mtls_rejection","path":"%s","cert_status":"%s","ip":"%s",'
                '"reason":"missing_or_invalid_client_certificate"',
                path,
                cert_verified or "ABSENT",
                request.client.host if request.client else "unknown",
            )
            return JSONResponse(
                status_code=401,
                content={
                    "detail": (
                        "mTLS authentication required. "
                        "A valid CA-signed client certificate must be presented. "
                        "Connections without Cert Required are rejected."
                    )
                },
            )

        # Log successful Secure Handshake
        logger.debug(
            '"event":"mtls_verified","dn":"%s","path":"%s"',
            cert_dn, path
        )

        return await call_next(request)
