"""Rule PS702: Detects TLS certificate verification disabled in HTTP requests."""

import ast

from pyshield.core.models import Confidence, Finding, Severity
from pyshield.rules.base import ASTContext, BaseRule

HTTP_METHODS = {"get", "post", "put", "delete", "head", "patch", "request"}
HTTP_CLIENT_CLASSES = {"client", "asyncclient", "session"}
HTTP_MODULES = {"requests", "httpx", "urllib3"}


class InsecureTlsRule(BaseRule):
    """Detects HTTP requests with TLS certificate verification disabled (verify=False)."""

    rule_id = "PS702"
    title = "TLS certificate verification disabled"
    description = (
        "Detects HTTP requests configured with TLS certificate verification disabled "
        "(verify=False), leaving data transmissions vulnerable to man-in-the-middle "
        "(MITM) inspection and tampering."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe = "CWE-295"
    remediation = (
        "Enable TLS certificate verification by setting verify=True (or omitting the "
        "verify argument to use default verification with trusted system CA certificates)."
    )

    def check(self, context: ASTContext) -> list[Finding]:
        """Scan AST for HTTP calls disabling certificate verification."""
        findings: list[Finding] = []

        for node in ast.walk(context.tree):
            if not isinstance(node, ast.Call):
                continue

            # Check if any keyword is verify=False
            verify_kwarg = self._find_insecure_verify_kwarg(node)
            if verify_kwarg is None:
                continue

            # Confirm whether this call is an identifiable HTTP client call
            if self._is_http_call(node, context):
                findings.append(
                    self.create_finding(
                        context=context,
                        node=verify_kwarg,
                        message=(
                            "TLS certificate verification is explicitly disabled (verify=False)."
                        ),
                    )
                )

        return findings

    @staticmethod
    def _find_insecure_verify_kwarg(call_node: ast.Call) -> ast.keyword | None:
        """Find keyword argument 'verify' set to False, 0, or None."""
        for kw in call_node.keywords:
            if kw.arg == "verify":
                if isinstance(kw.value, ast.Constant):
                    if kw.value.value is False or kw.value.value == 0 or kw.value.value is None:
                        return kw
        return None

    def _is_http_call(self, call_node: ast.Call, context: ASTContext) -> bool:
        """Statically inspect call structure and imports for HTTP client patterns."""
        func = call_node.func

        # Case 1: Attribute call like requests.get(...) or session.post(...)
        if isinstance(func, ast.Attribute):
            method_name = func.attr.lower()
            # Attribute on a module or object, e.g. requests.get
            if isinstance(func.value, ast.Name):
                caller_name = func.value.id.lower()
                # Direct module call (requests.get, httpx.post, etc.)
                if caller_name in HTTP_MODULES:
                    return method_name in HTTP_METHODS or method_name in HTTP_CLIENT_CLASSES

                # Client/session variable call (e.g. session.get, client.post)
                if any(sub in caller_name for sub in ("session", "client", "http")):
                    return method_name in HTTP_METHODS

                # Check if caller_name was imported from an HTTP module
                resolved_caller = context.resolve_name(func.value.id).lower()
                if any(mod in resolved_caller for mod in HTTP_MODULES):
                    return method_name in HTTP_METHODS or method_name in HTTP_CLIENT_CLASSES

            # Chained calls like requests.Session().get(...)
            elif isinstance(func.value, ast.Call):
                inner_func = func.value.func
                if isinstance(inner_func, ast.Attribute):
                    if inner_func.attr.lower() in HTTP_CLIENT_CLASSES:
                        return method_name in HTTP_METHODS
                elif isinstance(inner_func, ast.Name):
                    if inner_func.id.lower() in HTTP_CLIENT_CLASSES:
                        return method_name in HTTP_METHODS

        # Case 2: Bare name call like get(..., verify=False) imported from requests/httpx
        elif isinstance(func, ast.Name):
            resolved = context.resolve_name(func.id)
            for mod in HTTP_MODULES:
                if resolved.startswith(f"{mod}."):
                    fn_name = resolved.split(".")[-1].lower()
                    if fn_name in HTTP_METHODS or fn_name in HTTP_CLIENT_CLASSES:
                        return True

        return False
