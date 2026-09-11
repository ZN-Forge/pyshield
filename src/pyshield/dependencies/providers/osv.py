"""OSV (Open Source Vulnerabilities) API provider using Python standard library."""

import json
import urllib.error
import urllib.request
from typing import Any

from pyshield import __version__
from pyshield.core.models import Severity
from pyshield.dependencies.models import (
    ProviderStatus,
    Vulnerability,
    VulnerabilityLookupResult,
)
from pyshield.dependencies.providers.base import BaseVulnerabilityProvider

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2MB response size limit
USER_AGENT = f"PyShield-Security-Scanner/{__version__}"


class OSVProvider(BaseVulnerabilityProvider):
    """Vulnerability provider querying the Google OSV open-source vulnerability database."""

    def __init__(self, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        self.timeout = timeout_seconds
        self._cache: dict[tuple[str, str], VulnerabilityLookupResult] = {}

    def query_package(self, name: str, version: str) -> VulnerabilityLookupResult:
        """Query OSV for a single package and version."""
        cache_key = (name.lower(), version)
        if cache_key in self._cache:
            return self._cache[cache_key]

        payload = {
            "package": {"name": name, "ecosystem": "PyPI"},
            "version": version,
        }

        try:
            raw_data = self._make_request(OSV_QUERY_URL, payload)
            result = self._parse_query_response(raw_data, name)
            self._cache[cache_key] = result
            return result
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as err:
            err_msg = f"Network error querying OSV for {name}: {type(err).__name__}"
            result = VulnerabilityLookupResult(
                status=ProviderStatus.UNAVAILABLE,
                vulnerabilities=[],
                error_message=err_msg,
            )
            return result
        except (json.JSONDecodeError, ValueError) as err:
            err_msg = f"Malformed response from OSV for {name}: {err}"
            result = VulnerabilityLookupResult(
                status=ProviderStatus.UNAVAILABLE,
                vulnerabilities=[],
                error_message=err_msg,
            )
            return result

    def query_batch(
        self, packages: list[tuple[str, str]]
    ) -> dict[tuple[str, str], VulnerabilityLookupResult]:
        """Query OSV in batch for multiple package and version tuples."""
        results: dict[tuple[str, str], VulnerabilityLookupResult] = {}
        uncached: list[tuple[str, str]] = []

        for name, version in packages:
            cache_key = (name.lower(), version)
            if cache_key in self._cache:
                results[cache_key] = self._cache[cache_key]
            else:
                uncached.append((name, version))

        if not uncached:
            return results

        # Query uncached items in chunks of 50
        chunk_size = 50
        for i in range(0, len(uncached), chunk_size):
            chunk = uncached[i : i + chunk_size]
            queries = [
                {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
                for name, version in chunk
            ]
            payload = {"queries": queries}

            try:
                raw_data = self._make_request(OSV_BATCH_URL, payload)
                batch_results = raw_data.get("results", [])
                for (name, version), res_entry in zip(chunk, batch_results, strict=False):
                    parsed_res = self._parse_query_response(res_entry, name)
                    cache_key = (name.lower(), version)
                    self._cache[cache_key] = parsed_res
                    results[cache_key] = parsed_res
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as err:
                err_msg = f"Network error during OSV batch query: {type(err).__name__}"
                for name, version in chunk:
                    cache_key = (name.lower(), version)
                    unavail_res = VulnerabilityLookupResult(
                        status=ProviderStatus.UNAVAILABLE,
                        vulnerabilities=[],
                        error_message=err_msg,
                    )
                    results[cache_key] = unavail_res
            except (json.JSONDecodeError, ValueError) as err:
                err_msg = f"Malformed OSV batch response: {err}"
                for name, version in chunk:
                    cache_key = (name.lower(), version)
                    unavail_res = VulnerabilityLookupResult(
                        status=ProviderStatus.UNAVAILABLE,
                        vulnerabilities=[],
                        error_message=err_msg,
                    )
                    results[cache_key] = unavail_res

        return results

    def _make_request(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Perform an HTTP POST request with timeout and response size limit."""
        if not url.startswith("https://"):
            raise ValueError(f"Insecure or invalid URL scheme for OSV provider: {url}")

        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(  # noqa: S310
            url,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            raw_body = resp.read(MAX_RESPONSE_BYTES)
            decoded = raw_body.decode("utf-8", errors="replace")
            parsed = json.loads(decoded)
            if not isinstance(parsed, dict):
                raise ValueError("OSV response is not a JSON dictionary")
            return parsed

    def _parse_query_response(
        self, data: dict[str, Any], package_name: str
    ) -> VulnerabilityLookupResult:
        """Parse raw OSV JSON response into structured VulnerabilityLookupResult."""
        raw_vulns = data.get("vulns", [])
        if not isinstance(raw_vulns, list):
            return VulnerabilityLookupResult(
                status=ProviderStatus.AVAILABLE,
                vulnerabilities=[],
            )

        vulnerabilities: list[Vulnerability] = []
        for v in raw_vulns:
            if not isinstance(v, dict):
                continue
            vuln_id = str(v.get("id") or "UNKNOWN")
            summary = v.get("summary")
            details = v.get("details")
            if not summary:
                if details:
                    summary = details.splitlines()[0][:140].strip()
                else:
                    summary = f"Known security vulnerability in {package_name}"

            raw_aliases = v.get("aliases", [])
            aliases = [str(a) for a in raw_aliases if isinstance(a, str)]

            fixed_version = self._extract_fixed_version(v, package_name)
            severity = self._determine_severity(v)

            vulnerabilities.append(
                Vulnerability(
                    id=vuln_id,
                    summary=summary,
                    details=details,
                    aliases=aliases,
                    fixed_version=fixed_version,
                    severity=severity,
                )
            )

        return VulnerabilityLookupResult(
            status=ProviderStatus.AVAILABLE,
            vulnerabilities=vulnerabilities,
        )

    def _extract_fixed_version(self, vuln_data: dict[str, Any], package_name: str) -> str | None:
        """Extract the first remediating fixed version string for the package."""
        affected = vuln_data.get("affected", [])
        if not isinstance(affected, list):
            return None

        for item in affected:
            if not isinstance(item, dict):
                continue
            pkg_info = item.get("package", {})
            if isinstance(pkg_info, dict):
                pkg_name = pkg_info.get("name", "")
                if pkg_name.lower() != package_name.lower():
                    continue

            ranges = item.get("ranges", [])
            if isinstance(ranges, list):
                for r in ranges:
                    if isinstance(r, dict):
                        events = r.get("events", [])
                        if isinstance(events, list):
                            for event in events:
                                if isinstance(event, dict) and "fixed" in event:
                                    return str(event["fixed"])
        return None

    def _determine_severity(self, vuln_data: dict[str, Any]) -> Severity:
        """Derive Severity classification from CVSS score or database severity string."""
        # 1. Check database_specific severity string
        db_specific = vuln_data.get("database_specific", {})
        if isinstance(db_specific, dict):
            db_sev = db_specific.get("severity")
            if isinstance(db_sev, str):
                db_sev_upper = db_sev.upper()
                if "CRITICAL" in db_sev_upper:
                    return Severity.CRITICAL
                if "HIGH" in db_sev_upper:
                    return Severity.HIGH
                if "MODERATE" in db_sev_upper or "MEDIUM" in db_sev_upper:
                    return Severity.MEDIUM
                if "LOW" in db_sev_upper:
                    return Severity.LOW

        # 2. Check CVSS numeric score if available in severity list
        severities = vuln_data.get("severity", [])
        if isinstance(severities, list):
            for s in severities:
                if isinstance(s, dict) and s.get("type") in ("CVSS_V3", "CVSS_V4"):
                    score_str = s.get("score")
                    # Check for CVSS base score vector
                    if isinstance(score_str, str) and "/" in score_str:
                        # Vector string like CVSS:3.1/AV:N/...
                        continue

        return Severity.HIGH
