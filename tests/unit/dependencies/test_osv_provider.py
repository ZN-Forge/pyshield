"""Unit tests for OSVProvider."""

import json
import urllib.error
from unittest.mock import MagicMock, patch

from pyshield.core.models import Severity
from pyshield.dependencies.models import ProviderStatus
from pyshield.dependencies.providers.osv import OSVProvider


class TestOSVProvider:
    def setup_method(self) -> None:
        self.provider = OSVProvider(timeout_seconds=2.0)

    @patch("urllib.request.urlopen")
    def test_query_package_with_vulnerabilities(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        payload = {
            "vulns": [
                {
                    "id": "GHSA-1234-abcd-5678",
                    "summary": "Sample vulnerable package issue",
                    "details": "Extended details about vulnerability",
                    "aliases": ["CVE-2023-99999"],
                    "database_specific": {"severity": "HIGH"},
                    "affected": [
                        {
                            "package": {"name": "sample-pkg", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        mock_response.read.return_value = json.dumps(payload).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        res = self.provider.query_package("sample-pkg", "1.0.0")

        assert res.status == ProviderStatus.AVAILABLE
        assert len(res.vulnerabilities) == 1
        vuln = res.vulnerabilities[0]
        assert vuln.id == "GHSA-1234-abcd-5678"
        assert vuln.summary == "Sample vulnerable package issue"
        assert vuln.aliases == ["CVE-2023-99999"]
        assert vuln.fixed_version == "2.0.0"
        assert vuln.severity == Severity.HIGH

    @patch("urllib.request.urlopen")
    def test_query_package_clean_no_vulns(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"vulns": []}).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        res = self.provider.query_package("safe-pkg", "1.0.0")

        assert res.status == ProviderStatus.AVAILABLE
        assert len(res.vulnerabilities) == 0

    @patch("urllib.request.urlopen")
    def test_query_package_network_error(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = urllib.error.URLError("DNS resolution failure")

        res = self.provider.query_package("sample-pkg", "1.0.0")

        assert res.status == ProviderStatus.UNAVAILABLE
        assert len(res.vulnerabilities) == 0
        assert res.error_message is not None
        assert "Network error" in res.error_message

    @patch("urllib.request.urlopen")
    def test_query_package_malformed_json(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = b"Not valid json"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        res = self.provider.query_package("sample-pkg", "1.0.0")

        assert res.status == ProviderStatus.UNAVAILABLE
        assert "Malformed response" in (res.error_message or "")

    @patch("urllib.request.urlopen")
    def test_query_batch(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        payload = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-pkg1",
                            "summary": "Pkg 1 issue",
                        }
                    ]
                },
                {"vulns": []},
            ]
        }
        mock_response.read.return_value = json.dumps(payload).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        packages = [("pkg1", "1.0.0"), ("pkg2", "2.0.0")]
        results = self.provider.query_batch(packages)

        assert len(results) == 2
        assert len(results[("pkg1", "1.0.0")].vulnerabilities) == 1
        assert len(results[("pkg2", "2.0.0")].vulnerabilities) == 0

    @patch("urllib.request.urlopen")
    def test_cache_avoids_repeated_requests(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"vulns": []}).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        res1 = self.provider.query_package("cached-pkg", "1.0.0")
        res2 = self.provider.query_package("cached-pkg", "1.0.0")

        assert res1 is res2
        # HTTP request called only once
        assert mock_urlopen.call_count == 1

    @patch("urllib.request.urlopen")
    def test_query_batch_network_error(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        packages = [("pkg1", "1.0.0")]
        results = self.provider.query_batch(packages)

        assert ("pkg1", "1.0.0") in results
        assert results[("pkg1", "1.0.0")].status == ProviderStatus.UNAVAILABLE
        assert "Network error" in (results[("pkg1", "1.0.0")].error_message or "")

    @patch("urllib.request.urlopen")
    def test_query_batch_malformed_json(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = b"invalid json"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        packages = [("pkg1", "1.0.0")]
        results = self.provider.query_batch(packages)

        assert results[("pkg1", "1.0.0")].status == ProviderStatus.UNAVAILABLE
        assert "Malformed" in (results[("pkg1", "1.0.0")].error_message or "")

    def test_determine_severity_levels(self) -> None:
        assert (
            self.provider._determine_severity({"database_specific": {"severity": "CRITICAL"}})
            == Severity.CRITICAL
        )
        assert (
            self.provider._determine_severity({"database_specific": {"severity": "HIGH"}})
            == Severity.HIGH
        )
        assert (
            self.provider._determine_severity({"database_specific": {"severity": "MODERATE"}})
            == Severity.MEDIUM
        )
        assert (
            self.provider._determine_severity({"database_specific": {"severity": "LOW"}})
            == Severity.LOW
        )
        assert self.provider._determine_severity({}) == Severity.HIGH
