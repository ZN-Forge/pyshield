"""Vulnerability intelligence providers for PyShield."""

from pyshield.dependencies.providers.base import BaseVulnerabilityProvider
from pyshield.dependencies.providers.osv import OSVProvider

__all__ = ["BaseVulnerabilityProvider", "OSVProvider"]
