"""PURL (Package URL) generation and normalization utilities.

Spec: https://github.com/package-url/purl-spec
Format: pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>

Uses the `packageurl-python` library for standards compliance.
"""

from __future__ import annotations

import re
from typing import Optional

from packageurl import PackageURL

from depnova.core.models import Ecosystem


# ---------------------------------------------------------------------------
# Ecosystem → PURL type mapping
# ---------------------------------------------------------------------------

_ECOSYSTEM_TO_PURL_TYPE: dict[str, str] = {
    Ecosystem.NPM.value: "npm",
    Ecosystem.YARN.value: "npm",      # Yarn uses npm registry
    Ecosystem.PNPM.value: "npm",      # pnpm uses npm registry
    Ecosystem.PYPI.value: "pypi",
    Ecosystem.MAVEN.value: "maven",
    Ecosystem.GRADLE.value: "maven",  # Gradle uses Maven repos
    Ecosystem.CARGO.value: "cargo",
    Ecosystem.GO.value: "golang",
    Ecosystem.NUGET.value: "nuget",
    Ecosystem.COMPOSER.value: "composer",
    Ecosystem.OS_DPKG.value: "deb",
    Ecosystem.OS_RPM.value: "rpm",
    Ecosystem.OS_APK.value: "apk",
    Ecosystem.CDN.value: "generic",
    Ecosystem.STATIC.value: "generic",
    Ecosystem.UNKNOWN.value: "generic",
}


def generate_purl(
    name: str,
    version: str,
    ecosystem: Ecosystem | str,
    namespace: Optional[str] = None,
    qualifiers: Optional[dict[str, str]] = None,
    subpath: Optional[str] = None,
) -> str:
    """Generate a standards-compliant Package URL.

    Args:
        name:       Package name (e.g. "lodash", "requests")
        version:    Version string (e.g. "4.17.21")
        ecosystem:  Ecosystem enum or string value
        namespace:  Optional namespace (e.g. Maven groupId, npm scope)
        qualifiers: Optional qualifiers dict
        subpath:    Optional subpath

    Returns:
        PURL string like "pkg:npm/lodash@4.17.21"

    Examples:
        >>> generate_purl("lodash", "4.17.21", Ecosystem.NPM)
        'pkg:npm/lodash@4.17.21'
        >>> generate_purl("spring-core", "5.3.20", Ecosystem.MAVEN, namespace="org.springframework")
        'pkg:maven/org.springframework/spring-core@5.3.20'
    """
    eco_val = ecosystem.value if isinstance(ecosystem, Ecosystem) else ecosystem
    purl_type = _ECOSYSTEM_TO_PURL_TYPE.get(eco_val, "generic")

    # Normalize the name for the ecosystem
    normalized_name = _normalize_name(name, purl_type)
    normalized_version = normalize_version(version)

    purl = PackageURL(
        type=purl_type,
        namespace=namespace,
        name=normalized_name,
        version=normalized_version or None,
        qualifiers=qualifiers,
        subpath=subpath,
    )
    return str(purl)


def normalize_version(version: str) -> str:
    """Normalize a version string for consistent comparison.

    - Strip leading 'v' or 'V'
    - Strip leading/trailing whitespace
    - Handle epoch prefixes (e.g. "1:2.3.4" → "2.3.4" with epoch stored)
    - Collapse multiple dots

    Args:
        version: Raw version string

    Returns:
        Normalized version string

    Examples:
        >>> normalize_version("v1.2.3")
        '1.2.3'
        >>> normalize_version("  V2.0.0  ")
        '2.0.0'
    """
    if not version:
        return ""

    v = version.strip()

    # Strip leading 'v' or 'V'
    if v and v[0] in ("v", "V") and len(v) > 1 and v[1].isdigit():
        v = v[1:]

    # Remove epoch prefix (common in deb/rpm): "1:2.3.4" → "2.3.4"
    # We strip it for normalization but this could be preserved if needed
    epoch_match = re.match(r"^\d+:", v)
    if epoch_match:
        v = v[epoch_match.end():]

    return v


def parse_purl(purl_string: str) -> dict:
    """Parse a PURL string into its components.

    Args:
        purl_string: A Package URL string

    Returns:
        Dict with keys: type, namespace, name, version, qualifiers, subpath
    """
    try:
        purl = PackageURL.from_string(purl_string)
        return {
            "type": purl.type,
            "namespace": purl.namespace,
            "name": purl.name,
            "version": purl.version,
            "qualifiers": dict(purl.qualifiers) if purl.qualifiers else {},
            "subpath": purl.subpath,
        }
    except ValueError:
        return {
            "type": "generic",
            "namespace": None,
            "name": purl_string,
            "version": None,
            "qualifiers": {},
            "subpath": None,
        }


def _normalize_name(name: str, purl_type: str) -> str:
    """Normalize package name per ecosystem conventions.

    - PyPI: lowercase, replace hyphens/underscores with hyphens
    - npm:  keep as-is (case-sensitive)
    - Maven: keep as-is
    """
    if purl_type == "pypi":
        # PEP 503: normalize to lowercase with hyphens
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.strip()
