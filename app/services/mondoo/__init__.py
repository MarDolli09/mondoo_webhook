"""Teilsystem Mondoo: Bewertungen (CVSS, Risk) ueber die GraphQL-API."""

from app.services.mondoo.client import MondooGraphQLClient

__all__ = ["MondooGraphQLClient"]
