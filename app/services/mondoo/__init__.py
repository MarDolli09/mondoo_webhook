"""Teilsystem Mondoo: CVSS-Anreicherung ueber die GraphQL-API."""

from app.services.mondoo.client import MondooGraphQLClient

__all__ = ["MondooGraphQLClient"]
