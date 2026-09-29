"""GraphQL-Abfragen an die Mondoo-API."""

__all__ = ["CVSS_FIELDS", "GET_FINDING_SCORES_QUERY"]

# Aliase des cvss-Objekts je Finding-Typ. Mondoo deklariert cvss nicht bei allen
# Typen gleich (CvssScore! bzw. CvssScore); ohne Alias lehnt die API die ganze
# Abfrage mit HTTP 422 ab ("Fields cvss conflict ... conflicting types").
CVSS_FIELDS = ("cveCvss", "advisoryCvss", "packageCvss")

# Holt genau ein Finding ueber den Filter; die API liefert einen Knoten je
# betroffenem Asset. CheckFinding und GenericFinding haben kein cvss-Objekt.
GET_FINDING_SCORES_QUERY = """
query GetFindingScores($scopeMrn: String!, $findingMrn: String!, $first: Int!) {
  findings(scopeMrn: $scopeMrn, first: $first, filter: {mrn: $findingMrn}) {
    ... on FindingsConnection {
      totalCount
      edges {
        node {
          __typename
          ... on CveFinding {
            mrn
            riskValue
            rating
            cveCvss: cvss { value rating }
          }
          ... on AdvisoryFinding {
            mrn
            riskValue
            rating
            advisoryCvss: cvss { value rating }
          }
          ... on PackageFinding {
            mrn
            riskValue
            rating
            packageCvss: cvss { value rating }
          }
          ... on CheckFinding {
            mrn
            riskValue
            rating
          }
          ... on GenericFinding {
            mrn
            riskValue
            rating
          }
        }
      }
    }
    ... on RequestError { message }
    ... on NotFoundError { message }
  }
}
"""
