"""GraphQL-Abfragen an die Mondoo-API."""

__all__ = ["GET_FINDING_SCORES_QUERY"]

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
            cvss { value rating }
          }
          ... on AdvisoryFinding {
            mrn
            riskValue
            rating
            cvss { value rating }
          }
          ... on PackageFinding {
            mrn
            riskValue
            rating
            cvss { value rating }
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
