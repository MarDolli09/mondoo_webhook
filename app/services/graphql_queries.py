INTROSPECT_QUERY_ROOT = """
query IntrospectQueryRoot {
  __type(name: "Query") {
    name
    fields {
      name
      args {
        name
      }
    }
  }
}
"""

GET_ASSET_QUERY = """
query GetAsset($mrn: String!) {
  asset(mrn: $mrn) {
    name
  }
}
"""

GET_FINDINGS_PAGINATED_QUERY = """
query GetFindingsPaginated($scopeMrn: String!, $cursor: String) {
  findings(scopeMrn: $scopeMrn, first: 100, after: $cursor) {
    ... on FindingsConnection {
      pageInfo {
        hasNextPage
        endCursor
      }
      edges {
        node {
          __typename
          ... on CveFinding {
            mrn
            cveTitle: title
            riskScore
            riskValue
            baseValue
            rating
            baseRating
            cveCvss: cvss {
              value
              vector
              rating
            }
          }
          ... on AdvisoryFinding {
            mrn
            advTitle: title
            riskScore
            riskValue
            baseValue
            rating
            baseRating
            advCvss: cvss {
              value
              vector
              rating
            }
          }
          ... on PackageFinding {
            mrn
            pkgTitle: title
            riskScore
            riskValue
            baseScore
            rating
            pkgCvss: cvss {
              value
              vector
              rating
            }
          }
          ... on CheckFinding {
            mrn
            chkTitle: title
            riskScore
            riskValue
            rating
          }
          ... on GenericFinding {
            mrn
            genTitle: title
            riskScore
            riskValue
            rating
          }
        }
      }
    }
    ... on RequestError {
      message
    }
    ... on NotFoundError {
      message
    }
  }
}
"""