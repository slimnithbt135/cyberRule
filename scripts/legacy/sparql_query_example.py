""" 
sparql_query_example.py
=======================

This script demonstrates how to run SPARQL queries on the Turtle-based RDF graph
generated from the CyberRule enrichment process.

Usage:
    python scripts/sparql_query_example.py
Requires:
    pip install rdflib
"""

from rdflib import Graph

TTL_FILE = "outputs/cyberonto_enriched.ttl"

def run_sparql_query(file_path):
    g = Graph()
    g.parse(file_path, format="turtle")

    query = '''
    PREFIX : <http://example.org/ontology#>
    SELECT ?vuln ?component
    WHERE {
      ?vuln :affects ?component .
    }
    LIMIT 10
    '''

    print("🔎 SPARQL Query Results:")
    for row in g.query(query):
        print(f"Vulnerability: {row.vuln} --> Component: {row.component}")

if __name__ == "__main__":
    run_sparql_query(TTL_FILE)
