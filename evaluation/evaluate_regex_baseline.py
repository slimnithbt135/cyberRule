#!/usr/bin/env python3
"""
Regex Baseline for CVE Entity Extraction
A middle-ground baseline between simple keyword matching and CyberRule.
Uses curated regex patterns with basic normalization but no contextual constraints.
Author: Thabet Slimani
"""

import json
import re
from pathlib import Path
from typing import Set, Dict, List
import sys

# ============================================================================
# REGEX PATTERNS - Curated set capturing linguistic variation
# ============================================================================

REGEX_PATTERNS = {
    # Injection vulnerabilities
    'SQLInjection': [
        r'\bsql\s*injection\b',
        r'\bsqli\b',
        r'\bblind\s*sql\b',
        r'\bsql\s*injection\s*vulnerability',
    ],
    
    'CommandInjection': [
        r'\bcommand\s*injection\b',
        r'\bos\s*command\s*injection\b',
        r'\bcode\s*injection\b',
    ],
    
    # XSS variants
    'CrossSiteScripting': [
        r'\bcross[-\s]?site\s+scripting\b',
        r'\bxss\b',
        r'\breflected\s+xss\b',
        r'\bstored\s+xss\b',
        r'\bdom\s+xss\b',
    ],
    
    # Buffer/Memory issues
    'BufferOverflow': [
        r'\bbuffer\s*overflow\b',
        r'\bstack\s*overflow\b',
        r'\bheap\s*overflow\b',
        r'\binteger\s*overflow\b',
        r'\bbuffer\s*over[-]?read\b',
    ],
    
    # Path traversal
    'PathTraversal': [
        r'\bpath\s*traversal\b',
        r'\bdirectory\s*traversal\b',
        r'\bdot\s*dot\s*slash\b',
        r'\b\.\./',
        r'\blfi\b',
        r'\brfi\b',
    ],
    
    # Authentication issues
    'AuthenticationBypass': [
        r'\bauthentication\s*bypass\b',
        r'\bauth\s*bypass\b',
        r'\blogin\s*bypass\b',
        r'\bmissing\s*authentication\b',
    ],
    
    # Authorization issues
    'PrivilegeEscalation': [
        r'\bprivilege\s*escalation\b',
        r'\bprivilege\s*elevation\b',
        r'\bincorrect\s*authorization\b',
        r'\bmissing\s*authorization\b',
        r'\bidor\b',
        r'\binsecure\s*direct\s*object\s*reference',
    ],
    
    # CSRF
    'CrossSiteRequestForgery': [
        r'\bcross[-\s]?site\s*request\s*forgery',
        r'\bcsrf\b',
        r'\bxsrf\b',
    ],
    
    # Information disclosure
    'InformationDisclosure': [
        r'\binformation\s*disclosure\b',
        r'\bsensitive\s*data\s*exposure',
        r'\bdata\s*leak',
        r'\binformation\s*leak',
    ],
    
    # XXE
    'XMLExternalEntity': [
        r'\bxml\s*external\s*entity\b',
        r'\bxxe\b',
        r'\bxml\s*entity\s*expansion',
    ],
    
    # SSRF
    'ServerSideRequestForgery': [
        r'\bserver[-\s]?side\s*request\s*forgery',
        r'\bssrf\b',
    ],
    
    # Deserialization
    'Deserialization': [
        r'\binsecure\s*deserialization\b',
        r'\bdeserialization\s*of\s*untrusted\s*data',
    ],
    
    # Denial of Service
    'DenialOfService': [
        r'\bdenial\s*of\s*service\b',
        r'\bdos\b',
        r'\bresource\s*exhaustion',
        r'\balgorithmic\s*complexity',
    ],
    
    # File upload
    'UnrestrictedFileUpload': [
        r'\bunrestricted\s*file\s*upload',
        r'\barbitrary\s*file\s*upload',
    ],
    
    # Memory safety
    'UseAfterFree': [
        r'\buse[-\s]?after[-\s]?free\b',
        r'\buaf\b',
    ],
    
    'NullPointerDereference': [
        r'\bnull\s*pointer\s*dereference',
        r'\bnull\s*pointer',
    ],
    
    # Race conditions
    'RaceCondition': [
        r'\brace\s*condition',
        r'\btoctou\b',
        r'\btime\s*of\s*check\s*time\s*of\s*use',
    ],
    
    # Open redirect
    'OpenRedirect': [
        r'\bopen\s*redirect',
        r'\burl\s*redirection',
    ],
    
    # Cryptographic issues
    'HardcodedCredentials': [
        r'\bhardcoded\s*credentials?\b',
        r'\bhardcoded\s*password',
        r'\bhardcoded\s*key',
    ],
    
    # Remote Code Execution
    'RemoteCodeExecution': [
        r'\bremote\s*code\s*execution\b',
        r'\brce\b',
        r'\barbitrary\s*code\s*execution',
    ],
    
    # Products (basic patterns)
    'Wordpress': [r'\bwordpress\b'],
    'Microsoft': [r'\bmicrosoft\b'],
    'Windows': [r'\bwindows\b'],
    'Linux': [r'\blinux\b'],
    'Apache': [r'\bapache\b'],
    'Nginx': [r'\bnginx\b'],
    'Oracle': [r'\boracle\b'],
    'Cisco': [r'\bcisco\b'],
    'Adobe': [r'\badobe\b'],
    'MySQL': [r'\bmysql\b'],
    'PostgreSQL': [r'\bpostgresql\b'],
    'MongoDB': [r'\bmongodb\b'],
    'Redis': [r'\bredis\b'],
    'Elasticsearch': [r'\belasticsearch\b'],
    'Joomla': [r'\bjoomla\b'],
    'Drupal': [r'\bdrupal\b'],
    'Magento': [r'\bmagento\b'],
    'GitLab': [r'\bgitlab\b'],
    'GitHub': [r'\bgithub\b'],
    'Jira': [r'\bjira\b'],
    'Confluence': [r'\bconfluence\b'],
    'VMware': [r'\bvmware\b'],
    'Citrix': [r'\bcitrix\b'],
    'SAP': [r'\bsap\b'],
    'Salesforce': [r'\bsalesforce\b'],
    'AWS': [r'\baws\b', r'\bamazon\s*web\s*services\b'],
    'Azure': [r'\bazure\b'],
    'GCP': [r'\bgcp\b', r'\bgoogle\s*cloud\b'],
}


# ============================================================================
# NORMALIZATION MAPPINGS
# ============================================================================

NORMALIZATION_MAP = {
    # SQL injection variants
    'sqlinjection': 'SQLInjection',
    'sqli': 'SQLInjection',
    'blindsqli': 'SQLInjection',
    
    # XSS variants
    'crosssitescripting': 'CrossSiteScripting',
    'xss': 'CrossSiteScripting',
    'storedxss': 'CrossSiteScripting',
    'reflectedxss': 'CrossSiteScripting',
    'domxss': 'CrossSiteScripting',
    
    # Command injection variants
    'commandinjection': 'CommandInjection',
    'codeinjection': 'CommandInjection',
    'oscommandinjection': 'CommandInjection',
    
    # Buffer overflow variants
    'bufferoverflow': 'BufferOverflow',
    'stackoverflow': 'BufferOverflow',
    'heapoverflow': 'BufferOverflow',
    'integeroverflow': 'BufferOverflow',
    'bufferoverread': 'BufferOverflow',
    
    # Path traversal variants
    'pathtraversal': 'PathTraversal',
    'directorytraversal': 'PathTraversal',
    'lfi': 'PathTraversal',
    'rfi': 'PathTraversal',
    'zipslip': 'PathTraversal',
    
    # Authentication variants
    'authenticationbypass': 'AuthenticationBypass',
    'authbypass': 'AuthenticationBypass',
    'missingauthentication': 'AuthenticationBypass',
    
    # Authorization variants
    'privilegeescalation': 'PrivilegeEscalation',
    'incorrectauthorization': 'PrivilegeEscalation',
    'missingauthorization': 'PrivilegeEscalation',
    'idor': 'PrivilegeEscalation',
    'insecuredirectobjectreference': 'PrivilegeEscalation',
    
    # CSRF variants
    'crosssiterequestforgery': 'CrossSiteRequestForgery',
    'csrf': 'CrossSiteRequestForgery',
    'xsrf': 'CrossSiteRequestForgery',
    
    # Information disclosure variants
    'informationdisclosure': 'InformationDisclosure',
    'sensitivedataexposure': 'InformationDisclosure',
    'dataleak': 'InformationDisclosure',
    
    # XXE variants
    'xmlexternalentity': 'XMLExternalEntity',
    'xxe': 'XMLExternalEntity',
    
    # SSRF variants
    'serversiderequestforgery': 'ServerSideRequestForgery',
    'ssrf': 'ServerSideRequestForgery',
    
    # Deserialization variants
    'deserialization': 'Deserialization',
    'insecuredeserialization': 'Deserialization',
    'deserializationofuntrusteddata': 'Deserialization',
    
    # DoS variants
    'denialofservice': 'DenialOfService',
    'dos': 'DenialOfService',
    'resourceexhaustion': 'DenialOfService',
    
    # File upload variants
    'unrestrictedfileupload': 'UnrestrictedFileUpload',
    'arbitraryfileupload': 'UnrestrictedFileUpload',
    
    # Memory safety variants
    'useafterfree': 'UseAfterFree',
    'uaf': 'UseAfterFree',
    'danglingpointer': 'UseAfterFree',
    'nullpointerdereference': 'NullPointerDereference',
    
    # Race condition variants
    'racecondition': 'RaceCondition',
    'toctou': 'RaceCondition',
    'timeofchecktimeofuse': 'RaceCondition',
    
    # Open redirect variants
    'openredirect': 'OpenRedirect',
    'urlredirection': 'OpenRedirect',
    
    # Crypto variants
    'hardcodedcredentials': 'HardcodedCredentials',
    'hardcodedpassword': 'HardcodedCredentials',
    'hardcodedkey': 'HardcodedCredentials',
    
    # RCE variants
    'remotecodeexecution': 'RemoteCodeExecution',
    'rce': 'RemoteCodeExecution',
    'arbitrarycodeexecution': 'RemoteCodeExecution',
}


class RegexBaselineExtractor:
    """
    Regex-based baseline extractor.
    Uses curated regex patterns with normalization but no contextual constraints.
    """
    
    def __init__(self):
        self.patterns = REGEX_PATTERNS
        self.normalization = NORMALIZATION_MAP
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for efficiency."""
        self.compiled = {}
        for entity_type, patterns in self.patterns.items():
            self.compiled[entity_type] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
    
    def extract(self, description: str) -> Set[str]:
        """
        Extract entities from CVE description using regex patterns.
        
        Args:
            description: CVE description text
            
        Returns:
            Set of extracted entity names
        """
        if not description:
            return set()
        
        extracted = set()
        desc_lower = description.lower()
        
        # Apply all patterns
        for entity_type, compiled_patterns in self.compiled.items():
            for pattern in compiled_patterns:
                if pattern.search(desc_lower):
                    # Normalize the entity name
                    normalized = self._normalize(entity_type)
                    extracted.add(normalized)
                    break  # Only add once per entity type
        
        return extracted
    
    def _normalize(self, entity: str) -> str:
        """Normalize entity name using normalization map."""
        normalized = re.sub(r'[^a-z0-9]', '', entity.lower())
        return self.normalization.get(normalized, entity)


def evaluate_regex_baseline(reference_file: str, output_file: str):
    """
    Evaluate regex baseline against reference standard.
    
    Args:
        reference_file: Path to reference standard JSON
        output_file: Path to save evaluation results
    """
    from evaluate_cyberrule import calculate_metrics, analyze_by_category
    
    # Load reference standard
    with open(reference_file, 'r', encoding='utf-8') as f:
        reference = json.load(f)
    
    extractor = RegexBaselineExtractor()
    
    results = []
    all_predicted = []
    all_actual = []
    
    print("Evaluating Regex Baseline...")
    print("=" * 70)
    
    for i, ref in enumerate(reference):
        cve_id = ref['cve_id']
        description = ref['description']
        
        predicted = extractor.extract(description)
        actual = set(ref.get('ground_truth_classes', []))
        
        metrics = calculate_metrics(predicted, actual)
        
        results.append({
            'cve_id': cve_id,
            'predicted': list(predicted),
            'actual': list(actual),
            'metrics': metrics
        })
        
        all_predicted.extend(predicted)
        all_actual.extend(actual)
        
        if (i + 1) % 50 == 0:
            print(f"Processed {i+1}/{len(reference)} CVEs...")
    
    # Calculate overall metrics
    overall = calculate_metrics(set(all_predicted), set(all_actual))
    category_metrics = analyze_by_category(results)
    
    summary = {
        'system': 'Regex Baseline',
        'total_cves': len(reference),
        'overall_metrics': overall,
        'category_metrics': category_metrics,
        'per_cve_results': results
    }
    
    # Save results
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    
    print("\n" + "=" * 70)
    print("REGEX BASELINE EVALUATION RESULTS")
    print("=" * 70)
    print(f"Total CVEs evaluated: {len(reference)}")
    print(f"Overall Precision: {overall['precision']:.3f}")
    print(f"Overall Recall:    {overall['recall']:.3f}")
    print(f"Overall F1-Score:  {overall['f1']:.3f}")
    print(f"\nResults saved to: {output_path}")
    print("=" * 70)
    
    return summary


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Regex Baseline Evaluator')
    parser.add_argument('--reference', default='data/reference_standard_200.json',
                        help='Path to reference standard JSON')
    parser.add_argument('--output', default='data/regex_baseline_evaluation.json',
                        help='Path to save evaluation results')
    args = parser.parse_args()
    
    evaluate_regex_baseline(args.reference, args.output)
