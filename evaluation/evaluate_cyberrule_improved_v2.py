#!/usr/bin/env python3
"""
Refined CyberRule V2 Evaluation with Strict Entity Filtering
Only maps entities that are directly relevant to security classification.
"""

import json
import sys
import re
from pathlib import Path
from typing import List, Set, Dict
from collections import defaultdict
import numpy as np

# Import the enhanced extractor
sys.path.insert(0, str(Path(__file__).parent))
from CyberRule_Entity_Extractor_V2 import CyberRuleExtractor, CYBERRULE_PATTERNS

# ============================================================================
# STRICT ENTITY TO CLASS MAPPING
# Only high-confidence security-relevant mappings
# ============================================================================

# Core vulnerability type mappings
VULNERABILITY_MAPPINGS = {
    # Injection attacks
    'sql injection': 'SqlInjection',
    'sqli': 'SqlInjection',
    'blind sql injection': 'SqlInjection',
    'command injection': 'Cwe77',
    'os command injection': 'Cwe78',
    'code injection': 'CodeInjection',
    'remote code execution': 'Cwe94',
    'rce': 'Cwe94',

    # XSS variants
    'cross-site scripting': 'CrossSiteScripting',
    'xss': 'CrossSiteScripting',
    'stored xss': 'CrossSiteScripting',
    'reflected xss': 'CrossSiteScripting',
    'dom xss': 'CrossSiteScripting',

    # Buffer/Memory issues
    'buffer overflow': 'BufferOverflow',
    'stack overflow': 'BufferOverflow',
    'heap overflow': 'BufferOverflow',
    'stack-based buffer overflow': 'BufferOverflow',
    'heap-based buffer overflow': 'BufferOverflow',
    'integer overflow': 'Cwe190',
    'use-after-free': 'Cwe416',
    'uaf': 'Cwe416',
    'double free': 'Cwe415',
    'out-of-bounds read': 'OutOfBoundsRead',
    'out-of-bounds write': 'Cwe787',
    'oob read': 'OutOfBoundsRead',
    'oob write': 'Cwe787',
    'memory corruption': 'Cwe119',

    # Path/File issues
    'path traversal': 'PathTraversal',
    'directory traversal': 'PathTraversal',
    'unrestricted file upload': 'UnrestrictedFileUpload',
    'arbitrary file upload': 'UnrestrictedFileUpload',
    'arbitrary file read': 'Cwe22',
    'arbitrary file write': 'Cwe22',
    'arbitrary file deletion': 'Cwe22',

    # Authentication/Authorization
    'authentication bypass': 'AuthenticationBypass',
    'missing authentication': 'MissingAuthentication',
    'missing authorization': 'MissingAuthorization',
    'incorrect authorization': 'IncorrectAuthorization',
    'privilege escalation': 'PrivilegeEscalation',
    'local privilege escalation': 'PrivilegeEscalation',
    'hard-coded credentials': 'UseOfHardcodedCredentials',
    'hard-coded password': 'UseOfHardcodedCredentials',
    'use of hard-coded cryptographic key': 'Cwe321',

    # Web attacks
    'cross-site request forgery': 'CrossSiteRequestForgery',
    'csrf': 'CrossSiteRequestForgery',
    'xml external entity': 'Cwe611',
    'xxe': 'Cwe611',
    'server-side request forgery': 'Cwe918',
    'ssrf': 'Cwe918',
    'open redirect': 'OpenRedirect',
    'insecure deserialization': 'DeserializationOfUntrustedData',
    'deserialization of untrusted data': 'DeserializationOfUntrustedData',

    # Information/DoS
    'information disclosure': 'InformationDisclosure',
    'sensitive data exposure': 'InformationDisclosure',
    'sensitive information disclosure': 'InformationDisclosure',
    'denial of service': 'DenialOfService',
    'dos': 'DenialOfService',
    'remote denial of service': 'DenialOfService',

    # Race conditions
    'race condition': 'Cwe362',
    'time-of-check time-of-use': 'Cwe367',
    'toctou': 'Cwe367',

    # Other weaknesses
    'null pointer dereference': 'Cwe476',
    'format string vulnerability': 'Cwe134',
    'type confusion': 'Cwe843',
    'integer underflow': 'Cwe191',
    'uncontrolled resource consumption': 'Cwe400',
}

# Product/Vendor mappings (only if explicitly in reference)
PRODUCT_MAPPINGS = {
    'wordpress': 'Wordpress',
    'wordpress plugin': 'Wordpress',
    'wordpress theme': 'Wordpress',
    'microsoft': 'Microsoft',
    'windows': 'Windows',
    'linux': 'Linux',
    'apache': 'Apache',
    'oracle': 'Oracle',
    'cisco': 'Cisco',
    'chrome': 'Chrome',
    'android': 'Android',
    'ios': 'Ios',
    'php': 'Php',
    'java': 'Java',
    'python': 'Python',
    'javascript': 'Javascript',
}

# CWE number mappings
CWE_MAPPINGS = {
    'cwe79': 'CrossSiteScripting',
    'cwe89': 'SqlInjection',
    'cwe94': 'CodeInjection',
    'cwe77': 'Cwe77',
    'cwe78': 'Cwe78',
    'cwe22': 'PathTraversal',
    'cwe434': 'UnrestrictedFileUpload',
    'cwe416': 'Cwe416',
    'cwe787': 'Cwe787',
    'cwe121': 'BufferOverflow',
    'cwe122': 'BufferOverflow',
    'cwe125': 'OutOfBoundsRead',
    'cwe200': 'InformationDisclosure',
    'cwe287': 'AuthenticationBypass',
    'cwe306': 'MissingAuthentication',
    'cwe862': 'MissingAuthorization',
    'cwe863': 'IncorrectAuthorization',
    'cwe269': 'PrivilegeEscalation',
    'cwe352': 'CrossSiteRequestForgery',
    'cwe611': 'Cwe611',
    'cwe918': 'Cwe918',
    'cwe502': 'DeserializationOfUntrustedData',
    'cwe362': 'Cwe362',
    'cwe367': 'Cwe367',
    'cwe400': 'DenialOfService',
    'cwe798': 'UseOfHardcodedCredentials',
    'cwe259': 'UseOfHardcodedCredentials',
    'cwe321': 'Cwe321',
    'cwe190': 'Cwe190',
    'cwe191': 'Cwe191',
    'cwe476': 'Cwe476',
    'cwe134': 'Cwe134',
    'cwe843': 'Cwe843',
    'cwe415': 'Cwe415',
    'cwe119': 'Cwe119',
    'cwe120': 'Cwe120',
    'cwe131': 'Cwe131',
    'cwe167': 'Cwe167',
    'cwe285': 'Cwe285',
    'cwe286': 'Cwe286',
    'cwe290': 'Cwe290',
    'cwe295': 'Cwe295',
    'cwe330': 'Cwe330',
    'cwe521': 'Cwe521',
    'cwe732': 'Cwe732',
    'cwe770': 'Cwe770',
    'cwe841': 'Cwe841',
    'cwe202': 'Cwe202',
    'cwe209': 'Cwe209',
    'cwe284': 'Cwe284',
    'cwe639': 'Cwe639',
    'cwe23': 'Cwe23',
    'cwe24': 'Cwe24',
    'cwe667': 'Cwe667',
    'cwe427': 'Cwe427',
}

# Categories to EXCLUDE (too generic, not security-relevant)
EXCLUDED_CATEGORIES = {
    'ProgrammingLanguage',  # PHP, Java, Python - not security classes
    'FileType',            # PDF, ZIP, etc. - not security classes
    'Protocol',            # HTTP, FTP, etc. - not security classes
    'Hardware',            # CPU, RAM, etc. - not security classes
    'CryptoIssue',         # Often too generic
}

# Minimum confidence threshold for entity acceptance
MIN_CONFIDENCE = 0.7


def normalize_text(text: str) -> str:
    """Normalize text for matching."""
    if not text:
        return ""
    text = text.lower().strip()
    text = re.sub(r'[^a-z0-9]', '', text)
    return text


def map_entity_strict(entity_text: str, entity_label: str, confidence: float) -> str:
    """
    Strict entity mapping with confidence and category filtering.
    Returns mapped class or None if entity should be excluded.
    """
    # Skip low confidence entities
    if confidence < MIN_CONFIDENCE:
        return None

    # Skip excluded categories
    if entity_label in EXCLUDED_CATEGORIES:
        return None

    entity_lower = entity_text.lower().strip()
    entity_norm = normalize_text(entity_text)

    # Check vulnerability mappings first (highest priority)
    if entity_lower in VULNERABILITY_MAPPINGS:
        return VULNERABILITY_MAPPINGS[entity_lower]
    if entity_norm in VULNERABILITY_MAPPINGS:
        return VULNERABILITY_MAPPINGS[entity_norm]

    # Check for CWE number in entity text
    cwe_match = re.search(r'cwe-?(\d+)', entity_lower)
    if cwe_match:
        cwe_num = f"cwe{cwe_match.group(1)}"
        if cwe_num in CWE_MAPPINGS:
            return CWE_MAPPINGS[cwe_num]

    # Check product mappings (only for ProductType category)
    if entity_label == 'ProductType':
        if entity_lower in PRODUCT_MAPPINGS:
            return PRODUCT_MAPPINGS[entity_lower]
        if entity_norm in PRODUCT_MAPPINGS:
            return PRODUCT_MAPPINGS[entity_norm]

    # Partial matching for multi-word vulnerability types
    for key, value in VULNERABILITY_MAPPINGS.items():
        if key in entity_lower:
            return value

    # No valid mapping found
    return None


def calculate_metrics(predicted: Set[str], actual: Set[str]) -> Dict:
    """Calculate precision, recall, F1."""
    tp = len(predicted & actual)
    fp = len(predicted - actual)
    fn = len(actual - predicted)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        'precision': round(precision, 3),
        'recall': round(recall, 3),
        'f1': round(f1, 3),
        'tp': tp, 'fp': fp, 'fn': fn
    }


def calculate_metrics_from_counts(tp: int, fp: int, fn: int) -> Dict:
    """Calculate metrics from counts."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return {'precision': precision, 'recall': recall, 'f1': f1, 'tp': tp, 'fp': fp, 'fn': fn}


def bootstrap_ci(results: List[Dict], n_iterations: int = 1000, ci: float = 0.95) -> Dict:
    """Calculate bootstrap confidence intervals."""
    if not results:
        return None

    boot_precisions, boot_recalls, boot_f1s = [], [], []
    n_samples = len(results)
    alpha = (1 - ci) / 2

    for _ in range(n_iterations):
        indices = np.random.choice(n_samples, size=n_samples, replace=True)
        sample = [results[idx] for idx in indices]

        total_tp = sum(r['metrics']['tp'] for r in sample)
        total_fp = sum(r['metrics']['fp'] for r in sample)
        total_fn = sum(r['metrics']['fn'] for r in sample)

        metrics = calculate_metrics_from_counts(total_tp, total_fp, total_fn)
        boot_precisions.append(metrics['precision'])
        boot_recalls.append(metrics['recall'])
        boot_f1s.append(metrics['f1'])

    def get_stats(values):
        return {
            'mean': round(np.mean(values), 3),
            'std': round(np.std(values, ddof=1), 3),
            'median': round(np.median(values), 3),
            'ci_lower': round(np.percentile(values, alpha * 100), 3),
            'ci_upper': round(np.percentile(values, (1 - alpha) * 100), 3),
        }

    return {
        'precision': get_stats(boot_precisions),
        'recall': get_stats(boot_recalls),
        'f1': get_stats(boot_f1s),
        'n_iterations': n_iterations
    }


class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.bool_):
            return bool(obj)
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return super().default(obj)


def evaluate_cyberrule_v2_refined(
    reference_file: str,
    output_file: str,
    confidence_threshold: float = 0.6,
    bootstrap: bool = True
) -> Dict:
    """
    Evaluate CyberRule V2 with strict entity filtering.
    """

    print("=" * 80)
    print("CYBERRULE V2 EVALUATION (REFINED - STRICT FILTERING)")
    print("=" * 80)
    print(f"Confidence threshold: {confidence_threshold}")
    print(f"Minimum confidence for mapping: {MIN_CONFIDENCE}")
    print(f"Excluded categories: {', '.join(EXCLUDED_CATEGORIES)}")
    print(f"Pattern categories: {len(CYBERRULE_PATTERNS)}")
    print("-" * 80)

    # Load reference
    with open(reference_file, 'r', encoding='utf-8') as f:
        reference = json.load(f)

    print(f"Reference CVEs: {len(reference)}")

    extractor = CyberRuleExtractor(confidence_threshold=confidence_threshold)
    results = []

    # Statistics
    stats_by_category = defaultdict(lambda: {'extracted': 0, 'mapped': 0, 'filtered': 0})

    for i, ref in enumerate(reference):
        cve_id = ref['cve_id']
        description = ref['description']
        actual_classes = set(ref.get('ground_truth_classes', []))

        # Extract entities
        entities = extractor.extract_entities(description)

        # Map entities to classes with strict filtering
        mapped_classes = set()
        filtered_entities = []

        for entity in entities:
            entity_text = entity['text']
            entity_label = entity['label']
            confidence = entity['confidence']

            stats_by_category[entity_label]['extracted'] += 1

            # Try to map
            mapped_class = map_entity_strict(entity_text, entity_label, confidence)

            if mapped_class:
                mapped_classes.add(mapped_class)
                stats_by_category[entity_label]['mapped'] += 1
            else:
                filtered_entities.append({
                    'text': entity_text,
                    'label': entity_label,
                    'confidence': confidence
                })
                stats_by_category[entity_label]['filtered'] += 1

        # Calculate metrics
        metrics = calculate_metrics(mapped_classes, actual_classes)

        results.append({
            'cve_id': cve_id,
            'predicted': list(mapped_classes),
            'actual': list(actual_classes),
            'metrics': metrics,
            'filtered_count': len(filtered_entities),
            'total_extracted': len(entities)
        })

        if (i + 1) % 50 == 0:
            print(f"  Processed {i+1}/{len(reference)} CVEs...")

    # Overall metrics
    total_tp = sum(r['metrics']['tp'] for r in results)
    total_fp = sum(r['metrics']['fp'] for r in results)
    total_fn = sum(r['metrics']['fn'] for r in results)
    overall = calculate_metrics_from_counts(total_tp, total_fp, total_fn)

    # Bootstrap CI
    bootstrap_stats = None
    if bootstrap and len(results) > 0:
        print("\nCalculating bootstrap confidence intervals...")
        bootstrap_stats = bootstrap_ci(results, n_iterations=1000, ci=0.95)

    # Coverage stats
    cves_with_predictions = sum(1 for r in results if len(r['predicted']) > 0)
    cves_with_matches = sum(1 for r in results if r['metrics']['tp'] > 0)

    # Summary
    summary = {
        'system': 'CyberRule V2 (Refined - Strict Filtering)',
        'version': '2.0-refined',
        'total_cves': len(reference),
        'confidence_threshold': confidence_threshold,
        'min_mapping_confidence': MIN_CONFIDENCE,
        'excluded_categories': list(EXCLUDED_CATEGORIES),
        'overall_metrics': {
            'precision': round(overall['precision'], 3),
            'recall': round(overall['recall'], 3),
            'f1': round(overall['f1'], 3),
            'tp': total_tp,
            'fp': total_fp,
            'fn': total_fn
        },
        'coverage': {
            'cves_with_predictions': cves_with_predictions,
            'cves_with_matches': cves_with_matches,
            'prediction_coverage_pct': round(cves_with_predictions / len(reference) * 100, 1),
            'match_coverage_pct': round(cves_with_matches / len(reference) * 100, 1)
        },
        'bootstrap_ci': bootstrap_stats,
        'category_stats': dict(stats_by_category),
        'per_cve_results': results
    }

    # Save results
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, cls=NumpyEncoder)

    # Print summary
    print("\n" + "=" * 80)
    print("CYBERRULE V2 RESULTS (REFINED)")
    print("=" * 80)
    print(f"Total CVEs: {len(reference)}")
    print(f"Precision: {overall['precision']:.3f} ({total_tp}/{total_tp + total_fp})")
    print(f"Recall:    {overall['recall']:.3f} ({total_tp}/{total_tp + total_fn})")
    print(f"F1-Score:  {overall['f1']:.3f}")
    print(f"\nCoverage:")
    print(f"  CVEs with predictions: {cves_with_predictions} ({summary['coverage']['prediction_coverage_pct']}%)")
    print(f"  CVEs with matches: {cves_with_matches} ({summary['coverage']['match_coverage_pct']}%)")

    if bootstrap_stats:
        p_stats = bootstrap_stats['precision']
        print(f"\n95% CI Precision: [{p_stats['ci_lower']:.3f} – {p_stats['ci_upper']:.3f}] (mean: {p_stats['mean']:.3f})")

    print(f"\nCategory Statistics (extracted → mapped | filtered):")
    for cat, counts in sorted(stats_by_category.items(), key=lambda x: x[1]['extracted'], reverse=True):
        print(f"  {cat}: {counts['extracted']} → {counts['mapped']} | {counts['filtered']}")

    print(f"\nResults saved: {output_file}")
    print("=" * 80)

    return summary


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='CyberRule V2 Evaluation with Strict Entity Filtering'
    )
    parser.add_argument('--reference', required=True, help='Reference standard JSON file')
    parser.add_argument('--output', required=True, help='Output evaluation JSON file')
    parser.add_argument('--threshold', type=float, default=0.6, help='Confidence threshold (0.0-1.0)')
    parser.add_argument('--no-bootstrap', action='store_true', help='Skip bootstrap CI calculation')

    args = parser.parse_args()

    evaluate_cyberrule_v2_refined(
        args.reference,
        args.output,
        args.threshold,
        bootstrap=not args.no_bootstrap
    )
