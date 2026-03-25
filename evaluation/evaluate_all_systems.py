#!/usr/bin/env python3
"""
UPDATED Four-Way Comparison: CyberRule V2 vs Regex Baseline vs Simple Baseline vs Llama 3.3
Includes: McNemar's test, bootstrap confidence intervals, effect size analysis
"""

import json
import sys
from pathlib import Path
from typing import List, Set, Dict, Tuple
import numpy as np
from collections import defaultdict
import re
import argparse

try:
    from scipy import stats
    from statsmodels.stats.contingency_tables import mcnemar
    SCIPY_AVAILABLE = True
    STATSMODELS_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    STATSMODELS_AVAILABLE = False
    print("Warning: scipy/statsmodels not available, statistical tests will be skipped")


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


def normalize(text: str) -> str:
    """Normalize text for comparison."""
    return re.sub(r'[^a-z0-9]', '', text.lower())


def load_evaluation(file_path: str, system_name: str) -> Dict:
    """Load evaluation results from JSON file."""
    if not Path(file_path).exists():
        print(f"Warning: File not found: {file_path}")
        return None

    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Get per-CVE results
    if 'per_cve_results' in data:
        results = data['per_cve_results']
    elif 'results' in data:
        results = data['results']
    elif isinstance(data, list):
        results = data
    else:
        results = []

    # Use overall_metrics directly if available
    overall = data.get('overall_metrics', {})

    # If overall_metrics not present, fall back to calculation
    if not overall and results:
        total_tp = sum(r.get('metrics', {}).get('tp', 0) for r in results)
        total_fp = sum(r.get('metrics', {}).get('fp', 0) for r in results)
        total_fn = sum(r.get('metrics', {}).get('fn', 0) for r in results)

        precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
        recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        overall = {
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'tp': total_tp,
            'fp': total_fp,
            'fn': total_fn
        }

    return {
        'system': system_name,
        'results': results,
        'overall': overall
    }


def calc_metrics(tp: int, fp: int, fn: int) -> Dict:
    """Calculate metrics from counts."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        'precision': round(precision, 3),
        'recall': round(recall, 3),
        'f1': round(f1, 3),
        'tp': tp,
        'fp': fp,
        'fn': fn
    }


def bootstrap_ci(results: List[Dict], n_iterations: int = 1000, ci: float = 0.95) -> Dict:
    """Calculate bootstrap confidence intervals."""
    if not results:
        return None

    precisions, recalls, f1s = [], [], []
    n_samples = len(results)
    alpha = (1 - ci) / 2

    for _ in range(n_iterations):
        indices = np.random.choice(n_samples, size=n_samples, replace=True)
        sample = [results[idx] for idx in indices]

        tp = sum(r['metrics']['tp'] for r in sample)
        fp = sum(r['metrics']['fp'] for r in sample)
        fn = sum(r['metrics']['fn'] for r in sample)

        m = calc_metrics(tp, fp, fn)
        precisions.append(m['precision'])
        recalls.append(m['recall'])
        f1s.append(m['f1'])

    def get_stats(values):
        return {
            'mean': round(np.mean(values), 3),
            'std': round(np.std(values, ddof=1), 3),
            'median': round(np.median(values), 3),
            'ci_lower': round(np.percentile(values, alpha * 100), 3),
            'ci_upper': round(np.percentile(values, (1 - alpha) * 100), 3),
        }

    return {
        'precision': get_stats(precisions),
        'recall': get_stats(recalls),
        'f1': get_stats(f1s),
        'n_iterations': n_iterations
    }


def perform_mcnemar_test(s1_results: List[Dict], s2_results: List[Dict], 
                         name1: str, name2: str) -> Dict:
    """
    Perform McNemar's test comparing two systems at the entity level.

    Constructs a contingency table:
    - Both correct: a
    - Sys1 correct, Sys2 wrong: b  
    - Sys1 wrong, Sys2 correct: c
    - Both wrong: d

    McNemar's test focuses on b and c (discordant pairs).
    """
    if not STATSMODELS_AVAILABLE:
        return {
            'error': 'statsmodels not installed',
            'b': None, 'c': None, 'pvalue': None, 'significant': None
        }

    a = b = c = d = 0  # contingency table cells

    for r1, r2 in zip(s1_results, s2_results):
        # Get predicted and actual entities for each system
        p1 = set(normalize(p) for p in r1.get('predicted', []))
        a1 = set(normalize(a_entity) for a_entity in r1.get('actual', []))
        p2 = set(normalize(p) for p in r2.get('predicted', []))
        a2 = set(normalize(a_entity) for a_entity in r2.get('actual', []))

        # Use union of actual entities from both systems as ground truth
        all_actual = a1 | a2

        for entity in all_actual:
            s1_correct = entity in p1 and entity in a1
            s2_correct = entity in p2 and entity in a2

            if s1_correct and s2_correct:
                a += 1
            elif s1_correct and not s2_correct:
                b += 1
            elif not s1_correct and s2_correct:
                c += 1
            else:
                d += 1

    # Construct contingency table for statsmodels
    # Format: [[a, b], [c, d]]
    table = [[a, b], [c, d]]

    # Perform McNemar's test
    # Use exact=False for chi-square approximation (appropriate for large samples)
    # Use correction=True for continuity correction
    try:
        result = mcnemar(table, exact=False, correction=True)
        statistic = result.statistic
        pvalue = result.pvalue
    except Exception as e:
        # Fallback to manual calculation
        if b + c > 0:
            statistic = (abs(b - c) - 1) ** 2 / (b + c)
            pvalue = 1 - stats.chi2.cdf(statistic, df=1)
        else:
            statistic = 0
            pvalue = 1.0

    return {
        'contingency_table': {'a': a, 'b': b, 'c': c, 'd': d},
        'b': b,
        'c': c,
        'discordant_total': b + c,
        'statistic': round(statistic, 4),
        'pvalue': round(pvalue, 6),
        'significant': pvalue < 0.05,
        'significance_level': '***' if pvalue < 0.001 else ('**' if pvalue < 0.01 else ('*' if pvalue < 0.05 else 'ns')),
        'winner': name1 if b > c else (name2 if c > b else 'Tie'),
        'interpretation': 'Significant' if pvalue < 0.05 else 'Not significant'
    }


def compare_four_systems(
    cyberrule_file: str,
    regex_file: str,
    baseline_file: str,
    llama_file: str,
    output_file: str = None,
    n_bootstrap: int = 1000
):
    """
    Four-way comparison: CyberRule vs Regex vs Baseline vs Llama 3.3
    Includes McNemar's test and bootstrap confidence intervals
    """

    print("=" * 80)
    print("FOUR-WAY SYSTEM COMPARISON WITH McNEMAR'S TEST")
    print("CyberRule V2 | Regex Baseline | Simple Baseline | Llama 3.3")
    print("=" * 80)

    # Load all four systems
    systems = {}
    system_files = [
        ('cyberrule', cyberrule_file, 'CyberRule V2'),
        ('regex', regex_file, 'Regex Baseline'),
        ('baseline', baseline_file, 'Simple Baseline'),
        ('llama', llama_file, 'Llama 3.3')
    ]

    print("\nLoading evaluation results...")
    for key, file_path, label in system_files:
        data = load_evaluation(file_path, label)
        if data:
            systems[key] = data
            print(f"  ✓ {label}: {len(data['results'])} CVEs")
        else:
            print(f"  ✗ {label}: File not found")

    if len(systems) < 2:
        print("\nError: Need at least 2 systems for comparison")
        return

    # Find common CVEs across ALL available systems
    common_cves = None
    for name, data in systems.items():
        cves = {r['cve_id'] for r in data['results']}
        common_cves = cves if common_cves is None else (common_cves & cves)

    print(f"\nCommon CVEs across all systems: {len(common_cves)}")

    # Filter to common CVEs - BUT keep original overall metrics
    filtered_systems = {}
    for name, data in systems.items():
        filtered = [r for r in data['results'] if r['cve_id'] in common_cves]
        filtered.sort(key=lambda x: x['cve_id'])

        filtered_systems[name] = {
            'system': data['system'],
            'results': filtered,
            'overall': data['overall']
        }

    # Print comparison table using original overall metrics
    print("\n" + "=" * 80)
    print("COMPARISON TABLE (Using Original Overall Metrics)")
    print("=" * 80)
    print(f"{'System':<20} {'Precision':<12} {'Recall':<12} {'F1':<12} {'Deterministic':<15}")
    print("-" * 80)

    comparison_data = []

    for key in ['cyberrule', 'regex', 'baseline', 'llama']:
        if key in filtered_systems:
            data = filtered_systems[key]
            overall = data['overall']
            name = data['system']

            deterministic = 'No' if key == 'llama' else 'Yes'

            print(f"{name:<20} {overall['precision']:<12.3f} {overall['recall']:<12.3f} "
                  f"{overall['f1']:<12.3f} {deterministic:<15}")

            comparison_data.append({
                'system': name,
                'key': key,
                'precision': overall['precision'],
                'recall': overall['recall'],
                'f1': overall['f1'],
                'tp': overall.get('tp', 0),
                'fp': overall.get('fp', 0),
                'fn': overall.get('fn', 0),
                'deterministic': deterministic == 'Yes'
            })

    # Bootstrap confidence intervals
    print("\n" + "=" * 80)
    print("BOOTSTRAP CONFIDENCE INTERVALS (95% CI)")
    print("=" * 80)

    bootstrap_results = {}
    for key in ['cyberrule', 'regex', 'baseline', 'llama']:
        if key in filtered_systems:
            data = filtered_systems[key]
            print(f"\n{data['system']}:")

            ci = bootstrap_ci(data['results'], n_iterations=n_bootstrap)
            bootstrap_results[key] = ci

            if ci:
                print(f"  Precision: {ci['precision']['mean']:.3f} "
                      f"[{ci['precision']['ci_lower']:.3f}, {ci['precision']['ci_upper']:.3f}]")
                print(f"  Recall:    {ci['recall']['mean']:.3f} "
                      f"[{ci['recall']['ci_lower']:.3f}, {ci['recall']['ci_upper']:.3f}]")
                print(f"  F1:        {ci['f1']['mean']:.3f} "
                      f"[{ci['f1']['ci_lower']:.3f}, {ci['f1']['ci_upper']:.3f}]")

    # McNemar's test - ALL PAIRWISE COMPARISONS
    print("\n" + "=" * 80)
    print("McNEMAR'S TEST - ALL PAIRWISE COMPARISONS")
    print("=" * 80)
    print("Testing whether discordant predictions are significantly biased toward one system")
    print("-" * 80)

    mcnemar_results = {}
    system_keys = ['cyberrule', 'regex', 'baseline', 'llama']

    # All pairwise combinations
    pairs = [
        ('cyberrule', 'regex'),
        ('cyberrule', 'baseline'),
        ('cyberrule', 'llama'),
        ('regex', 'baseline'),
        ('regex', 'llama'),
        ('baseline', 'llama')
    ]

    print(f"\n{'Comparison':<30} {'b':>6} {'c':>6} {'Total':>8} {'χ²':>10} {'p-value':>12} {'Sig.':>6} {'Winner':<15}")
    print("-" * 100)

    for key1, key2 in pairs:
        if key1 in filtered_systems and key2 in filtered_systems:
            name1 = filtered_systems[key1]['system']
            name2 = filtered_systems[key2]['system']

            result = perform_mcnemar_test(
                filtered_systems[key1]['results'],
                filtered_systems[key2]['results'],
                name1, name2
            )

            pair_name = f"{name1} vs {name2}"
            mcnemar_results[pair_name] = result

            if 'error' not in result:
                print(f"{pair_name:<30} {result['b']:>6} {result['c']:>6} "
                      f"{result['discordant_total']:>8} {result['statistic']:>10.2f} "
                      f"{result['pvalue']:>12.6f} {result['significance_level']:>6} "
                      f"{result['winner']:<15}")
            else:
                print(f"{pair_name:<30} Error: {result['error']}")

    print("\nLegend: b = cases where System 1 correct, System 2 incorrect")
    print("        c = cases where System 1 incorrect, System 2 correct")
    print("        *** p<0.001, ** p<0.01, * p<0.05, ns = not significant")

    # Effect size analysis
    print("\n" + "=" * 80)
    print("EFFECT SIZE ANALYSIS")
    print("=" * 80)
    print(f"{'Comparison':<35} {'F1 Diff':>10} {'Effect Size':>15} {'Magnitude':>12}")
    print("-" * 80)

    f1_values = {d['key']: d['f1'] for d in comparison_data}

    for key1, key2 in pairs:
        if key1 in f1_values and key2 in f1_values:
            f1_1 = f1_values[key1]
            f1_2 = f1_values[key2]
            diff = f1_1 - f1_2

            if abs(diff) > 0.20:
                magnitude = "Very Large"
            elif abs(diff) > 0.10:
                magnitude = "Large"
            elif abs(diff) > 0.05:
                magnitude = "Medium"
            else:
                magnitude = "Small"

            name1 = filtered_systems[key1]['system']
            name2 = filtered_systems[key2]['system']
            print(f"{name1} vs {name2:<20} {diff:>+10.3f} {abs(diff):>15.3f} {magnitude:>12}")

    # Rankings
    print("\n" + "=" * 80)
    print("SYSTEM RANKINGS")
    print("=" * 80)

    # Precision ranking
    print("\nBy Precision:")
    prec_sorted = sorted(comparison_data, key=lambda x: x['precision'], reverse=True)
    for i, d in enumerate(prec_sorted, 1):
        print(f"  {i}. {d['system']}: {d['precision']:.1%}")

    # Recall ranking
    print("\nBy Recall:")
    rec_sorted = sorted(comparison_data, key=lambda x: x['recall'], reverse=True)
    for i, d in enumerate(rec_sorted, 1):
        print(f"  {i}. {d['system']}: {d['recall']:.1%}")

    # F1 ranking
    print("\nBy F1-Score:")
    f1_sorted = sorted(comparison_data, key=lambda x: x['f1'], reverse=True)
    for i, d in enumerate(f1_sorted, 1):
        print(f"  {i}. {d['system']}: {d['f1']:.3f}")

    # Summary interpretation
    print("\n" + "=" * 80)
    print("SUMMARY INTERPRETATION")
    print("=" * 80)

    # Find best system by F1
    best_f1 = max(comparison_data, key=lambda x: x['f1'])
    print(f"\nBest Overall (F1): {best_f1['system']} ({best_f1['f1']:.3f})")

    # Find best precision
    best_prec = max(comparison_data, key=lambda x: x['precision'])
    print(f"Best Precision: {best_prec['system']} ({best_prec['precision']:.1%})")

    # Find best recall
    best_rec = max(comparison_data, key=lambda x: x['recall'])
    print(f"Best Recall: {best_rec['system']} ({best_rec['recall']:.1%})")

    # Determinism analysis
    print(f"\nDeterminism:")
    for d in comparison_data:
        status = "✓ Deterministic" if d['deterministic'] else "✗ Non-deterministic"
        print(f"  {d['system']}: {status}")

    # Statistical significance summary
    print(f"\nStatistical Significance (McNemar's test):")
    sig_count = sum(1 for r in mcnemar_results.values() if r.get('significant', False))
    print(f"  Significant comparisons: {sig_count}/{len(mcnemar_results)}")

    cyberrule_sig = sum(1 for k, r in mcnemar_results.items() 
                       if 'CyberRule' in k and r.get('significant', False))
    print(f"  CyberRule V2 significant wins: {cyberrule_sig}/3")

    print("\n" + "=" * 80)

    # Save results
    if output_file:
        output = {
            'common_cves': len(common_cves),
            'systems': {},
            'comparison_table': comparison_data,
            'bootstrap_ci': bootstrap_results,
            'mcnemar_test': mcnemar_results,
            'rankings': {
                'precision': [(d['system'], d['precision']) for d in prec_sorted],
                'recall': [(d['system'], d['recall']) for d in rec_sorted],
                'f1': [(d['system'], d['f1']) for d in f1_sorted]
            }
        }

        for key, data in filtered_systems.items():
            output['systems'][key] = {
                'name': data['system'],
                'precision': data['overall']['precision'],
                'recall': data['overall']['recall'],
                'f1': data['overall']['f1'],
                'tp': data['overall'].get('tp'),
                'fp': data['overall'].get('fp'),
                'fn': data['overall'].get('fn')
            }

        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, cls=NumpyEncoder)

        print(f"Results saved: {output_file}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Four-Way Comparison with McNemar\'s Test: CyberRule vs Regex vs Baseline vs Llama 3.3'
    )
    parser.add_argument('--cyberrule', required=True, help='CyberRule V2 evaluation JSON')
    parser.add_argument('--regex', required=True, help='Regex baseline evaluation JSON')
    parser.add_argument('--baseline', required=True, help='Simple baseline evaluation JSON')
    parser.add_argument('--llama', required=True, help='Llama 3.3 evaluation JSON')
    parser.add_argument('--output', default='evaluation/four_way_comparison_complete.json',
                       help='Output comparison JSON')
    parser.add_argument('--bootstrap-iterations', type=int, default=1000,
                       help='Number of bootstrap iterations for CI calculation')

    args = parser.parse_args()

    compare_four_systems(
        args.cyberrule,
        args.regex,
        args.baseline,
        args.llama,
        args.output,
        args.bootstrap_iterations
    )
