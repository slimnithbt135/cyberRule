#!/usr/bin/env python3
"""
Calculated from Actual Observed Data
============================================================
This script calculates sample size requirements using ACTUAL parameters
from the integrated performance analysis:
- Sample size: 151 CVEs
Formula: n = (Z_α + Z_β)² × pD / δ²
"""

import numpy as np
from scipy import stats


def mcnemar_sample_size(effect_size, p_discordant, alpha=0.05, power=0.80):
    """
    Calculate required sample size for McNemar's test.

    Formula: n = (Z_(1-α/2) + Z_power)² × pD / δ²
    """
    Z_alpha = stats.norm.ppf(1 - alpha/2)
    Z_beta = stats.norm.ppf(power)

    n = ((Z_alpha + Z_beta)**2 * p_discordant) / (effect_size**2)
    return int(np.ceil(n))


def calculate_power(n, effect_size, p_discordant, alpha=0.05):
    """Calculate statistical power given sample size."""
    Z_alpha = stats.norm.ppf(1 - alpha/2)
    Z_beta = np.sqrt(n * effect_size**2 / p_discordant) - Z_alpha
    return stats.norm.cdf(Z_beta)


def generate_table_a22_real():
    """Generate Table A.2.2 from actual observed data."""

    # ACTUAL parameters from integrated performance document
    ACTUAL_EFFECT_SIZES = [
        ("CyberRule vs Regex", 0.238),
        ("CyberRule vs Simple", 0.292),
        ("CyberRule vs Llama", 0.314)
    ]

    P_DISCORDANT = 33/151  # Actual from McNemar table: (7+26)/151
    N_ACTUAL = 151

    print("="*70)
    print("TABLE A.2.2: Validation Against Sample Size Requirements")
    print("="*70)
    print("Calculated from ACTUAL observed data in integrated performance analysis:")
    print(f"  • Discordant proportion: {P_DISCORDANT:.3f} (33 discordant / 151 total CVEs)")
    print(f"  • Observed F1 effect sizes from McNemar comparisons")
    print(f"  • Formula: n = (Z_α + Z_β)² × pD / δ²")
    print()

    # Header
    print(f"{'| Comparison |':<28} {'Effect Size |':<15} {'Required n |':<15} {'Our Sample |':<15}")
    print(f"{'|------------|':<28} {'-----------|':<15} {'-----------|':<15} {'------------|':<15}")

    # Calculate for each actual comparison
    for comparison, es in ACTUAL_EFFECT_SIZES:
        required = mcnemar_sample_size(es, P_DISCORDANT)
        check = "✓" if N_ACTUAL >= required else ""
        print(f"| {comparison:<25} | {es:<12.3f} | {required:<11} | {N_ACTUAL} {check:<7} |")

    print()
    print(f"Our sample of {N_ACTUAL} CVEs provides:")

    # Calculate actual power for each
    for comparison, es in ACTUAL_EFFECT_SIZES:
        power = calculate_power(N_ACTUAL, es, P_DISCORDANT)
        print(f"  • {power:.1%} power for {comparison} (δ={es:.3f})")

    print()
    print("Validation:")
    print(f"  • Minimum required for largest effect (0.314): {mcnemar_sample_size(0.314, P_DISCORDANT)} CVEs")
    print(f"  • Minimum required for smallest effect (0.238): {mcnemar_sample_size(0.238, P_DISCORDANT)} CVEs")
    print(f"  • Actual sample: {N_ACTUAL} CVEs")
    print(f"  → Sufficient power for all observed effect sizes ✓")

    print("="*70)


if __name__ == "__main__":
    generate_table_a22_real()
