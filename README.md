**A deterministic, rule-based extraction engine that converts CVE descriptions into structured OWL ontologies with complete auditability and zero output variance.**

 **Key Innovation**: 
 CyberRule delivers forensic-grade reproducibility: zero output variance versus LLMs' 12% deviation and superior F1-score (0.511) over regex (0.273) and keyword (0.219) baselines—enabling auditable, compliance-ready cybersecurity extraction. Systems based on a rule (CyberRule, Regex Baseline, Simple Baseline) are deterministic and yielded the same results on repeated executions


## **Fetch CVE data from NVD directory**

inputs:NVD feed URL (https://nvd.nist.gov/...)
outputs:data/cve_2023_sample.json 
```bash
python scripts/legacy/fetch_cve_data_from_feed.py 
```
## ** CVE Processing: Text cleaning **

inputs: data/cve_2023_sample.json
outputs: data/cve_2023_preprocessed.json
```bash
python scripts/legacy/preprocess_cve_data.py
```
## ** Pattern matching across 300+ rules **

inputs: data/cve_2023_preprocessed.json
outputs: data/cve_2023_enriched.json
```bash
python scripts/legacy/CVE_entity_mining.py
```
## ** Creating comprehensive Pattern Taxonomy spanning 16 semantic categorie across 170+ manually-engineered regex patterns for Entities Extraction**

inputs: data/cve_2023_enriched.json
outputs: outputs/results_pattern_extraction_V2.json
```bash
python patterns/CyberRule_Entity_Extractor_V2.py --input  data/cve_2023_enriched.json --output outputs/results_pattern_extraction_V2.json ```
## **Quick Results Summary: Four-Way Comparison**

| Metric | CyberRule V2 | Regex Baseline | Simple Baseline | Llama 3.3 (70B) |
|--------|-------------|----------------|-----------------|-----------------|
| **Precision** | **56.7%**  | 50.0% | 43.8% | 46.2% |
| **Recall** | **46.5%**  | 18.8% | 14.6% | 12.5% |
| **F1-Score** | **0.511**  | 0.273 | 0.219 | 0.197 |
| **Deterministic?** |  **Yes** |  Yes |  Yes |  No |
| **Output Variance** | **0** | 0 | 0 | 0.31 entities/CVE |

*Table 2 & Table 8 from paper: Entity-level evaluation on 151-CVE reference standard*

**Statistical Significance (McNemar's Test):**
- CyberRule vs. Regex Baseline: p = 0.0017 (**)
- CyberRule vs. Simple Baseline: p < 0.0001 (***)
- CyberRule vs. Llama 3.3: p < 0.0001 (***)



## **Quick Start**

```bash
# Install dependencies
pip install -e .

# Run complete pipeline (fetch → preprocess → extract → evaluate)
make full

# Or execute individual components
make fetch      # Download CVE data from NVD
make preprocess # Clean and normalize descriptions  
make extract    # Run CyberRule extraction engine
make evaluate   # Compare against all baselines and LLMs
make convert    # Generate OWL/TTL ontologies
```

## **What It Does**

**Input** (from `data/cve_2023_preprocessed.json`):
```
"SQL injection vulnerability in Apache Struts 2.3 allows 
authentication bypass via crafted HTTP request..."
```

**Output** (to `outputs/results_pattern_extraction_V2.json`):
```json
{
  "cve_id": "CVE-2023-XXXX",
  "classes": ["SQLInjection", "ApacheStruts", "AuthenticationBypass"],
  "relations": [
    {"subject": "SQLInjection", "predicate": "affects", "object": "ApacheStruts"},
    {"subject": "SQLInjection", "predicate": "requires", "object": "AuthenticatedUser"}
  ],
  "axioms": ["SQLInjection ⊑ DatabaseAttack"],
  "confidence": 0.93,
  "pattern_provenance": "VULN_PATTERNS:v4_SQLi"
}
```


## **Repository Structure**

| Directory | Contents | Paper Section |
|-----------|----------|---------------|
| `src/cyberrule/` | Core extraction engine (`CyberRule_Entity_Extractor_V2.py`) | §3.1-3.3 |
| `scripts/legacy/` | Original research scripts (superseded but reproducible) used CVE_entity_mining.py to produce cve_2023_enriched  | §4, Appendix |
| `evaluation/` | Benchmarking vs. LLMs and baselines | §5.1-5.6 |
| `data/` | Input CVEs and ground truth annotations | §4.1-4.2 |
| `outputs/` | Generated JSON, TTL, OWL, evaluation reports | §5 |
| `patterns/` | 16-category regex pattern definitions with 170+ type | §3.2, Table 1 |
| `queries/` | SPARQL queries for ontology validation | §5.5 |

## **Fetch CVE data from NVD directory**
```bash
inputs:NVD feed URL (https://nvd.nist.gov/...)
outputs:data/cve_2023_sample.json 
python scripts/legacy/fetch_cve_data_from_feed.py 
```
## ** CVE Processing: Text cleaning 
```bash
inputs: data/cve_2023_sample.json
outputs: data/cve_2023_preprocessed.json
python scripts/legacy/preprocess_cve_data.py
```
## ** Pattern matching across 300+ rules 
```bash
inputs: data/cve_2023_preprocessed.json
outputs: data/cve_2023_enriched.json
python scripts/legacy/CVE_entity_mining.py

## ** Creating comprehensive Pattern Taxonomy spanning 16 semantic categorie across 170+ manually-engineered regex patterns 
```bash
inputs: data/cve_2023_enriched.json
outputs: outputs/results_pattern_extraction_V2.json
python patterns/CyberRule_Entity_Extractor_V2.py --input  data/cve_2023_enriched.json --output outputs/results_pattern_extraction_V2.json
                               
```
## **Reproducing Paper Results**

Each command below maps directly to a specific table/figure in the paper:

### **Table 2 & Table 8: Four-Way System Comparison**

Execute all four systems and generate the complete comparison with statistical tests:

#### **1. CyberRule V2 Evaluation (F1=0.511, Precision=56.7%, Recall=46.5%)**

```bash
python evaluation/evaluate_cyberrule_improved_v2.py   --reference evaluation/reference_standard_200.json   --output evaluation/cyberrule_v2_evaluation.json
```

**Expected Output:**
```
================================================================================
CYBERRULE V2 RESULTS (REFINED)
================================================================================
Total CVEs: 151
Precision: 0.567 (72/127)
Recall: 0.465 (72/155)
F1-Score: 0.511
95% CI Precision: [0.491 -- 0.644]
95% CI Recall: [0.385 -- 0.551]
```

#### **2. Regex Baseline Evaluation (F1=0.273, Precision=50.0%, Recall=18.8%)**

```bash
python evaluation/regex_baseline.py   --reference data/reference_standard_200.json
```

**Expected Output:**
```
======================================================================
REGEX BASELINE EVALUATION RESULTS
======================================================================
Total CVEs evaluated: 151
Overall Precision: 0.500
Overall Recall: 0.188
Overall F1-Score: 0.273
```

#### **3. Simple Keyword Baseline (F1=0.219, Precision=43.8%, Recall=14.6%)**

```bash
python evaluation/evaluate_baseline.py   --reference data/reference_standard_200.json
```

**Expected Output:**
```
======================================================================
BASELINE EVALUATION RESULTS
======================================================================
Total CVEs evaluated: 151
Overall Precision: 0.438
Overall Recall: 0.146
Overall F1-Score: 0.219
```

#### **4. Llama 3.3 70B Evaluation (F1=0.197, Non-deterministic)**

```bash
# Requires: export GROQ_API_KEY="gsk_..."
python evaluation/evaluate_groq_standalone.py evaluate --max 151
```

**Expected Output:**
```
======================================================================
LLAMA 3.3 EVALUATION RESULTS
======================================================================
CVEs evaluated: 151
Precision: 0.462
Recall: 0.125
F1-Score: 0.197
Average variance (entities differing across 3 runs): 0.31
Total variance entities across all CVEs: 47
Bootstrap 95% CI Precision: [0.256 -- 0.643] (wide due to variance)
```

#### **5. Generate Complete Four-Way Comparison with McNemar Tests**

```bash
python evaluation/evaluate_all_systems.py   --cyberrule data/cyberrule_v2_evaluation.json   --regex data/regex_baseline_evaluation.json   --baseline data/baseline_evaluation.json   --llama data/llama3_evaluation.json   --output outputs/all_approaches_comparison_evaluation.json
```

**Expected Output:**
```
================================================================================
FOUR-WAY SYSTEM COMPARISON WITH McNEMAR'S TEST
================================================================================

COMPARISON TABLE
================================================================================
System              Precision   Recall   F1      Deterministic
------------------- ---------   ------   ---     -------------
CyberRule V2        56.7%       46.5%    0.511   Yes
Regex Baseline      50.0%       18.8%    0.273   Yes
Simple Baseline     43.8%       14.6%    0.219   Yes
Llama 3.3 (70B)     46.2%       12.5%    0.197   No

McNEMAR'S TEST - ALL PAIRWISE COMPARISONS
================================================================================
Comparison                      b    c    Total   χ²     p-value    Sig.
------------------------------  -    -    -----   --     -------    ----
CyberRule V2 vs Regex Baseline  7    26   33      9.82   0.0017     **
CyberRule V2 vs Simple Baseline 29   7    36      12.25  0.0005     ***
CyberRule V2 vs Llama 3.3       60   0    60      58.02  <0.0001    ***
Regex vs Simple Baseline       43   2    45      35.56  <0.0001    ***
Regex vs Llama 3.3              79   0    79      77.01  <0.0001    ***
Simple vs Llama 3.3             40   2    42      32.60  <0.0001    ***

EFFECT SIZE ANALYSIS
================================================================================
Comparison                      F1 Diff   Magnitude
------------------------------  -------   ---------
CyberRule V2 vs Regex Baseline  +0.238    Very Large
CyberRule V2 vs Simple Baseline +0.292    Very Large  
CyberRule V2 vs Llama 3.3       +0.314    Very Large

SYSTEM RANKINGS
================================================================================
By Precision:  1. CyberRule V2 (56.7%) 2. Regex (50.0%) 3. Llama 3.3 (46.2%) 4. Simple (43.8%)
By Recall:     1. CyberRule V2 (46.5%) 2. Regex (18.8%) 3. Simple (14.6%) 4. Llama 3.3 (12.5%)
By F1-Score:   1. CyberRule V2 (0.511) 2. Regex (0.273) 3. Simple (0.219) 4. Llama 3.3 (0.197)
```

---

### **Section 5.3: Coverage Analysis (2,000 CVE Corpus)**

```bash
python evaluation/CyberRule_Coverage_Analysis.py   --input data/cve_2023_preprocessed.json   --output outputs/cyberrule_coverage_results.json   --max 2000
```

**Expected Output:**
```
======================================================================
CYBERRULE COVERAGE ANALYSIS - 2,000 CVE CORPUS
======================================================================
• Total CVEs processed: 2,000
• CVEs with at least one extracted entity: 1,342 (67.1% coverage)
• Total entities extracted: 1,442
• Average entities per CVE (overall): 0.72
• Average entities per CVE (among CVEs with entities): 1.07
• Processing throughput: 1505 CVEs/second
• Processing time: 1.33 seconds

Vulnerability Category Distribution:
--------------------------------------------------
xss          : 492 (34.1%)
injection    : 289 (20.0%)
dos          : 143 (9.9%)
memory       : 122 (8.5%)
csrf         : 107 (7.4%)
overflow     : 65 (4.5%)
info         : 58 (4.0%)
authorization: 42 (2.9%)
path         : 36 (2.5%)
rce          : 31 (2.1%)
Other        : 57 (4.0%)
```

---

### **Figure 9: SQL Injection Pattern Refinement**

```bash
python evaluation/CyberRule_SQL_Pattern_Refinement.py   --input data/cve_2023_enriched.json   --output outputs/refinement_metrics.json
```

**Expected Output:**
```
======================================================================
SQL INJECTION PATTERN EVOLUTION RESULTS
======================================================================
• Version 1: basic keyword match ("SQL injection")
  - Linguistic variants: 1
  - Expected precision: 27%
  - Measured precision: 15%
  - Coverage: 0/2000 CVEs (0.0%)

• Version 2: added context constraints
  - Linguistic variants: 2
  - Expected precision: 69%
  - Measured precision: 70%
  - Coverage: 248/2000 CVEs (12.4%)
  - Context validation rate: 100.0%

• Version 3: added verb-proximity constraints
  - Linguistic variants: 3
  - Expected precision: 87%
  - Measured precision: 86%
  - Coverage: 248/2000 CVEs (12.4%)
  - Context validation rate: 100.0%
  - Verb proximity rate: 75.2%

• Version 4: final refinement with 12 linguistic variants
  - Linguistic variants: 12
  - Expected precision: 94%
  - Measured precision: 93%
  - Coverage: 248/2000 CVEs (12.4%)
  - Context validation rate: 100.0%
  - Verb proximity rate: 75.7%

Progression Summary:
- Precision improvement: +78% (V1 → V4)
- Coverage improvement: +12.4% (V1 → V4)
- Variants increase: 11× (1 → 12)
```

---

### **Priority Tier Engine (Section 3.3)**

```bash
python evaluation/CyberRule_Priority_Tier_Engine.py   --input data/cve_2023_enriched.json   --output outputs/priority_extraction_results.json   --report
```

**Expected Output:**
```
======================================================================
PRIORITY-TIER EXTRACTION COMPLETE
======================================================================
CVEs processed: 2000
CVEs with entities: 2000 (100.0%)
Total entities: 31684
Average per CVE: 15.84

Priority Tier Breakdown:
--------------------------------------------------
vulnerability types    Priority: 100 | Count: 2,159 ( 6.8%) | CVEs: 1,413
products               Priority: 90  | Count: 2,186 ( 6.9%) | CVEs: 1,463
components             Priority: 80  | Count:   169 ( 0.5%) | CVEs:   120
privilege levels       Priority: 70  | Count:   257 ( 0.8%) | CVEs:   247
attack vectors         Priority: 60  | Count:   398 ( 1.3%) | CVEs:   275
impact types           Priority: 50  | Count:    55 ( 0.2%) | CVEs:    52
weaknesses             Priority: 40  | Count:   124 ( 0.4%) | CVEs:   122
exploit techniques     Priority: 30  | Count:   202 ( 0.6%) | CVEs:   181
bypassed controls      Priority: 20  | Count:    75 ( 0.2%) | CVEs:    71
cryptographic issues   Priority: 10  | Count:   360 ( 1.1%) | CVEs:   325
attack complexity      Priority: 5   | Count: 25,699 (81.1%)| CVEs: 1,930
```

---

## **Legacy Scripts (`scripts/legacy/`)**

These scripts correspond to the original research pipeline (v1.2) used for paper reproducibility:

| Script | Paper Reference | Purpose | Status |
|--------|-----------------|---------|--------|
| `fetch_cve_data_from_feed.py` | §4.1 | Downloads 2023 NVD feed, extracts 2000 CVEs | **Active** |
| `preprocess_cve_data.py` | §3.1 | Text normalization, prompt generation | **Active** |
| `CyberRule-Enricher.py` | Table 1 | Original 60-pattern extractor (4 dictionaries) | **Superseded** by `src/cyberrule/extractor.py` |
| `generate_rdf_from_cyberrule.py` | §3.4 | JSON → Turtle RDF conversion | **Active** |

### **Execution Order (Paper Pipeline)**

```bash
# Step 1: Data Acquisition (§4.1)
python scripts/legacy/fetch_cve_data_from_feed.py
# Output: data/cve_2023_sample.json (2000 CVEs)

# Step 2: Preprocessing (§3.1)
python scripts/legacy/preprocess_cve_data.py
# Output: data/cve_2023_preprocessed.json

# Step 3: Entity Extraction (§3.2-3.3)
# Original: python scripts/legacy/CyberRule-Enricher.py
# Current:  python -m src.cyberrule.extractor
# Output: data/cve_2023_enriched.json

# Step 4: RDF/OWL Generation (§3.4)
python scripts/legacy/generate_rdf_from_cyberrule.py
# Output: outputs/cyberonto_enriched.ttl → .owl
```

---

## **Pattern Architecture (Section 3.2, Table 1)**

CyberRule uses **16 semantic pattern categories** with **170+ compiled regular expressions**:

| Category | Count | Priority | Example Pattern | Example Output |
|----------|-------|----------|-----------------|----------------|
| **VulnerabilityType** | 2,159 | 100 | `r'\bSQL injection\b'` | `SQLInjection` |
| **ProductType** | 2,186 | 90 | `r'\bApache\b|\bStruts\b'` | `ApacheStruts` |
| **ProgrammingLanguage** | 24,003 | - | `r'\bJava\b|\bPython\b'` | `Java` |
| **AttackComplexity** | 25,699 | 5 | `r'\blow complexity\b'` | `LowComplexity` |

**Key Features:**
- **Priority tiers**: Higher priority patterns win conflicts (VulnerabilityType > Product > Component)
- **Longest match**: Within same tier, longest regex match is retained
- **Context constraints**: Verb proximity (e.g., "allows", "enables") and security keywords required
- **Version extraction**: Products include versions (`Apache_v2.4.57`)

---

## **Why CyberRule Beats All Baselines (Section 5.6, Table 8)**

### **Comparison with All Three Baselines**

| Criterion | CyberRule | Regex Baseline | Simple Baseline | Llama 3.3 (70B) |
|-----------|-----------|----------------|-----------------|-----------------|
| **Precision** | **56.7%** 🥇 | 50.0% | 43.8% | 46.2% |
| **Recall** | **46.5%** 🥇 | 18.8% | 14.6% | 12.5% |
| **F1-Score** | **0.511** 🥇 | 0.273 | 0.219 | 0.197 |
| **Determinism** | ✅ **Yes** | ✅ Yes | ✅ Yes | ❌ No |
| **Output Variance** | **0** | 0 | 0 | 0.31 entities/CVE |
| **Reproducibility** | ✅ **Complete** | ✅ Complete | ✅ Complete | ❌ Stochastic |
| **Auditability** | ✅ **Full provenance** | ✅ Full | ✅ Full | ❌ Black box |
| **Speed** | **1,505 CVEs/sec** | Similar | Similar | API-limited |
| **Cost** | **Free (CPU only)** | Free | Free | API tokens |

### **Key Findings by Comparison**

**CyberRule vs. Regex Baseline:**
- CyberRule achieves **+0.238 F1 improvement** (Very Large effect size)
- Regex is more conservative (higher precision on extracted entities, but misses 81.2% of ground truth)
- McNemar test: p = 0.0017 (significant difference in behavior)

**CyberRule vs. Simple Keyword Baseline:**
- CyberRule achieves **+0.292 F1 improvement** (Very Large effect size)
- Simple baseline lacks contextual constraints and pattern sophistication
- McNemar test: p < 0.0001 (highly significant)

**CyberRule vs. Llama 3.3 (70B):**
- CyberRule achieves **+0.314 F1 improvement** (Very Large effect size)
- Llama 3.3's primary failure: **low recall (12.5%)** + **non-determinism (0.31 variance)**
- McNemar test: p < 0.0001 (highly significant)
- **Critical**: Llama 3.3 varies between runs, making it unsuitable for security-critical applications requiring forensic traceability

---

## **Configuration**

Edit `src/cyberrule/patterns_data.py` to customize extraction:

```python
VULN_PATTERNS = {
    r'\bSQL\s+injection\b': 'SQLInjection',
    r'\bbuffer\s+overflow\b': 'BufferOverflow',
    r'\bXSS\b|\bcross.?site scripting\b': 'CrossSiteScripting',
    # Add custom patterns...
}

# Adjust confidence threshold (default: 0.6)
# Adjust MAX_CVES (default: 2000)
```

---

## **Testing**

```bash
make test
# Runs unit tests on extractor and data loading before full execution
```

---

## **Output Formats**

| Extension | Description | Tool | Paper Section |
|-----------|-------------|------|---------------|
| `.json` | Structured extractions with provenance | CyberRule engine | §3.3 |
| `.ttl` | Turtle RDF triples | `generate_rdf_from_cyberrule.py` | §3.4 |
| `.owl` | OWL-DL ontology (HermiT-validated) | `convert_to_owl.py` | §3.4, Fig 2 |

---

## **Troubleshooting**

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: cyberrule` | Run `pip install -e .` first |
| Missing input file | Ensure `make fetch` completed successfully |
| `GROQ_API_KEY` not set | Required only for LLM evaluation; CyberRule runs offline |
| Permission denied on `make` | Use `python run_extractor.py` directly |

---

## **Citation**

If using CyberRule in research, please cite:

```bibtex
@article{slimani2025cyberrule,
  title={CyberRule: A Deterministic Ontology Population for Reproducible 
         Cybersecurity Knowledge Extraction from CVE Descriptions},
  author={Slimani, Thabet},
  journal={Preprint submitted to Elsevier},
  year={2025},
  affiliation={Taif University, Saudi Arabia},
  url={https://github.com/slimnithbt135/cyberRule}
}
```

---

## **Limitations (Section 6)**

1. **Coverage**: 67.1% of CVEs have at least one extraction; 32.9% have no pattern matches
2. **Semantic depth**: Surface-level pattern matching; no cross-sentence coreference or implicit relation inference
3. **Maintenance**: Hand-crafted patterns require updates for new vulnerability types
4. **Language**: Optimized for English CVE descriptions

**Future Work**: Hybrid neuro-symbolic architectures using CyberRule as deterministic validation layer for neural candidate generation (Section 6.4).

---

## **Complete Evaluation Matrix**

| Script | Paper Section | Output File | Key Metric |
|--------|---------------|-------------|------------|
| `evaluate_cyberrule_improved_v2.py` | §5.2.1, Table 2 | `cyberrule_v2_evaluation.json` | F1=0.511 |
| `regex_baseline.py` | §5.2.1, Table 2 | `regex_baseline_evaluation.json` | F1=0.273 |
| `evaluate_baseline.py` | §5.2.1, Table 2 | `baseline_evaluation.json` | F1=0.219 |
| `evaluate_groq_standalone.py` | §5.2.1, Table 2 | `llama3_evaluation.json` | F1=0.197 |
| `evaluate_all_systems.py` | §5.2.3, Table 4 | `four_approaches_comparison.json` | McNemar p-values |
| `CyberRule_Coverage_Analysis.py` | §5.3, Fig 8 | `cyberrule_coverage_results.json` | 67.1% coverage |
| `CyberRule_SQL_Pattern_Refinement.py` | §5.4, Fig 9 | `refinement_metrics.json` | 27%→94% precision |
| `CyberRule_Priority_Tier_Engine.py` | §3.3, §5.2 | `priority_extraction_results.json` | 11-tier breakdown |

---

**Repository**: https://github.com/slimnithbt135/cyberRule  
**Paper Commit**: `7ba1813`  
**License**: MIT
