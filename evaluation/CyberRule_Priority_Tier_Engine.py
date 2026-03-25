#!/usr/bin/env python3
"""
CyberRule Priority-Tier Extraction Engine
Implements priority-based entity extraction with deterministic overlap resolution.

Priority Tiers:
- Tier 1 (100): VulnerabilityType
- Tier 2 (90): ProductType  
- Tier 3 (80): AffectedComponent
- Tier 4 (70): AttackRequirement (privilege levels)

Overlap Resolution: Within each tier, retain longest match, discard shorter overlaps.
"""

import json
import re
import argparse
import os
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass, field
from enum import IntEnum


# ============================================================================
# PRIORITY TIER SYSTEM
# ============================================================================

class PriorityTier(IntEnum):
    """Priority tiers for entity extraction."""
    VULNERABILITY_TYPE = 100    # vulnerability types
    PRODUCT_TYPE = 90           # products
    AFFECTED_COMPONENT = 80     # components
    ATTACK_REQUIREMENT = 70     # privilege levels
    ATTACK_VECTOR = 60          # additional tier
    IMPACT = 50                 # additional tier
    WEAKNESS = 40               # additional tier
    EXPLOIT_TECHNIQUE = 30      # additional tier
    BYPASSED_CONTROL = 20       # additional tier
    CRYPTO_ISSUE = 10           # additional tier
    PROTOCOL = 5                # additional tier
    PROGRAMMING_LANGUAGE = 5    # additional tier
    FILE_TYPE = 5               # additional tier
    HARDWARE = 5                # additional tier
    SEVERITY = 5                # additional tier
    ATTACK_COMPLEXITY = 5       # additional tier


# Tier descriptions for documentation
TIER_DESCRIPTIONS = {
    PriorityTier.VULNERABILITY_TYPE: "vulnerability types",
    PriorityTier.PRODUCT_TYPE: "products",
    PriorityTier.AFFECTED_COMPONENT: "components",
    PriorityTier.ATTACK_REQUIREMENT: "privilege levels",
    PriorityTier.ATTACK_VECTOR: "attack vectors",
    PriorityTier.IMPACT: "impact types",
    PriorityTier.WEAKNESS: "weaknesses",
    PriorityTier.EXPLOIT_TECHNIQUE: "exploit techniques",
    PriorityTier.BYPASSED_CONTROL: "bypassed controls",
    PriorityTier.CRYPTO_ISSUE: "cryptographic issues",
    PriorityTier.PROTOCOL: "protocols",
    PriorityTier.PROGRAMMING_LANGUAGE: "programming languages",
    PriorityTier.FILE_TYPE: "file types",
    PriorityTier.HARDWARE: "hardware",
    PriorityTier.SEVERITY: "severity levels",
    PriorityTier.ATTACK_COMPLEXITY: "attack complexity"
}


# ============================================================================
# CYBERRULE PATTERNS WITH PRIORITY TIERS
# ============================================================================

CYBERRULE_PATTERNS = {
    # Tier 100: VulnerabilityType (highest priority)
    "VulnerabilityType": {
        "tier": PriorityTier.VULNERABILITY_TYPE,
        "pattern": r"buffer overflow|stack overflow|heap overflow|integer overflow|integer underflow|arithmetic overflow|use-after-free|UAF|double free|memory corruption|memory leak|denial of service|DoS|distributed denial of service|DDoS|SQL injection|SQLi|blind SQL injection|cross-site scripting|XSS|stored XSS|reflected XSS|DOM XSS|command injection|code injection|OS command injection|path traversal|directory traversal|arbitrary file upload|unrestricted file upload|remote code execution|RCE|arbitrary code execution|ACE|privilege escalation|local privilege escalation|LPE|horizontal privilege escalation|vertical privilege escalation|information disclosure|information exposure|sensitive data exposure|authentication bypass|authorization bypass|session fixation|session hijacking|clickjacking|cross-site request forgery|CSRF|open redirect|SSRF|server-side request forgery|XML external entity|XXE|insecure deserialization|prototype pollution|race condition|time-of-check time-of-use|TOCTOU|format string vulnerability|integer truncation|sign extension error|type confusion|out-of-bounds read|out-of-bounds write|OOB read|OOB write|heap-based buffer overflow|stack-based buffer overflow"
    },
    
    # Tier 90: ProductType
    "ProductType": {
        "tier": PriorityTier.PRODUCT_TYPE,
        "pattern": r"wordpress plugin|wordpress theme|joomla extension|drupal module|chrome extension|firefox extension|browser extension|mobile application|iOS app|Android app|web application|web service|REST API|SOAP API|desktop application|client software|server software|firmware|BIOS|UEFI|driver|kernel module|operating system|OS|database|DBMS|network device|router|switch|firewall|VPN|IoT device|smart device|SCADA system|industrial control system|ICS|medical device|automotive software|cloud service|SaaS|PaaS|IaaS"
    },
    
    # Tier 80: AffectedComponent
    "AffectedComponent": {
        "tier": PriorityTier.AFFECTED_COMPONENT,
        "pattern": r"web interface|admin panel|management interface|API endpoint|REST endpoint|SOAP endpoint|database|configuration file|log file|session cookie|authentication module|authorization module|file upload component|image processing|video processing|audio processing|PDF parser|XML parser|JSON parser|HTML parser|script engine|template engine|plugin system|extension system|kernel|driver|firmware|bootloader|hypervisor|virtual machine|container|docker|kubernetes"
    },
    
    # Tier 70: AttackRequirement (privilege levels)
    "AttackRequirement": {
        "tier": PriorityTier.ATTACK_REQUIREMENT,
        "pattern": r"authenticated user|unauthenticated attacker|low privilege user|high privilege user|administrator access|root access|system access|local access|physical access|network access|adjacent network access|user interaction|victim interaction|administrator interaction|specific configuration|default configuration|particular setup"
    },
    
    # Additional tiers for completeness
    "AttackVector": {
        "tier": PriorityTier.ATTACK_VECTOR,
        "pattern": r"remote attacker|local attacker|network adjacent|physical access|wireless|bluetooth|WiFi|LAN|WAN|internet|web-based|email|malicious file|crafted file|malicious packet|crafted packet|malicious URL|phishing|social engineering|man-in-the-middle|MitM"
    },
    
    "Impact": {
        "tier": PriorityTier.IMPACT,
        "pattern": r"execute arbitrary code|arbitrary command execution|arbitrary file read|arbitrary file write|arbitrary file deletion|sensitive information disclosure|data theft|data exfiltration|credential theft|password theft|session hijacking|account takeover|system crash|application crash|service disruption|service outage|unauthorized access|unauthorized read|unauthorized write|unauthorized deletion|privilege escalation|privilege reduction|security bypass|protection bypass|policy bypass"
    },
    
    "Weakness": {
        "tier": PriorityTier.WEAKNESS,
        "pattern": r"improper input validation|improper output validation|improper access control|missing authentication|missing authorization|insufficient sanitization|insufficient escaping|improper neutralization|hard-coded credentials|default password|weak password|weak encryption|weak cryptography|cleartext transmission|cleartext storage|session fixation|insecure session management|insecure deserialization|untrusted deserialization|improper certificate validation|improper SSL validation|improper TLS validation|NULL pointer dereference|use of hard-coded cryptographic key|improper privilege management|improper permission assignment|improper resource shutdown|uncontrolled resource consumption|infinite loop|unreachable exit condition|improper exception handling|improper error handling|information exposure through error message|verbose error message|sensitive information in URL|sensitive information in log|debug mode enabled|test functionality enabled"
    },
    
    "ExploitTechnique": {
        "tier": PriorityTier.EXPLOIT_TECHNIQUE,
        "pattern": r"heap spraying|return-oriented programming|ROP|jump-oriented programming|JOP|code reuse|gadget chain|format string attack|integer overflow attack|buffer overflow attack|stack smashing|heap feng shui|use-after-free exploit|type confusion exploit|prototype pollution attack|prototype chain pollution|DOM clobbering|XSS filter bypass|WAF bypass|IDS bypass|IPS bypass|anti-virus bypass|sandbox escape|container escape|privilege escalation exploit"
    },
    
    "BypassedControl": {
        "tier": PriorityTier.BYPASSED_CONTROL,
        "pattern": r"same-origin policy|SOP|content security policy|CSP|XSS filter|WAF|web application firewall|IDS|intrusion detection system|IPS|intrusion prevention system|anti-virus|endpoint protection|sandbox|ASLR|address space layout randomization|DEP|data execution prevention|NX bit|stack canary|stack guard|CFI|control flow integrity|SafeSEH|SEHOP"
    },
    
    "CryptoIssue": {
        "tier": PriorityTier.CRYPTO_ISSUE,
        "pattern": r"weak encryption|weak hashing|MD5|SHA1|DES|RC4|weak random number generator|predictable random|insufficient entropy|hard-coded key|hard-coded IV|improper key management|improper certificate validation|self-signed certificate|expired certificate|weak SSL|weak TLS|SSLv2|SSLv3|TLS 1\.0|downgrade attack|padding oracle|timing attack|side-channel attack"
    },
    
    "Protocol": {
        "tier": PriorityTier.PROTOCOL,
        "pattern": r"HTTP|HTTPS|FTP|SFTP|SSH|Telnet|SMTP|SMTPS|POP3|POP3S|IMAP|IMAPS|DNS|DNSSEC|DHCP|SNMP|LDAP|LDAPS|Kerberos|NTLM|SMB|CIFS|NFS|RDP|VNC|X11|ICMP|TCP|UDP|IP|IPv4|IPv6|BGP|OSPF|RIP|VRRP|HSRP|WiFi|WPA|WPA2|WPA3|WEP|Bluetooth|BLE|Zigbee|Z-Wave|Modbus|OPC|OPC UA|DNP3|IEC 61850"
    },
    
    "ProgrammingLanguage": {
        "tier": PriorityTier.PROGRAMMING_LANGUAGE,
        "pattern": r"C|C\+\+|Java|Python|JavaScript|TypeScript|PHP|Ruby|Perl|Go|Golang|Rust|Swift|Kotlin|Objective-C|C#|VB\.NET|Visual Basic|PowerShell|Bash|Shell script|Assembly|ASM|SQL|PL/SQL|T-SQL|HTML|CSS|XML|JSON|YAML|Markdown|LaTeX"
    },
    
    "FileType": {
        "tier": PriorityTier.FILE_TYPE,
        "pattern": r"executable|EXE|DLL|SO|binary|script|batch file|shell script|PDF|ZIP|tar|gz|bz2|7z|RAR|image file|JPEG|JPG|PNG|GIF|BMP|TIFF|SVG|video file|MP4|AVI|MKV|MOV|audio file|MP3|WAV|FLAC|document|DOC|DOCX|XLS|XLSX|PPT|PPTX|database file|DB|SQLite|MySQL|PostgreSQL|configuration file|CONF|INI|XML|JSON|YAML|log file|LOG"
    },
    
    "Hardware": {
        "tier": PriorityTier.HARDWARE,
        "pattern": r"CPU|processor|GPU|graphics card|memory|RAM|ROM|flash memory|SSD|HDD|hard drive|storage|network card|NIC|WiFi card|Bluetooth adapter|USB controller|PCIe|PCI|BIOS|UEFI|firmware|microcontroller|MCU|FPGA|ASIC|embedded system|SoC|system on chip|IoT device|sensor|actuator|PLC|industrial controller"
    },
    
    "Severity": {
        "tier": PriorityTier.SEVERITY,
        "pattern": r"critical|high severity|medium severity|low severity|informational|CVSS [0-9]\.[0-9]|base score [0-9]\.[0-9]|temporal score [0-9]\.[0-9]|environmental score [0-9]\.[0-9]"
    },
    
    "AttackComplexity": {
        "tier": PriorityTier.ATTACK_COMPLEXITY,
        "pattern": r"low complexity|high complexity|easily exploitable|difficult to exploit|trivial to exploit|requires user interaction|no user interaction required|authentication required|no authentication required|single factor|multi-factor"
    }
}


# ============================================================================
# PRIORITY-TIER EXTRACTION ENGINE
# ============================================================================

@dataclass
class ExtractedEntity:
    """Represents an extracted entity with metadata."""
    text: str
    label: str
    tier: int
    priority: int
    start: int
    end: int
    confidence: float
    length: int = field(init=False)
    
    def __post_init__(self):
        self.length = len(self.text)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'text': self.text,
            'label': self.label,
            'tier': self.tier,
            'priority': self.priority,
            'start': self.start,
            'end': self.end,
            'confidence': self.confidence,
            'length': self.length
        }


class CyberRulePriorityEngine:
    """
    CyberRule extraction engine with priority-tier model.
    Resolves overlaps deterministically by retaining longest match per tier.
    """
    
    def __init__(self, confidence_threshold: float = 0.6):
        self.confidence_threshold = confidence_threshold
        self.patterns = CYBERRULE_PATTERNS
        self.compiled_patterns = {}
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile all regex patterns for efficiency."""
        for category, config in self.patterns.items():
            try:
                self.compiled_patterns[category] = re.compile(
                    config['pattern'], 
                    re.IGNORECASE
                )
            except re.error as e:
                print(f"Warning: Invalid regex in '{category}': {e}")
    
    def _calculate_confidence(self, entity_text: str, full_text: str, match) -> float:
        """Calculate confidence score for an entity match."""
        confidence = 0.6  # Base confidence
        
        # Longer matches are more specific
        if len(entity_text) > 10:
            confidence += 0.1
        if len(entity_text) > 20:
            confidence += 0.05
        
        # Check for context boosters
        context_start = max(0, match.start() - 50)
        context_end = min(len(full_text), match.end() + 50)
        context_window = full_text[context_start:context_end]
        
        context_boosters = [
            'vulnerability', 'exploit', 'attack', 'security', 'bypass',
            'malicious', 'arbitrary', 'unauthorized', 'sensitive', 'crafted',
            'allows', 'enables', 'leads to', 'results in'
        ]
        
        for booster in context_boosters:
            if booster in context_window.lower():
                confidence += 0.05
                break
        
        return min(confidence, 1.0)
    
    def _extract_all_entities(self, text: str) -> List[ExtractedEntity]:
        """Extract all entities from text before tier-based resolution."""
        entities = []
        
        for category, config in self.patterns.items():
            tier = config['tier']
            pattern = self.compiled_patterns.get(category)
            
            if not pattern:
                continue
            
            try:
                for match in pattern.finditer(text):
                    entity_text = match.group(0)
                    confidence = self._calculate_confidence(entity_text, text, match)
                    
                    if confidence >= self.confidence_threshold:
                        entity = ExtractedEntity(
                            text=entity_text,
                            label=category,
                            tier=tier,
                            priority=tier,  # Priority equals tier value
                            start=match.start(),
                            end=match.end(),
                            confidence=round(confidence, 3)
                        )
                        entities.append(entity)
            except Exception:
                continue
        
        return entities
    
    def _resolve_overlaps_by_tier(self, entities: List[ExtractedEntity]) -> List[ExtractedEntity]:
        """
        Resolve overlapping entities within each tier.
        Strategy: Retain longest match, discard shorter overlapping matches.
        """
        # Group entities by tier
        tier_groups: Dict[int, List[ExtractedEntity]] = {}
        for entity in entities:
            tier = entity.tier
            if tier not in tier_groups:
                tier_groups[tier] = []
            tier_groups[tier].append(entity)
        
        resolved_entities = []
        
        for tier, tier_entities in tier_groups.items():
            # Sort by length (descending), then by start position
            tier_entities.sort(key=lambda e: (-e.length, e.start))
            
            # Greedily select non-overlapping entities (longest first)
            selected = []
            occupied_ranges = []
            
            for entity in tier_entities:
                # Check if this entity overlaps with any selected entity
                overlaps = False
                for sel_start, sel_end in occupied_ranges:
                    if not (entity.end <= sel_start or entity.start >= sel_end):
                        # Overlap detected
                        overlaps = True
                        break
                
                if not overlaps:
                    selected.append(entity)
                    occupied_ranges.append((entity.start, entity.end))
                    # Keep ranges sorted for efficiency
                    occupied_ranges.sort()
            
            resolved_entities.extend(selected)
        
        return resolved_entities
    
    def _resolve_cross_tier_conflicts(self, entities: List[ExtractedEntity]) -> List[ExtractedEntity]:
        """
        Resolve conflicts across different tiers.
        Higher priority (tier value) wins.
        """
        # Sort by priority (descending), then by length (descending)
        entities.sort(key=lambda e: (-e.priority, -e.length, e.start))
        
        selected = []
        occupied_ranges = []
        
        for entity in entities:
            # Check for overlap with already selected (higher priority) entities
            overlaps_higher = False
            for sel_start, sel_end in occupied_ranges:
                if not (entity.end <= sel_start or entity.start >= sel_end):
                    overlaps_higher = True
                    break
            
            if not overlaps_higher:
                selected.append(entity)
                occupied_ranges.append((entity.start, entity.end))
                occupied_ranges.sort()
        
        # Sort final result by position in text
        selected.sort(key=lambda e: e.start)
        return selected
    
    def extract(self, text: str) -> List[ExtractedEntity]:
        """
        Main extraction method implementing priority-tier algorithm:
        1. Extract all entities with confidence >= threshold
        2. Resolve overlaps within each tier (keep longest)
        3. Resolve conflicts across tiers (higher priority wins)
        4. Return unambiguous set of entities
        """
        if not text:
            return []
        
        # Step 1: Extract all candidate entities
        all_entities = self._extract_all_entities(text)
        
        # Step 2: Resolve overlaps within each tier
        tier_resolved = self._resolve_overlaps_by_tier(all_entities)
        
        # Step 3: Resolve conflicts across tiers
        final_entities = self._resolve_cross_tier_conflicts(tier_resolved)
        
        return final_entities
    
    def extract_with_tier_summary(self, text: str) -> Dict[str, Any]:
        """Extract entities and provide tier-based summary."""
        entities = self.extract(text)
        
        # Group by tier
        tier_summary = {}
        for entity in entities:
            tier_name = TIER_DESCRIPTIONS.get(entity.tier, f"Tier_{entity.tier}")
            if tier_name not in tier_summary:
                tier_summary[tier_name] = {
                    'priority': entity.priority,
                    'count': 0,
                    'entities': []
                }
            tier_summary[tier_name]['count'] += 1
            tier_summary[tier_name]['entities'].append(entity.to_dict())
        
        # Sort tiers by priority
        sorted_tiers = dict(sorted(
            tier_summary.items(), 
            key=lambda x: x[1]['priority'], 
            reverse=True
        ))
        
        return {
            'entities': [e.to_dict() for e in entities],
            'total_entities': len(entities),
            'tier_summary': sorted_tiers,
            'tiers_represented': len(tier_summary)
        }


# ============================================================================
# CVE PROCESSOR
# ============================================================================

class CVEProcessor:
    """Process CVE entries with priority-tier extraction."""
    
    def __init__(self, engine: CyberRulePriorityEngine):
        self.engine = engine
    
    def process_cve(self, cve_data: Dict) -> Dict:
        """Process a single CVE entry."""
        if isinstance(cve_data, dict):
            cve_id = cve_data.get('cve_id', cve_data.get('id', 'Unknown'))
            description = cve_data.get('description', cve_data.get('prompt_input', ''))
        else:
            cve_id = 'Unknown'
            description = str(cve_data)
        
        # Clean up if needed
        if description.startswith('Extract cybersecurity concepts'):
            parts = description.split('\n\n', 1)
            if len(parts) > 1:
                description = parts[1]
        
        # Extract using priority-tier engine
        extraction_result = self.engine.extract_with_tier_summary(description)
        
        return {
            'cve_id': cve_id,
            'description': description[:300] + '...' if len(description) > 300 else description,
            'extraction': extraction_result
        }
    
    def process_cve_list(self, cve_list: List[Dict]) -> List[Dict]:
        """Process a list of CVE entries."""
        results = []
        total = len(cve_list)
        
        for i, cve in enumerate(cve_list):
            if (i + 1) % 100 == 0 or i == 0:
                print(f"  Processing {i + 1}/{total}...")
            result = self.process_cve(cve)
            results.append(result)
        
        return results


# ============================================================================
# STATISTICS AND REPORTING
# ============================================================================

def generate_extraction_report(results: List[Dict]) -> Dict:
    """Generate comprehensive extraction report."""
    total_cves = len(results)
    
    # Overall statistics
    total_entities = sum(r['extraction']['total_entities'] for r in results)
    cves_with_entities = sum(1 for r in results if r['extraction']['total_entities'] > 0)
    
    # Tier statistics
    tier_stats = {}
    for r in results:
        for tier_name, tier_data in r['extraction']['tier_summary'].items():
            if tier_name not in tier_stats:
                tier_stats[tier_name] = {
                    'priority': tier_data['priority'],
                    'total_occurrences': 0,
                    'cves_with_tier': 0
                }
            tier_stats[tier_name]['total_occurrences'] += tier_data['count']
            if tier_data['count'] > 0:
                tier_stats[tier_name]['cves_with_tier'] += 1
    
    # Sort by priority
    sorted_tiers = dict(sorted(tier_stats.items(), key=lambda x: x[1]['priority'], reverse=True))
    
    return {
        'dataset_summary': {
            'total_cves': total_cves,
            'cves_with_entities': cves_with_entities,
            'coverage_percent': round(cves_with_entities / total_cves * 100, 1),
            'total_entities': total_entities,
            'average_per_cve': round(total_entities / total_cves, 2)
        },
        'tier_breakdown': sorted_tiers,
        'priority_tier_model': {
            'description': 'Priority-tier extraction with deterministic overlap resolution',
            'resolution_strategy': 'Within each tier: retain longest match, discard shorter overlaps. Across tiers: higher priority wins.',
            'tiers': [
                {'name': 'VulnerabilityType', 'priority': 100, 'description': 'vulnerability types'},
                {'name': 'ProductType', 'priority': 90, 'description': 'products'},
                {'name': 'AffectedComponent', 'priority': 80, 'description': 'components'},
                {'name': 'AttackRequirement', 'priority': 70, 'description': 'privilege levels'},
                {'name': 'AttackVector', 'priority': 60, 'description': 'attack vectors'},
                {'name': 'Impact', 'priority': 50, 'description': 'impact types'},
                {'name': 'Weakness', 'priority': 40, 'description': 'weaknesses'},
                {'name': 'ExploitTechnique', 'priority': 30, 'description': 'exploit techniques'},
                {'name': 'BypassedControl', 'priority': 20, 'description': 'bypassed controls'},
                {'name': 'CryptoIssue', 'priority': 10, 'description': 'cryptographic issues'},
                {'name': 'Others', 'priority': 5, 'description': 'protocols, languages, file types, hardware, severity, complexity'}
            ]
        }
    }


# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    """Main entry point for priority-tier extraction."""
    parser = argparse.ArgumentParser(
        description='CyberRule Priority-Tier Extraction Engine'
    )
    parser.add_argument('--input', '-i', required=True, 
                       help='Input JSON file with CVE data')
    parser.add_argument('--output', '-o', default='priority_extraction_results.json',
                       help='Output JSON file (default: priority_extraction_results.json)')
    parser.add_argument('--threshold', '-t', type=float, default=0.6,
                       help='Confidence threshold (default: 0.6)')
    parser.add_argument('--report', '-r', action='store_true',
                       help='Print detailed tier report to console')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"Error: Input file not found: {args.input}")
        return 1
    
    # Load data
    print(f"Loading CVE data from {args.input}...")
    with open(args.input, 'r', encoding='utf-8') as f:
        cve_data = json.load(f)
    
    # Normalize to list
    if isinstance(cve_data, dict):
        first_key = list(cve_data.keys())[0]
        if first_key.startswith('CVE-'):
            cve_list = [{'cve_id': k, 'description': v} for k, v in cve_data.items()]
        else:
            cve_list = list(cve_data.values())
    else:
        cve_list = cve_data
    
    print(f"Loaded {len(cve_list)} CVEs")
    print(f"\nInitializing priority-tier engine (threshold={args.threshold})...")
    
    # Initialize engine
    engine = CyberRulePriorityEngine(confidence_threshold=args.threshold)
    processor = CVEProcessor(engine)
    
    print("Processing with priority-tier model...")
    print("  Tiers: VulnerabilityType(100) > ProductType(90) > Component(80) > Privilege(70) > ...")
    print("  Resolution: Longest match per tier, higher priority wins across tiers")
    print("=" * 70)
    
    # Process CVEs
    results = processor.process_cve_list(cve_list)
    
    # Generate report
    report = generate_extraction_report(results)
    
    # Prepare output
    output_data = {
        'extraction_results': results,
        'report': report
    }
    
    # Save
    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)
    
    # Console output
    print("\n" + "=" * 70)
    print("PRIORITY-TIER EXTRACTION COMPLETE")
    print("=" * 70)
    stats = report['dataset_summary']
    print(f"  CVEs processed:        {stats['total_cves']}")
    print(f"  CVEs with entities:    {stats['cves_with_entities']} ({stats['coverage_percent']}%)")
    print(f"  Total entities:        {stats['total_entities']}")
    print(f"  Average per CVE:       {stats['average_per_cve']}")
    
    if args.report:
        print(f"\n  Priority Tier Breakdown:")
        print("  " + "-" * 60)
        for tier_name, tier_data in report['tier_breakdown'].items():
            percentage = (tier_data['total_occurrences'] / stats['total_entities'] * 100) if stats['total_entities'] > 0 else 0
            print(f"    {tier_name:<25} Priority: {tier_data['priority']:>3} | "
                  f"Count: {tier_data['total_occurrences']:>5} ({percentage:>5.1f}%) | "
                  f"CVEs: {tier_data['cves_with_tier']}")
        print("  " + "-" * 60)
    
    print(f"\n  Results saved to: {args.output}")
    print("=" * 70)
    
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
