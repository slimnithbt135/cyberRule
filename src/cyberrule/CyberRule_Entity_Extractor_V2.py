#!/usr/bin/env python3
"""
CyberRule Entity Extractor v2.0
Extracts cybersecurity entities from CVE descriptions using regex patterns.
"""

import json
import re
import argparse
import os
from typing import Dict, List, Any


# ============================================================================
# CYBERRULE PATTERNS - Complete Pattern Set
# ============================================================================

CYBERRULE_PATTERNS = {
    "VulnerabilityType": r"buffer overflow|stack overflow|heap overflow|integer overflow|integer underflow|arithmetic overflow|use-after-free|UAF|double free|memory corruption|memory leak|denial of service|DoS|distributed denial of service|DDoS|SQL injection|SQLi|blind SQL injection|cross-site scripting|XSS|stored XSS|reflected XSS|DOM XSS|command injection|code injection|OS command injection|path traversal|directory traversal|arbitrary file upload|unrestricted file upload|remote code execution|RCE|arbitrary code execution|ACE|privilege escalation|local privilege escalation|LPE|horizontal privilege escalation|vertical privilege escalation|information disclosure|information exposure|sensitive data exposure|authentication bypass|authorization bypass|session fixation|session hijacking|clickjacking|cross-site request forgery|CSRF|open redirect|SSRF|server-side request forgery|XML external entity|XXE|insecure deserialization|prototype pollution|race condition|time-of-check time-of-use|TOCTOU|format string vulnerability|integer truncation|sign extension error|type confusion|out-of-bounds read|out-of-bounds write|OOB read|OOB write|heap-based buffer overflow|stack-based buffer overflow",
    
    "AttackVector": r"remote attacker|local attacker|network adjacent|physical access|wireless|bluetooth|WiFi|LAN|WAN|internet|web-based|email|malicious file|crafted file|malicious packet|crafted packet|malicious URL|phishing|social engineering|man-in-the-middle|MitM",
    
    "AttackComplexity": r"low complexity|high complexity|easily exploitable|difficult to exploit|trivial to exploit|requires user interaction|no user interaction required|authentication required|no authentication required|single factor|multi-factor",
    
    "ProductType": r"wordpress plugin|wordpress theme|joomla extension|drupal module|chrome extension|firefox extension|browser extension|mobile application|iOS app|Android app|web application|web service|REST API|SOAP API|desktop application|client software|server software|firmware|BIOS|UEFI|driver|kernel module|operating system|OS|database|DBMS|network device|router|switch|firewall|VPN|IoT device|smart device|SCADA system|industrial control system|ICS|medical device|automotive software|cloud service|SaaS|PaaS|IaaS",
    
    "Weakness": r"improper input validation|improper output validation|improper access control|missing authentication|missing authorization|insufficient sanitization|insufficient escaping|improper neutralization|hard-coded credentials|default password|weak password|weak encryption|weak cryptography|cleartext transmission|cleartext storage|session fixation|insecure session management|insecure deserialization|untrusted deserialization|improper certificate validation|improper SSL validation|improper TLS validation|NULL pointer dereference|use of hard-coded cryptographic key|improper privilege management|improper permission assignment|improper resource shutdown|uncontrolled resource consumption|infinite loop|unreachable exit condition|improper exception handling|improper error handling|information exposure through error message|verbose error message|sensitive information in URL|sensitive information in log|debug mode enabled|test functionality enabled",
    
    "Impact": r"execute arbitrary code|arbitrary command execution|arbitrary file read|arbitrary file write|arbitrary file deletion|sensitive information disclosure|data theft|data exfiltration|credential theft|password theft|session hijacking|account takeover|system crash|application crash|service disruption|service outage|unauthorized access|unauthorized read|unauthorized write|unauthorized deletion|privilege escalation|privilege reduction|security bypass|protection bypass|policy bypass",
    
    "AttackRequirement": r"authenticated user|unauthenticated attacker|low privilege user|high privilege user|administrator access|root access|system access|local access|physical access|network access|adjacent network access|user interaction|victim interaction|administrator interaction|specific configuration|default configuration|particular setup",
    
    "AffectedComponent": r"web interface|admin panel|management interface|API endpoint|REST endpoint|SOAP endpoint|database|configuration file|log file|session cookie|authentication module|authorization module|file upload component|image processing|video processing|audio processing|PDF parser|XML parser|JSON parser|HTML parser|script engine|template engine|plugin system|extension system|kernel|driver|firmware|bootloader|hypervisor|virtual machine|container|docker|kubernetes",
    
    "ExploitTechnique": r"heap spraying|return-oriented programming|ROP|jump-oriented programming|JOP|code reuse|gadget chain|format string attack|integer overflow attack|buffer overflow attack|stack smashing|heap feng shui|use-after-free exploit|type confusion exploit|prototype pollution attack|prototype chain pollution|DOM clobbering|XSS filter bypass|WAF bypass|IDS bypass|IPS bypass|anti-virus bypass|sandbox escape|container escape|privilege escalation exploit",
    
    "BypassedControl": r"same-origin policy|SOP|content security policy|CSP|XSS filter|WAF|web application firewall|IDS|intrusion detection system|IPS|intrusion prevention system|anti-virus|endpoint protection|sandbox|ASLR|address space layout randomization|DEP|data execution prevention|NX bit|stack canary|stack guard|CFI|control flow integrity|SafeSEH|SEHOP",
    
    "CryptoIssue": r"weak encryption|weak hashing|MD5|SHA1|DES|RC4|weak random number generator|predictable random|insufficient entropy|hard-coded key|hard-coded IV|improper key management|improper certificate validation|self-signed certificate|expired certificate|weak SSL|weak TLS|SSLv2|SSLv3|TLS 1\.0|downgrade attack|padding oracle|timing attack|side-channel attack",
    
    "Protocol": r"HTTP|HTTPS|FTP|SFTP|SSH|Telnet|SMTP|SMTPS|POP3|POP3S|IMAP|IMAPS|DNS|DNSSEC|DHCP|SNMP|LDAP|LDAPS|Kerberos|NTLM|SMB|CIFS|NFS|RDP|VNC|X11|ICMP|TCP|UDP|IP|IPv4|IPv6|BGP|OSPF|RIP|VRRP|HSRP|WiFi|WPA|WPA2|WPA3|WEP|Bluetooth|BLE|Zigbee|Z-Wave|Modbus|OPC|OPC UA|DNP3|IEC 61850",
    
    "ProgrammingLanguage": r"C|C\+\+|Java|Python|JavaScript|TypeScript|PHP|Ruby|Perl|Go|Golang|Rust|Swift|Kotlin|Objective-C|C#|VB\.NET|Visual Basic|PowerShell|Bash|Shell script|Assembly|ASM|SQL|PL/SQL|T-SQL|HTML|CSS|XML|JSON|YAML|Markdown|LaTeX",
    
    "FileType": r"executable|EXE|DLL|SO|binary|script|batch file|shell script|PDF|ZIP|tar|gz|bz2|7z|RAR|image file|JPEG|JPG|PNG|GIF|BMP|TIFF|SVG|video file|MP4|AVI|MKV|MOV|audio file|MP3|WAV|FLAC|document|DOC|DOCX|XLS|XLSX|PPT|PPTX|database file|DB|SQLite|MySQL|PostgreSQL|configuration file|CONF|INI|XML|JSON|YAML|log file|LOG",
    
    "Hardware": r"CPU|processor|GPU|graphics card|memory|RAM|ROM|flash memory|SSD|HDD|hard drive|storage|network card|NIC|WiFi card|Bluetooth adapter|USB controller|PCIe|PCI|BIOS|UEFI|firmware|microcontroller|MCU|FPGA|ASIC|embedded system|SoC|system on chip|IoT device|sensor|actuator|PLC|industrial controller",
    
    "Severity": r"critical|high severity|medium severity|low severity|informational|CVSS [0-9]\.[0-9]|base score [0-9]\.[0-9]|temporal score [0-9]\.[0-9]|environmental score [0-9]\.[0-9]"
}


# ============================================================================
# EXTRACTOR CLASS
# ============================================================================

class CyberRuleExtractor:
    """
    Extract cybersecurity entities from text using CyberRule patterns.
    """
    
    def __init__(self, confidence_threshold: float = 0.6):
        """
        Initialize the extractor.
        
        Args:
            confidence_threshold: Minimum confidence score for entities (0.0-1.0)
        """
        self.confidence_threshold = confidence_threshold
        self.patterns = CYBERRULE_PATTERNS
        self.compiled_patterns = {}
        
        # Compile all patterns for efficiency
        for category, pattern in self.patterns.items():
            try:
                self.compiled_patterns[category] = re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                print(f"Warning: Invalid regex in category '{category}': {e}")
    
    def calculate_confidence(self, entity_text: str, full_text: str, match) -> float:
        """
        Calculate confidence score for an entity match.
        
        Args:
            entity_text: The matched text
            full_text: The full description text
            match: The regex match object
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        confidence = 0.6  # Base confidence
        
        # Longer matches are more specific
        if len(entity_text) > 10:
            confidence += 0.1
        if len(entity_text) > 20:
            confidence += 0.05
        
        # Check for context words that increase confidence
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
                break  # Only apply once
        
        # Cap at 1.0
        return min(confidence, 1.0)
    
    def extract_entities(self, text: str) -> List[Dict[str, Any]]:
        """
        Extract entities from text.
        
        Args:
            text: The text to analyze
            
        Returns:
            List of extracted entities with metadata
        """
        if not text:
            return []
        
        entities = []
        
        for category, pattern in self.compiled_patterns.items():
            try:
                matches = pattern.finditer(text)
                for match in matches:
                    entity_text = match.group(0)
                    confidence = self.calculate_confidence(entity_text, text, match)
                    
                    if confidence >= self.confidence_threshold:
                        entities.append({
                            'text': entity_text,
                            'label': category,
                            'confidence': round(confidence, 2),
                            'start': match.start(),
                            'end': match.end()
                        })
            except Exception as e:
                # Skip problematic patterns
                continue
        
        # Sort by confidence (highest first)
        entities.sort(key=lambda x: x['confidence'], reverse=True)
        return entities
    
    def process_cve(self, cve_data: Dict) -> Dict:
        """
        Process a single CVE entry.
        
        Args:
            cve_data: Dictionary with CVE data
            
        Returns:
            Processed CVE with extracted entities
        """
        # Handle different input formats
        if isinstance(cve_data, dict):
            cve_id = cve_data.get('cve_id', cve_data.get('id', 'Unknown'))
            description = cve_data.get('description', cve_data.get('prompt_input', ''))
        else:
            cve_id = 'Unknown'
            description = str(cve_data)
        
        # Clean up description if it's in LLM prompt format
        if description.startswith('Extract cybersecurity concepts'):
            parts = description.split('\n\n', 1)
            if len(parts) > 1:
                description = parts[1]
        
        # Extract entities
        entities = self.extract_entities(description)
        
        # Count high confidence entities
        high_confidence = [e for e in entities if e['confidence'] >= 0.8]
        
        return {
            'cve_id': cve_id,
            'description': description[:500] + '...' if len(description) > 500 else description,
            'entities': entities,
            'total_entities': len(entities),
            'high_confidence_count': len(high_confidence),
            'extraction_metadata': {
                'threshold': self.confidence_threshold,
                'pattern_categories': len(self.patterns)
            }
        }
    
    def process_cve_list(self, cve_list: List[Dict]) -> List[Dict]:
        """
        Process a list of CVE entries.
        
        Args:
            cve_list: List of CVE dictionaries
            
        Returns:
            List of processed CVE results
        """
        results = []
        total = len(cve_list)
        
        for i, cve in enumerate(cve_list):
            if (i + 1) % 100 == 0 or i == 0:
                print(f"  Processing {i + 1}/{total}...")
            result = self.process_cve(cve)
            results.append(result)
        
        return results


# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    """Main entry point for command-line usage."""
    parser = argparse.ArgumentParser(
        description='Extract cybersecurity entities from CVE data using CyberRule patterns'
    )
    parser.add_argument(
        '--input', '-i',
        required=True,
        help='Input JSON file with CVE data'
    )
    parser.add_argument(
        '--output', '-o',
        required=True,
        help='Output JSON file for results'
    )
    parser.add_argument(
        '--threshold', '-t',
        type=float,
        default=0.6,
        help='Confidence threshold (0.0-1.0, default: 0.6)'
    )
    
    args = parser.parse_args()
    
    # Validate input file
    if not os.path.exists(args.input):
        print(f"Error: Input file not found: {args.input}")
        return 1
    
    # Load CVE data
    print(f"Loading CVE data from {args.input}...")
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            cve_data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in input file: {e}")
        return 1
    except Exception as e:
        print(f"Error loading input file: {e}")
        return 1
    
    # Normalize to list format
    if isinstance(cve_data, dict):
        # Check if it's a dict of CVEs (keyed by CVE ID like "CVE-2023-0001")
        first_key = list(cve_data.keys())[0]
        if first_key.startswith('CVE-'):
            # Convert dict format to list format
            cve_list = []
            for cve_id, description in cve_data.items():
                cve_list.append({
                    'cve_id': cve_id,
                    'description': description
                })
        else:
            # Regular dict with nested objects
            cve_list = list(cve_data.values())
    else:
        cve_list = cve_data
    
    print(f"Loaded {len(cve_list)} CVE entries")
    
    # Initialize extractor
    print(f"\nInitializing extractor (threshold={args.threshold})...")
    extractor = CyberRuleExtractor(confidence_threshold=args.threshold)
    print(f"Loaded {len(extractor.patterns)} pattern categories")
    
    # Process CVEs
    print("\nExtracting entities...")
    results = extractor.process_cve_list(cve_list)
    
    # Calculate statistics
    cves_with_entities = sum(1 for r in results if r['total_entities'] > 0)
    total_entities = sum(r['total_entities'] for r in results)
    high_confidence_entities = sum(r['high_confidence_count'] for r in results)
    
    # Entity type breakdown
    entity_type_counts = {}
    for r in results:
        for e in r['entities']:
            label = e['label']
            entity_type_counts[label] = entity_type_counts.get(label, 0) + 1
    
    # Prepare output
    output_data = {
        'extraction_results': results,
        'statistics': {
            'total_cves': len(results),
            'cves_with_entities': cves_with_entities,
            'coverage_percent': round(cves_with_entities / len(results) * 100, 1) if results else 0,
            'total_entities': total_entities,
            'high_confidence_entities': high_confidence_entities,
            'average_per_cve': round(total_entities / len(results), 2) if results else 0,
            'entity_type_breakdown': entity_type_counts
        }
    }
    
    # Save results
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Error saving output file: {e}")
        return 1
    
    # Print summary
    print("\n" + "=" * 60)
    print("EXTRACTION COMPLETE")
    print("=" * 60)
    print(f"  CVEs processed: {len(results)}")
    print(f"  CVEs with entities: {cves_with_entities} ({output_data['statistics']['coverage_percent']}%)")
    print(f"  Total entities: {total_entities}")
    print(f"  High confidence: {high_confidence_entities}")
    print(f"  Average per CVE: {output_data['statistics']['average_per_cve']}")
    print(f"\n  Entity type breakdown:")
    for entity_type, count in sorted(entity_type_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    {entity_type}: {count}")
    print(f"\n  Results saved to: {args.output}")
    print("=" * 60)
    
    return 0


# ============================================================================
# SIMPLE USAGE EXAMPLE (if run as script)
# ============================================================================

if __name__ == '__main__':
    import sys
    sys.exit(main())
