#!/usr/bin/env python3
"""
Hardcoded pattern dictionaries from CyberRule-Enricher.py
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

# Vulnerability Types (16 patterns)
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

