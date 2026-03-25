#CyberRule Coverage Analysis for 80+ pattern extraction
# INJECTION VULNERABILITIES
            'SQLInjection': {
                'patterns': [
                    r'\bsql\s*injection',
                    r'\bsqli',
                    r'\bblind\s*sql\s*injection',
                    r'\bsql\s*injection\s*vulnerability',
                    r'\bsql\s*query\s*injection',
                ],
                'context_required': ['sql', 'database', 'query', 'injection', 'select'],
                'confidence': 0.88,
                'category': 'injection'
            },
            'CommandInjection': {
                'patterns': [
                    r'\bcommand\s*injection',
                    r'\bos\s*command\s*injection',
                    r'\bshell\s*injection',
                    r'\bremote\s*command\s*execution',
                ],
                'context_required': ['command', 'shell', 'execute', 'system', 'code'],
                'confidence': 0.88,
                'category': 'injection'
            },
            'LDAPInjection': {
                'patterns': [r'\bldap\s*injection'],
                'context_required': ['ldap', 'injection', 'query'],
                'confidence': 0.9,
                'category': 'injection'
            },
            
            # CROSS-SITE SCRIPTING
            'CrossSiteScripting': {
                'patterns': [
                    r'\bcross[-\s]?site\s+scripting',
                    r'\bxss',
                    r'\breflected\s+xss',
                    r'\bstored\s+xss',
                    r'\bdom\s*xss',
                    r'\bxss\s+vulnerability',
                ],
                'context_required': ['script', 'javascript', 'html', 'browser', 'xss', 'web'],
                'confidence': 0.85,
                'category': 'xss'
            },
            
            # BUFFER OVERFLOWS
            'BufferOverflow': {
                'patterns': [
                    r'\bbuffer\s*overflow',
                    r'\bstack\s*overflow',
                    r'\bheap\s*overflow',
                    r'\binteger\s*overflow',
                    r'\bstack\s*buffer\s*overflow',
                    r'\bheap\s*buffer\s*overflow',
                ],
                'context_required': ['buffer', 'memory', 'stack', 'heap', 'overflow'],
                'confidence': 0.85,
                'category': 'overflow'
            },
            
            # PATH TRAVERSAL
            'PathTraversal': {
                'patterns': [
                    r'\bpath\s*traversal',
                    r'\bdirectory\s*traversal',
                    r'\btraversal\s*vulnerability',
                    r'\blfi',
                    r'\brfi',
                ],
                'context_required': ['file', 'path', 'directory', 'traversal', 'lfi', 'rfi'],
                'confidence': 0.8,
                'category': 'path'
            },
            
            # AUTHENTICATION ISSUES
            'AuthenticationBypass': {
                'patterns': [
                    r'\bauthentication\s*bypass',
                    r'\bauth\s*bypass',
                    r'\blogin\s*bypass',
                    r'\bmissing\s*authentication',
                    r'\bbroken\s*authentication',
                ],
                'context_required': ['auth', 'login', 'session', 'credential', 'bypass'],
                'confidence': 0.8,
                'category': 'authentication'
            },
            'PrivilegeEscalation': {
                'patterns': [
                    r'\bprivilege\s*escalation',
                    r'\bprivilege\s*elevation',
                    r'\bincorrect\s*authorization',
                    r'\bmissing\s*authorization',
                    r'\bidor',
                    r'\binsecure\s*direct\s*object\s*reference',
                ],
                'context_required': ['privilege', 'authorization', 'permission', 'access', 'idor'],
                'confidence': 0.8,
                'category': 'authorization'
            },
            
            # CROSS-SITE REQUEST FORGERY
            'CrossSiteRequestForgery': {
                'patterns': [
                    r'\bcross[-\s]?site\s*request\s*forgery',
                    r'\bcsrf',
                    r'\bxsrf',
                ],
                'context_required': ['csrf', 'forgery', 'request', 'token'],
                'confidence': 0.8,
                'category': 'csrf'
            },
            
            # INFORMATION DISCLOSURE
            'InformationDisclosure': {
                'patterns': [
                    r'\binformation\s*disclosure',
                    r'\binformation\s*exposure',
                    r'\bsensitive\s*data\s*exposure',
                    r'\bdata\s*leak',
                    r'\binformation\s*leak',
                    r'\bexposure\s*of\s*sensitive\s*information',
                ],
                'context_required': ['information', 'data', 'sensitive', 'disclosure', 'exposure', 'leak'],
                'confidence': 0.75,
                'category': 'info'
            },
            
            # XML EXTERNAL ENTITY
            'XMLExternalEntity': {
                'patterns': [
                    r'\bxml\s*external\s*entity',
                    r'\bxxe',
                    r'\bxml\s*entity\s*expansion',
                ],
                'context_required': ['xml', 'entity', 'external', 'xxe'],
                'confidence': 0.8,
                'category': 'xxe'
            },
            
            # SERVER-SIDE REQUEST FORGERY
            'ServerSideRequestForgery': {
                'patterns': [
                    r'\bserver[-\s]?side\s*request\s*forgery',
                    r'\bssrf',
                ],
                'context_required': ['ssrf', 'server', 'request', 'forgery'],
                'confidence': 0.8,
                'category': 'ssrf'
            },
            
            # DESERIALIZATION
            'Deserialization': {
                'patterns': [
                    r'\binsecure\s*deserialization',
                    r'\bdeserialization\s*of\s*untrusted\s*data',
                    r'\bdeserialization\s*vulnerability',
                ],
                'context_required': ['deserialization', 'untrusted', 'data'],
                'confidence': 0.85,
                'category': 'memory'
            },
            
            # DENIAL OF SERVICE
            'DenialOfService': {
                'patterns': [
                    r'\bdenial\s*of\s*service',
                    r'\bdos',
                    r'\bresource\s*exhaustion',
                    r'\bdos\s*attack',
                    r'\bdos\s*vulnerability',
                ],
                'context_required': ['dos', 'denial', 'service', 'resource', 'exhaustion'],
                'confidence': 0.75,
                'category': 'dos'
            },
            
            # REMOTE CODE EXECUTION
            'RemoteCodeExecution': {
                'patterns': [
                    r'\bremote\s*code\s*execution',
                    r'\brce',
                    r'\barbitrary\s*code\s*execution',
                ],
                'context_required': ['remote', 'code', 'execution', 'rce', 'arbitrary'],
                'confidence': 0.9,
                'category': 'rce'
            },
            
            # MEMORY CORRUPTION
            'MemoryCorruption': {
                'patterns': [
                    r'\buse[-\s]?after[-\s]?free',
                    r'\buaf',
                    r'\bout[-\s]?of[-\s]?bounds',
                    r'\bdouble\s*free',
                    r'\bheap\s*corruption',
                ],
                'context_required': ['memory', 'heap', 'free', 'uaf', 'bounds', 'corruption'],
                'confidence': 0.85,
                'category': 'memory'
            },
            
            # RACE CONDITIONS
            'RaceCondition': {
                'patterns': [
                    r'\brace\s*condition',
                    r'\btoctou',
                    r'\btime\s*of\s*check\s*time\s*of\s*use',
                ],
                'context_required': ['race', 'condition', 'toctou', 'check', 'use'],
                'confidence': 0.75,
                'category': 'race'
            },
            
            # HARDCODED CREDENTIALS
            'HardcodedCredentials': {
                'patterns': [
                    r'\bhardcoded\s*credentials?',
                    r'\bhardcoded\s*password',
                    r'\bhardcoded\s*key',
                    r'\bhardcoded\s*secret',
                ],
                'context_required': ['hardcoded', 'credential', 'password', 'key', 'secret'],
                'confidence': 0.8,
                'category': 'auth'
            },
            
            # ADDITIONAL VULNERABILITY TYPES
            'OpenRedirect': {
                'patterns': [
                    r'\bopen\s*redirect',
                    r'\burl\s*redirection',
                ],
                'context_required': ['redirect', 'url', 'redirection', 'open'],
                'confidence': 0.85,
                'category': 'redirect'
            },
            'FileUpload': {
                'patterns': [
                    r'\bunrestricted\s*file\s*upload',
                    r'\barbitrary\s*file\s*upload',
                ],
                'context_required': ['file', 'upload', 'arbitrary', 'unrestricted'],
                'confidence': 0.85,
                'category': 'file'
            },
            'Clickjacking': {
                'patterns': [
                    r'\bclickjacking',
                    r'\bui\s*redressing',
                ],
                'context_required': ['clickjacking', 'ui', 'redressing', 'click'],
                'confidence': 0.9,
                'category': 'ui'
            },
     
