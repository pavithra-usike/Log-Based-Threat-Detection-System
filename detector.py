import re
DEFAULT_RULES={
"SQL Injection":{"pattern":r"(\bunion\b.*\bselect\b|\bor\b\s*1\s*=\s*1\b|'\s*or\s*'1'\s*=\s*'1)","severity":"HIGH"},
"Cross-Site Scripting (XSS)":{"pattern":r"(<script\b|javascript:|onerror=|onload=|<svg\b|<iframe\b)","severity":"HIGH"},
"Directory Traversal":{"pattern":r"(\.\./|\.\.\\|%2e%2e(%2f|%5c))","severity":"HIGH"},
"Sensitive File Access":{"pattern":r"(/etc/passwd|/etc/shadow|/\.env\b|wp-config\.php|/id_rsa\b|\.git/config)","severity":"CRITICAL"},
"Suspicious Scanner":{"pattern":r"(\bsqlmap\b|\bnikto\b|\bnmap\b|\bgobuster\b|\bdirbuster\b|\bmasscan\b)","severity":"MEDIUM"},
"Command Injection":{"pattern":r"(;\s*(cat|whoami|id|wget|curl|bash|sh)\b|\|\s*(cat|whoami|id)\b|`[^`]+`|\$\([^)]*\))","severity":"CRITICAL"},
"SSRF Probe":{"pattern":r"(169\.254\.169\.254|localhost:\d+|127\.0\.0\.1:\d+|metadata\.google\.internal)","severity":"HIGH"},
"Credential-Stuffing Probe":{"pattern":r"(/login.*(password|username)|/oauth/token)","severity":"MEDIUM"},
"Suspicious Admin Access":{"pattern":r"(/admin(?:/|\?|$)|/wp-admin|/phpmyadmin|/administrator/index)","severity":"MEDIUM"},
"Encoded Traversal":{"pattern":r"(%252e%252e|%c0%ae|%2e%2e%2f|%2e%2e%5c)","severity":"HIGH"},
"Suspicious File Upload":{"pattern":r"(\.php[? ].*(upload|file=)|/upload.*\.(php|jsp|asp)\b)","severity":"HIGH"},
"Open Redirect Parameter":{"pattern":r"(\bredirect=|\breturn=|\bnext=)\s*https?://","severity":"MEDIUM"},
"Discovery / Recon Probes":{"pattern":r"(/robots\.txt|/sitemap\.xml|/\.git/|/\.env|/phpinfo\.php)","severity":"LOW"},
}
class ThreatDetector:
    def __init__(self,rules=None):
        self.rules=rules or DEFAULT_RULES.copy(); self._compile_all()
    def _compile_all(self):
        self.compiled={n:re.compile(r["pattern"],re.I) for n,r in self.rules.items()}
    def detect(self,text):
        out=[]
        for n,p in self.compiled.items():
            m=p.search(text)
            if m: out.append({"rule":n,"severity":self.rules[n]["severity"],"match":m.group(0)[:180]})
        return out
    def add_rule(self,name,pattern,severity="MEDIUM"):
        re.compile(pattern); self.rules[name]={"pattern":pattern,"severity":severity}; self._compile_all()
    def remove_rule(self,name): self.rules.pop(name,None); self._compile_all()
    def rule_names(self): return list(self.rules)
