import yara
import os

class YaraScanner:
    def __init__(self, rules_path='config/yara_rules'):
        self.rules = self._compile_rules(rules_path)
        
    def _compile_rules(self, rules_path):
        """Compile YARA rules from directory"""
        rule_files = {}
        for root, _, files in os.walk(rules_path):
            for file in files:
                if file.endswith('.yar') or file.endswith('.yara'):
                    path = os.path.join(root, file)
                    rule_files[file] = path
        
        try:
            return yara.compile(filepaths=rule_files)
        except yara.Error as e:
            print(f"YARA compilation error: {e}")
            return None
    
    def scan_file(self, file_path):
        """Scan a file with YARA rules"""
        if not self.rules:
            return []
            
        try:
            matches = self.rules.match(file_path)
            return [{
                'rule': match.rule,
                'tags': match.tags,
                'meta': match.meta,
                'strings': [str(s) for s in match.strings]
            } for match in matches]
        except yara.Error as e:
            print(f"YARA scan error: {e}")
            return []