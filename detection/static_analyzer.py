import os
import yara
import hashlib
import pefile
import magic
from datetime import datetime

class StaticAnalyzer:
    def __init__(self):
        # Set the rules path to the specific directory
        self.rules_path = r"C:\Users\firda\OneDrive - Strathmore University\Documents\Git1\malware-analysis-sandbox\rules\malware_signatures.yar"
        self.yara_rules = self._load_yara_rules()
        self.file_magic = magic.Magic()

    def _load_yara_rules(self):
        """Load and compile YARA rules with better error handling"""
        try:
            if not os.path.exists(self.rules_path):
                raise FileNotFoundError(f"YARA rules file not found at {self.rules_path}")
            
            # Test if file can be read
            with open(self.rules_path, 'r') as f:
                content = f.read()
            
            # Try compiling
            try:
                rules = yara.compile(filepath=self.rules_path)
                return rules
            except yara.SyntaxError as e:
                raise ValueError(f"YARA syntax error in rules file: {str(e)}")
            except yara.Error as e:
                raise ValueError(f"YARA error: {str(e)}")
                
        except Exception as e:
            raise ValueError(f"Failed to load YARA rules: {str(e)}")

    def _calculate_hashes(self, file_path):
        """Calculate multiple hash types for the file"""
        hashes = {}
        hash_algorithms = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                for algo in hash_algorithms.values():
                    algo.update(chunk)
        
        for name, algo in hash_algorithms.items():
            hashes[name] = algo.hexdigest()
        
        return hashes

    def _analyze_pe(self, file_path):
        """Analyze PE file structure"""
        try:
            pe = pefile.PE(file_path)
            info = {
                'basic': {
                    'machine_type': hex(pe.FILE_HEADER.Machine),
                    'timestamp': datetime.utcfromtimestamp(
                        pe.FILE_HEADER.TimeDateStamp
                    ).strftime('%Y-%m-%d %H:%M:%S'),
                    'sections': len(pe.sections),
                    'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                    'image_base': hex(pe.OPTIONAL_HEADER.ImageBase)
                },
                'sections': [],
                'imports': [],
                'suspicious': []
            }

            # Section analysis
            for section in pe.sections:
                sec_info = {
                    'name': section.Name.decode().rstrip('\x00'),
                    'virtual_size': hex(section.Misc_VirtualSize),
                    'virtual_address': hex(section.VirtualAddress),
                    'characteristics': hex(section.Characteristics)
                }
                info['sections'].append(sec_info)

                # Detect suspicious section characteristics
                if section.Characteristics & 0xE0000020:  # EXECUTE | READ | WRITE
                    info['suspicious'].append(
                        f"Writable executable section: {sec_info['name']}"
                    )

            # Import analysis
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    imports = [imp.name.decode() for imp in entry.imports if imp.name]
                    info['imports'].append({
                        'dll': entry.dll.decode(),
                        'functions': imports
                    })

            pe.close()
            return info
        except pefile.PEFormatError as e:
            return {'error': f"PE parsing error: {str(e)}"}
        except Exception as e:
            return {'error': f"Unexpected PE analysis error: {str(e)}"}

    def analyze(self, file_path):
        """Perform complete static analysis"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        results = {
            'file_info': {
                'path': file_path,
                'size': os.path.getsize(file_path),
                'type': self.file_magic.from_file(file_path),
                'hashes': self._calculate_hashes(file_path)
            },
            'pe_info': None,
            'yara': []
        }

        # PE Analysis
        try:
            results['pe_info'] = self._analyze_pe(file_path)
        except Exception as e:
            results['pe_error'] = str(e)

        # YARA Scanning
        try:
            matches = self.yara_rules.match(file_path)
            results['yara'] = [
                {
                    'rule': match.rule,
                    'meta': match.meta,
                    'strings': [
                        {'offset': s[0], 'identifier': s[1], 'data': s[2]}
                        for s in match.strings
                    ]
                }
                for match in matches
            ]
        except Exception as e:
            results['yara_error'] = str(e)

        return results