import yara
import os
import logging
from typing import Dict, Optional, Union
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class YaraScanner:
    def __init__(self, rules_dir: str = None):
        """
        Initialize YARA scanner with rules from specified directory
        
        Args:
            rules_dir: Path to directory containing YARA rules (.yar files)
        """
        self.rules = None
        # Use absolute path to rules directory if not provided
        if rules_dir is None:
            self.rules_dir = r"C:\Users\firda\OneDrive - Strathmore University\Documents\Git1\Brainwave_Matrix_Intern_T2\rules"
        else:
            self.rules_dir = rules_dir
        self._load_rules()

    def _load_rules(self) -> bool:
        """Load and compile YARA rules from directory"""
        try:
            if not os.path.exists(self.rules_dir):
                logger.error(f"Rules directory not found: {self.rules_dir}")
                return False

            rule_files = list(Path(self.rules_dir).glob("*.yar")) + list(Path(self.rules_dir).glob("*.yara"))
            if not rule_files:
                logger.error(f"No YARA rules found in {self.rules_dir}")
                return False

            rules_dict = {}
            for rule_file in rule_files:
                try:
                    rules_dict[str(rule_file)] = str(rule_file)
                    logger.info(f"Loaded YARA rule: {rule_file.name}")
                except yara.SyntaxError as e:
                    logger.error(f"Syntax error in {rule_file}: {str(e)}")
                except Exception as e:
                    logger.error(f"Error loading {rule_file}: {str(e)}")

            self.rules = yara.compile(filepaths=rules_dict)
            return True
            
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {str(e)}")
            return False

    def scan_file(self, file_path: str) -> Dict[str, Union[dict, str]]:
        """
        Scan a file with loaded YARA rules
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            Dictionary with:
            - matches: Dict of rule matches (if any)
            - error: Error message (if failed)
            - status: Scan status
        """
        result = {
            "matches": {},
            "error": None,
            "status": "not_run"
        }

        if not self.rules:
            result["error"] = "YARA rules not loaded"
            result["status"] = "error"
            return result

        if not os.path.exists(file_path):
            result["error"] = f"File not found: {file_path}"
            result["status"] = "error"
            return result

        try:
            matches = self.rules.match(file_path)
            if matches:
                result["matches"] = {
                    match.rule: {
                        "meta": match.meta,
                        "tags": match.tags,
                        "strings": [
                            {
                                "identifier": s.identifier,
                                "data": str(s),
                                "offset": s.offset
                            } for s in match.strings
                        ]
                    } for match in matches
                }
                result["status"] = "matched"
            else:
                result["status"] = "clean"
                
            return result
            
        except yara.Error as e:
            result["error"] = f"YARA error: {str(e)}"
            result["status"] = "error"
            return result
        except Exception as e:
            result["error"] = f"Scan failed: {str(e)}"
            result["status"] = "error"
            return result

    def scan_buffer(self, buffer: bytes) -> Dict[str, Union[dict, str]]:
        """
        Scan in-memory buffer with YARA rules
        
        Args:
            buffer: Binary data to scan
            
        Returns:
            Same result format as scan_file()
        """
        if not self.rules:
            return {
                "error": "YARA rules not loaded",
                "status": "error"
            }

        try:
            matches = self.rules.match(data=buffer)
            return {
                "matches": {
                    match.rule: {
                        "meta": match.meta,
                        "strings": [str(s) for s in match.strings]
                    } for match in matches
                } if matches else {},
                "status": "matched" if matches else "clean"
            }
        except Exception as e:
            return {
                "error": str(e),
                "status": "error"
            }

# Singleton pattern for easy access
yara_scanner = YaraScanner()

def scan_file(file_path: str) -> Dict[str, Union[dict, str]]:
    """Convenience function for simple file scanning"""
    return yara_scanner.scan_file(file_path)

def scan_buffer(buffer: bytes) -> Dict[str, Union[dict, str]]:
    """Convenience function for simple buffer scanning"""
    return yara_scanner.scan_buffer(buffer)