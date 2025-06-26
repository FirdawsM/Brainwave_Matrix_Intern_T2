# Malware Analysis Sandbox

A Python-based sandbox environment for analyzing malware samples in a controlled and safe manner. This tool performs both static and behavioral (dynamic) analysis to help detect and understand malicious files.

## Features

- **Static Analysis:**
  - Scans files using comprehensive YARA rules for known malware signatures, suspicious scripts, macros, and encoded data.
  - Supports both PE (Windows executables) and non-PE files (scripts, documents, text, etc).
  - Detects EICAR test files, suspicious script keywords, document macros, and encoded payloads.
  - Validates PE structure and detects packers, suspicious sections, and known malicious hashes.
- **Behavioral Monitoring:**
  - Monitors file system changes (creation, modification, deletion) in the sample's directory during execution.
  - (Optional) Can be extended to monitor process activity and network traffic.
- **Safe Sample Handling:**
  - By default, the sandbox restricts analysis to files in the `samples/` directory for safety.
  - You can optionally allow analysis of any file on your system. If you select a file outside `samples/`, the GUI will show a warning before proceeding.
  - This provides flexibility while helping prevent accidental analysis of important system or personal files.
  - Path traversal protection to avoid analyzing files outside the intended directory.
- **Extensible Design:**
  - Easily add new YARA rules in `rules/malware_signatures.yar`.
  - Add new behavioral monitors in the `monitors/` directory.
  - Modular codebase for future expansion (e.g., GUI, reporting, more monitors).

## Getting Started

### Prerequisites
- Python 3.8 or higher
- YARA (Python package)
- Other dependencies listed in `requirements.txt`

### Installation
1. Clone this repository or download the source code.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. (Optional) Install YARA system-wide if not included in your Python environment.

### Usage
1. Place your sample files in the `samples/` directory.
2. Run the sandbox:
   ```bash
   python sandbox.py
   ```
3. Enter the sample filename when prompted (relative to `samples/`).
4. View static and behavioral analysis results in the terminal.
5. (Optional) Check the `reports/` directory for generated reports.

## Important Note on YARA Rules Path

If you move or rename this project, or clone it to a new location, make sure that the path to the YARA rules directory is correct. By default, the project expects the rules to be in a folder named `rules` inside the project directory (e.g., `<your_project_folder>/rules`).

If you encounter errors like:

```
Failed to load YARA rules: YARA rules file not found at ...
```

update the path in `detection/yara_scan.py` and `detection/static_analyzer.py` to match the location of your `rules` folder in your current workspace.

## Requirements

All required Python packages are listed in `requirements.txt`:

```
yara-python
python-magic
pefile
PyQt6
```

Install them with:

```
pip install -r requirements.txt
```

## Installing YARA (System-wide)

In addition to the Python package (`yara-python`), you may need to install the YARA binary for your operating system:

**Windows:**
1. Download the latest YARA release from the [official YARA GitHub releases](https://github.com/VirusTotal/yara/releases).
2. Extract the ZIP and add the folder containing `yara.exe` to your system `PATH` (optional, for command-line use).

**Linux (Debian/Ubuntu):**
```bash
sudo apt update
sudo apt install yara
```

**macOS (Homebrew):**
```bash
brew install yara
```

If you only use the Python API, installing `yara-python` via `pip` is usually sufficient. For advanced features or command-line use, install the system binary as above.

## Project Structure
- `sandbox.py` — Main CLI for running analysis and orchestrating static/dynamic checks
- `gui_sandbox.py` — (Optional) GUI version for interactive analysis
- `detection/` — YARA scanning and static analysis logic
  - `yara_scan.py` — Loads and applies YARA rules
  - `static_analyzer.py` — (Extendable) Static file analysis
- `monitors/` — Behavioral monitoring modules
  - `file_monitor.py` — Monitors file system changes
  - `process_monitor.py` — (Optional) Monitors process activity
  - `network_sniffer.py` — (Optional) Monitors network traffic
- `rules/` — YARA rules for malware detection
  - `malware_signatures.yar` — Main YARA ruleset
- `samples/` — Place your test files here
- `reports/` — (Optional) Analysis reports (HTML/JSON)

## Extending the Sandbox
- **Add new YARA rules:**
  - Edit `rules/malware_signatures.yar` to include new signatures for malware, scripts, or document threats.
- **Add new monitors:**
  - Implement a new module in `monitors/` (e.g., process or network monitor).
  - Integrate it in `sandbox.py` for automatic use during analysis.
- **Improve reporting:**
  - Modify `sandbox.py` to save results to `reports/` in JSON or HTML format.
- **GUI:**
  - Use `gui_sandbox.py` for a graphical interface (if implemented).

## Safety Notice
- ⚠️ **Warning:** Analyzing malware samples can be dangerous. Always ensure you are working in a secure, isolated environment such as a virtual machine or sandboxed system. Do not use your main operating system for malware analysis.
- By default, the sandbox restricts analysis to the `samples/` directory for safety, but you can enable analysis of any file (with a warning if outside `samples/`).
- You are responsible for your own system's security.
- Never analyze live malware on your main operating system.

## Example Output
```
[+] Analyzing: test_malware.bin
[1/3] Running YARA scan...
🔍 YARA Results: No matches found
[2/3] Starting behavioral monitoring (Ctrl+C to stop)...
[3/3] Analysis complete!
⚠️  Remember to revert VM snapshots if testing real malware
```

## Troubleshooting
- **No YARA matches found:**
  - Ensure your sample contains content matching the rules in `malware_signatures.yar`.
  - Check file encoding (e.g., ASCII vs UTF-16 for EICAR).
- **Permission errors:**
  - Run the sandbox with appropriate permissions to access files in `samples/`.
- **YARA errors:**
  - Ensure YARA and all dependencies are installed correctly.

## VS Code Configuration
This project requires special VS Code settings for safe malware analysis:
1. Create `.vscode/settings.json` if it doesn't exist
2. Use the [provided configuration](#) (link to your settings)
3. Never override these settings when analyzing live malware

## License
MIT License

---