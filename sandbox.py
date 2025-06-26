import os
from detection.yara_scan import scan_file
from monitors.file_monitor import monitor_directory

def is_safe_path(path, base_dir):
    """Prevent path traversal attacks"""
    return os.path.abspath(path).startswith(os.path.abspath(base_dir))

def analyze_sample(sample_path):
    if not os.path.exists(sample_path):
        print(f"[!] Error: File '{sample_path}' not found!")
        return

    if not is_safe_path(sample_path, "samples"):
        print("[!] Security Alert: Sample must be in 'samples/' directory!")
        return

    print(f"\n[+] Analyzing: {os.path.basename(sample_path)}")
    
    # Static Analysis
    print("[1/3] Running YARA scan...")
    yara_results = scan_file(sample_path)
    print(f"🔍 YARA Results: {yara_results or 'No matches found'}")

    # Dynamic Analysis
    print("\n[2/3] Starting behavioral monitoring (Ctrl+C to stop)...")
    try:
        monitor_directory(os.path.dirname(sample_path)) 
    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped by user")

    print("\n[3/3] Analysis complete!")
    print("⚠️  Remember to revert VM snapshots if testing real malware")

if __name__ == "__main__":
    print("=== Malware Analysis Sandbox ===")
    sample = input("Enter sample path (relative to 'samples/'): ").strip()
    
    # Auto-prepend samples/ if not provided
    if not sample.startswith("samples" + os.sep):
        sample = os.path.join("samples", sample)
    
    analyze_sample(sample)