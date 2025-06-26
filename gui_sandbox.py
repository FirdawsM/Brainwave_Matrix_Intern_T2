import os
import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget, QPushButton,
    QFileDialog, QTextEdit, QLabel, QProgressBar, QTabWidget, QHBoxLayout, QComboBox
)
from PyQt6.QtCore import QThread, pyqtSignal, QTimer, QMutex, QMutexLocker
from monitors.file_monitor import FileMonitorThread
from detection.static_analyzer import StaticAnalyzer

# Ensure proper imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

class AnalysisThread(QThread):
    update_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(dict)  # Changed to emit results
    error_signal = pyqtSignal(str)

    def __init__(self, sample_path):
        super().__init__()
        self.sample_path = sample_path
        self._is_running = True
        self.mutex = QMutex()

    def run(self):
        try:
            with QMutexLocker(self.mutex):
                if not self._is_running:
                    return

            self.update_signal.emit("🔍 Starting static analysis...")
            
            # Initialize analyzer
            analyzer = StaticAnalyzer()
            self.update_signal.emit("📂 Loading YARA rules...")
            
            # Perform analysis
            static_results = analyzer.analyze(self.sample_path)
            
            # Format results for display
            formatted_results = {
                'hashes': f"📄 File Hashes:\nMD5: {static_results['file_info']['hashes']['md5']}\n"
                          f"SHA1: {static_results['file_info']['hashes']['sha1']}\n"
                          f"SHA256: {static_results['file_info']['hashes']['sha256']}",
                'pe_info': f"⚙️ PE Structure:\n{static_results['pe_info']}" if static_results['pe_info'] else "No PE info available",
                'yara': f"✅ YARA Results:\n{static_results['yara']}" if static_results['yara'] else "No YARA matches found"
            }

            self.update_signal.emit(formatted_results['hashes'])
            self.update_signal.emit(formatted_results['pe_info'])
            self.update_signal.emit(formatted_results['yara'])
            
            if self._is_running:
                self.update_signal.emit("\n👀 Starting behavioral monitoring...")
                self.finished_signal.emit(static_results)  # Emit the full results

        except Exception as e:
            self.error_signal.emit(f"Analysis Error: {str(e)}")

    def stop(self):
        with QMutexLocker(self.mutex):
            self._is_running = False
        self.quit()
        self.wait(1000)

class SandboxGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Malware Analysis Sandbox")
        self.setGeometry(100, 100, 800, 600)
        self.analysis_timeout = 30000  # 30 seconds
        self.analysis_thread = None
        self.file_monitor = None
        self.timeout_timer = None
        self.init_ui()
        
    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Title and theme toggle row
        title_row = QHBoxLayout()
        title = QLabel("<h2>Malware Analysis Sandbox</h2>")
        title.setStyleSheet("margin-bottom: 0.5em;")
        title_row.addWidget(title)
        title_row.addStretch()
        theme_label = QLabel("Theme:")
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["System", "Light", "Dark"])
        self.theme_combo.currentTextChanged.connect(self.apply_theme)
        theme_label.setStyleSheet("margin-right: 4px;")
        self.theme_combo.setStyleSheet("min-width: 80px;")
        title_row.addWidget(theme_label)
        title_row.addWidget(self.theme_combo)
        layout.addLayout(title_row)

        # Instructions
        instructions = QLabel("<i>Select a malware sample from the 'samples/' directory to begin analysis. Always use a VM for safety.</i>")
        instructions.setStyleSheet("color: #555; margin-bottom: 1em;")
        layout.addWidget(instructions)

        # Button Row
        button_layout = QHBoxLayout()
        self.btn_select = QPushButton("Select Malware Sample")
        self.btn_select.setToolTip("Choose a file from the samples directory for analysis.")
        self.btn_select.clicked.connect(self.select_sample)
        self.btn_stop = QPushButton("End Scan")
        self.btn_stop.setToolTip("Stop the current analysis and monitoring.")
        self.btn_stop.clicked.connect(self.stop_analysis)
        self.btn_stop.setEnabled(False)
        button_layout.addWidget(self.btn_select)
        button_layout.addWidget(self.btn_stop)
        layout.addLayout(button_layout)

        # Analysis Tabs
        tabs = QTabWidget()
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("background: #f8f8f8; font-family: Consolas, monospace; font-size: 11pt;")
        # Add initial prompt message as a card
        prompt_card = """
        <div style='background: #f4f6fa; border: 1.5px solid #e0e5ec; border-radius: 10px; padding: 18px 32px; margin: 30px 0; box-shadow: 0 2px 8px rgba(60,60,60,0.04); font-family: Consolas, monospace; font-size: 15pt; color: #888; text-align:center;'>
            <span style='font-size:16pt; color:#888; font-weight:bold;'>Please select a malware sample to begin analysis.</span>
        </div>
        """
        self.log_view.setHtml(prompt_card)
        tabs.addTab(self.log_view, "Analysis Log")
        self.static_tab = QTextEdit()
        self.static_tab.setReadOnly(True)
        self.static_tab.setStyleSheet("background: #f8f8ff; color: #222; font-family: Consolas, monospace; font-size: 11pt;")
        tabs.addTab(self.static_tab, "Static Analysis")
        layout.addWidget(tabs)

        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setFormat("%p% - Analysis in progress...")
        self.progress.setTextVisible(True)
        layout.addWidget(self.progress)

        # Status Bar
        self.status = QLabel("Ready.")
        self.status.setStyleSheet("color: #333; margin-top: 0.5em;")
        layout.addWidget(self.status)

    def handle_error(self, error_msg):
        self.log_view.append(f"<span style='color:red;'>❌ {error_msg}</span>")
        self.status.setText("Error: See log for details.")
        self.stop_analysis()

    def select_sample(self):
        from PyQt6.QtWidgets import QMessageBox
        from PyQt6.QtCore import QTimer
        samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "samples"))
        os.makedirs(samples_dir, exist_ok=True)
        sample, _ = QFileDialog.getOpenFileName(
            self,
            "Select Malware Sample",
            samples_dir,
            "All Files (*);;Executable Files (*.exe *.dll *.bin)",
            options=QFileDialog.Option.DontUseNativeDialog
        )
        if sample:
            if not self.is_safe_path(sample, samples_dir):
                QMessageBox.critical(
                    self,
                    "⚠️ Unsafe File Location",
                    "You selected a file OUTSIDE the 'samples/' directory.\n\nThis is NOT recommended.\n\nFor safety, only analyze files in the 'samples/' directory unless you are sure.\n\nClick OK to continue, or Cancel to abort.",
                    QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel,
                    QMessageBox.StandardButton.Cancel
                )
                def show_confirm():
                    reply = QMessageBox.question(
                        self,
                        "Proceed with Analysis?",
                        "Are you sure you want to analyze this file?\n\nThis may be unsafe.",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                        QMessageBox.StandardButton.No
                    )
                    if reply != QMessageBox.StandardButton.Yes:
                        self.log_view.append("<span style='color:red;'>❌ Analysis cancelled by user (file not in samples/).</span>")
                        self.status.setText("Analysis cancelled.")
                        # Clear summary and static analysis tabs if present
                        if hasattr(self, 'summary_tab'):
                            self.summary_tab.clear()
                        self.static_tab.clear()
                        return
                    self.start_analysis(sample)
                QTimer.singleShot(2000, show_confirm)
                return
            self.start_analysis(sample)
        elif sample:
            self.log_view.append("<span style='color:red;'>❌ Error: Invalid sample location!</span>")
            self.status.setText("Invalid sample location.")

    def start_analysis(self, sample_path):
        self.log_view.clear()
        self.static_tab.clear()
        self.progress.setValue(0)
        self.btn_select.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.status.setText("Static analysis in progress...")
        # Static analysis
        self.analysis_thread = AnalysisThread(sample_path)
        self.analysis_thread.update_signal.connect(self.update_log)
        self.analysis_thread.finished_signal.connect(self.handle_analysis_results)
        self.analysis_thread.error_signal.connect(self.handle_error)
        self.analysis_thread.start()
        # Timeout timer
        self.timeout_timer = QTimer()
        self.timeout_timer.setSingleShot(True)
        self.timeout_timer.timeout.connect(self.stop_analysis)
        self.timeout_timer.start(self.analysis_timeout)

    def handle_analysis_results(self, results):
        self.static_tab.clear()
        self.last_results = results  # Store for summary
        # Use plain text for static analysis results for clarity
        lines = []
        lines.append("=== Static Analysis Results ===")
        lines.append("\n=== File Information ===")
        lines.append(f"Path: {results['file_info']['path']}")
        lines.append(f"Size: {results['file_info']['size']} bytes")
        lines.append(f"Type: {results['file_info']['type']}")
        lines.append("\n=== Hashes ===")
        for hash_type, hash_value in results['file_info']['hashes'].items():
            lines.append(f"{hash_type.upper()}: {hash_value}")
        if results['pe_info'] and not isinstance(results['pe_info'], dict) and 'error' not in results['pe_info']:
            lines.append("\n=== PE Information ===")
            lines.append(str(results['pe_info']))
        if results['yara']:
            lines.append("\n=== YARA Matches ===")
            for match in results['yara']:
                lines.append(f"Rule: {match['rule']}")
                if 'meta' in match:
                    for k, v in match['meta'].items():
                        lines.append(f"  {k}: {v}")
        self.static_tab.setPlainText("\n".join(lines))
        from PyQt6.QtGui import QTextCursor
        self.static_tab.moveCursor(QTextCursor.MoveOperation.Start)
        # Force dark text and light background for static analysis tab
        self.static_tab.setStyleSheet("background-color: #f8f8ff; color: #111; font-family: Consolas, monospace; font-size: 12pt;")
        self.status.setText("Static analysis complete. Monitoring behavior...")
        self.start_behavioral_monitoring()

    def generate_summary_html(self, results):
        # Summarize static analysis results for the summary tab
        file_info = results.get('file_info', {})
        yara_matches = results.get('yara', [])
        pe_info = results.get('pe_info', None)
        verdict = "<span style='color:#388e3c; font-weight:bold;'>No malicious indicators detected.</span>"
        if yara_matches:
            verdict = f"<span style='color:#e53935; font-weight:bold;'>Potentially MALICIOUS! {len(yara_matches)} YARA rule(s) matched.</span>"
        # File info summary
        file_info_html = f"""
        <b>File:</b> {file_info.get('path', 'N/A')}<br>
        <b>Type:</b> {file_info.get('type', 'N/A')}<br>
        <b>Size:</b> {file_info.get('size', 'N/A')} bytes<br>
        <b>MD5:</b> {file_info.get('hashes', {}).get('md5', 'N/A')}<br>
        <b>SHA1:</b> {file_info.get('hashes', {}).get('sha1', 'N/A')}<br>
        <b>SHA256:</b> {file_info.get('hashes', {}).get('sha256', 'N/A')}<br>
        """
        # YARA summary
        if yara_matches:
            yara_html = "<ul style='margin:0 0 0 1em;'>"
            for match in yara_matches:
                rule = match.get('rule', 'Unknown')
                desc = match.get('meta', {}).get('description', '')
                yara_html += f"<li><b>{rule}</b>"
                if desc:
                    yara_html += f" - <i>{desc}</i>"
                yara_html += "</li>"
            yara_html += "</ul>"
        else:
            yara_html = "<i>No YARA rules matched.</i>"
        # PE info
        pe_html = ""
        if pe_info and not isinstance(pe_info, dict) and 'error' not in str(pe_info):
            pe_html = f"<b>PE Info:</b> <span style='color:#555;'>{str(pe_info)[:200]}{'...' if len(str(pe_info))>200 else ''}</span><br>"
        # Compose summary
        summary = f"""
        <div style='text-align:center; margin: 24px 0;'>
            <span style='display:inline-block; background:#e53935; color:#fff; font-weight:bold; font-size:20pt; padding:16px 32px; border-radius:12px; border:2px solid #fff;'>🛑 Analysis Complete!</span>
        </div>
        <hr style='border:1px solid #e0b400; margin: 24px 0;'>
        <div style='font-size:15pt; margin-bottom:12px;'>{verdict}</div>
        <div style='font-size:12pt; margin-bottom:10px;'>{file_info_html}</div>
        {pe_html}
        <div style='font-size:12pt; margin-bottom:10px;'><b>YARA Matches:</b> {yara_html}</div>
        <div style='font-size:11pt; color:#888;'>See the Static Analysis and Log tabs for full details.</div>
        """
        return summary

    def start_behavioral_monitoring(self):
        if self.analysis_thread:
            self.file_monitor = FileMonitorThread(self.analysis_thread.sample_path)
            self.file_monitor.file_activity.connect(self.update_log)
            self.file_monitor.start()
            self.log_view.append(f"<span style='color:blue;'>⏳ Monitoring for {self.analysis_timeout/1000} seconds...</span>")
            self.status.setText("Behavioral monitoring in progress...")

    def stop_analysis(self):
        # Stop file monitor
        if hasattr(self, 'file_monitor') and self.file_monitor is not None:
            if self.file_monitor.isRunning():
                self.file_monitor.stop()
                self.file_monitor.quit()
                self.file_monitor.wait(1000)

        # Stop analysis thread
        if hasattr(self, 'analysis_thread') and self.analysis_thread is not None:
            if self.analysis_thread.isRunning():
                self.analysis_thread.stop()

        # Stop timeout timer
        if hasattr(self, 'timeout_timer') and self.timeout_timer is not None:
            if self.timeout_timer.isActive():
                self.timeout_timer.stop()

        self.progress.setValue(100)
        # Add a summary/completion tab if not already present
        theme = self.theme_combo.currentText()
        summary_html = None
        if hasattr(self, 'last_results'):
            summary_html = self.generate_summary_html(self.last_results)
        if not hasattr(self, 'summary_tab'):
            from PyQt6.QtWidgets import QTextEdit
            self.summary_tab = QTextEdit()
            self.summary_tab.setReadOnly(True)
            self.summary_tab.setStyleSheet("background: #fffbe6; color: #222; font-family: Consolas, monospace; font-size: 13pt; border: 2px solid #e0b400; border-radius: 8px; padding: 16px;")
            self.centralWidget().layout().itemAt(3).widget().addTab(self.summary_tab, "Summary")
        if theme == "Dark":
            self.summary_tab.setStyleSheet("background: #2d1a1a; color: #fff; font-family: Consolas, monospace; font-size: 14pt; border: 2px solid #e53935; border-radius: 8px; padding: 18px;")
        else:
            self.summary_tab.setStyleSheet("background: #fffbe6; color: #222; font-family: Consolas, monospace; font-size: 13pt; border: 2px solid #e0b400; border-radius: 8px; padding: 16px;")
        if summary_html:
            self.summary_tab.setHtml(summary_html)
        else:
            self.summary_tab.setHtml("""
            <div style='text-align:center; margin: 24px 0;'>
                <span style='display:inline-block; background:#e53935; color:#fff; font-weight:bold; font-size:20pt; padding:16px 32px; border-radius:12px; border:2px solid #fff;'>🛑 Analysis Complete!</span>
            </div>
            <hr style='border:1px solid #e0b400; margin: 24px 0;'>
            <div style='font-size:13pt; color:#888;'>You may now review the results in the Static Analysis and Log tabs.</div>
            """)
        # Also add a visible log message for completion
        if theme == "Dark":
            self.log_view.append("<div style='background:#e53935; color:#fff; font-weight:bold; font-size:15pt; padding:8px 0; border-radius:8px; text-align:center;'>🛑 Analysis complete!</div>")
        else:
            self.log_view.append("<div style='background:#fffbe6; color:#b71c1c; font-weight:bold; font-size:15pt; padding:8px 0; border-radius:8px; text-align:center;'>🛑 Analysis complete!</div>")
        self.status.setText("Ready.")
        self.btn_select.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def update_log(self, message):
        # Modern card style for all log messages
        card_style = (
            "background: #f4f6fa; "
            "border: 1.5px solid #e0e5ec; "
            "border-radius: 10px; "
            "padding: 12px 18px; "
            "margin: 10px 0; "
            "box-shadow: 0 2px 8px rgba(60,60,60,0.04); "
            "font-family: Consolas, monospace; "
            "font-size: 12pt; "
            "color: #222; "
        )
        # Icon-specific accent (optional, can be extended)
        if message.startswith("❌"):
            card_style += "border-left: 5px solid #e53935; background: #fbeaea; color: #b71c1c;"
        elif message.startswith("✅") or message.startswith("🔍"):
            card_style += "border-left: 5px solid #0078d7; background: #eaf3fb; color: #1a237e;"
        elif message.startswith("📂"):
            card_style += "border-left: 5px solid #6a4cff; background: #f3f0fa; color: #3d246b;"
        elif message.startswith("📄"):
            card_style += "border-left: 5px solid #0078d7; background: #f4f8fd; color: #222;"
        elif message.startswith("⚙️"):
            card_style += "border-left: 5px solid #b8860b; background: #fffbe6; color: #7c5c00;"
        elif message.startswith("No YARA matches found"):
            card_style += "border-left: 5px solid #bdbdbd; background: #f7f7f7; color: #888; font-style:italic;"
        elif message.startswith("👀"):
            card_style += "border-left: 5px solid #0078d7; background: #eaf3fb; color: #0078d7;"
        elif message.startswith("⏳"):
            card_style += "border-left: 5px solid #1976d2; background: #e3f2fd; color: #1976d2;"
        elif message.startswith("🛑"):
            card_style += "border-left: 5px solid #e53935; background: #fbeaea; color: #b71c1c; font-weight:bold;"
        # Compose card
        card_html = f"<div style='{card_style}'>{message}</div>"
        self.log_view.append(card_html)
        current_progress = min(self.progress.value() + 10, 100)
        self.progress.setValue(current_progress)

    def is_safe_path(self, path, base_dir="samples"):
        # Always use absolute, normalized, and case-insensitive paths for comparison
        abs_base = os.path.abspath(base_dir)
        abs_path = os.path.abspath(path)
        # On Windows, make comparison case-insensitive
        abs_base = os.path.normcase(abs_base)
        abs_path = os.path.normcase(abs_path)
        # Debug log for troubleshooting
        print(f"[DEBUG] Checking if path is safe: {abs_path} (base: {abs_base})")
        return abs_path.startswith(abs_base + os.sep) or abs_path == abs_base

    def apply_theme(self, theme):
        # Use the same font family and size for both modes
        font_css = "font-family: Consolas, monospace; font-size: 12pt;"
        if theme == "Dark":
            self.setStyleSheet(f"""
                QMainWindow {{ background: #232629; }}
                QWidget {{ background: #232629; color: #eee; {font_css} }}
                QTextEdit, QTabWidget, QTabBar, QComboBox, QProgressBar, QLabel {{
                    background: #232629; color: #eee; {font_css}
                }}
                QPushButton {{ background: #333; color: #eee; border-radius: 6px; padding: 6px; {font_css} }}
                QPushButton:disabled {{ background: #444; color: #888; }}
                QProgressBar {{ background: #333; color: #eee; border-radius: 6px; }}
                QProgressBar::chunk {{ background: #0078d7; }}
            """)
            self.theme_combo.setStyleSheet("color: #eee; background: #232629; border: 1px solid #444;" + font_css)
        elif theme == "Light":
            self.setStyleSheet(f"""
                QMainWindow {{ background: #f8f8f8; }}
                QWidget {{ background: #f8f8f8; color: #222; {font_css} }}
                QTextEdit, QTabWidget, QComboBox, QProgressBar, QLabel {{
                    background: #f8f8f8; color: #222; {font_css}
                }}
                QTabBar::tab {{
                    background: #e0e0e0; color: #222; border: 1px solid #ccc; border-bottom: none; border-top-left-radius: 6px; border-top-right-radius: 6px; padding: 6px 16px; {font_css}
                }}
                QTabBar::tab:selected {{
                    background: #fff; color: #111; border: 2px solid #0078d7; border-bottom: none; {font_css}
                }}
                QTabBar::tab:!selected {{
                    margin-top: 2px;
                }}
                QTabWidget::pane {{
                    border: 1px solid #ccc; border-radius: 6px; top: -1px; background: #fff;
                }}
                QPushButton {{ background: #e0e0e0; color: #222; border-radius: 6px; padding: 6px; {font_css} }}
                QPushButton:disabled {{ background: #eee; color: #aaa; }}
                QProgressBar {{ background: #e0e0e0; color: #222; border-radius: 6px; }}
                QProgressBar::chunk {{ background: #0078d7; }}
            """)
            self.theme_combo.setStyleSheet("color: #111; background: #f8f8f8; border: 1px solid #ccc;" + font_css)
        else:  # System/default
            self.setStyleSheet("")
            self.theme_combo.setStyleSheet("")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SandboxGUI()
    window.show()
    sys.exit(app.exec())