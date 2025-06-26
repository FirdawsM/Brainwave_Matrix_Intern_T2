from PyQt6.QtCore import QThread, pyqtSignal, QMutex, QMutexLocker
import psutil
import time

class ProcessMonitorThread(QThread):
    process_activity = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self._running = False
        self.mutex = QMutex()
        self.initial_processes = set(p.pid for p in psutil.process_iter())
        
    def run(self):
        self._running = True
        while self.is_running():
            current_processes = set()
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                current_processes.add(proc.info['pid'])
                if proc.info['pid'] not in self.initial_processes:
                    cmd = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                    self.process_activity.emit(
                        f"New process: {proc.info['name']} (PID: {proc.info['pid']}) {cmd}"
                    )
            self.initial_processes.update(current_processes)
            time.sleep(1)
    
    def is_running(self):
        with QMutexLocker(self.mutex):
            return self._running
            
    def stop(self):
        with QMutexLocker(self.mutex):
            self._running = False