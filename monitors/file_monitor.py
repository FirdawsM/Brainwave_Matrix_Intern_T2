from PyQt6.QtCore import QThread, pyqtSignal, QMutex, QMutexLocker
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os

class FileMonitorThread(QThread):
    file_activity = pyqtSignal(str)
    # In FileMonitorThread
    MAX_FILE_EVENTS = 1000  # Stop after observing this many changes

    def __init__(self, sample_path):
        super().__init__()
        self.sample_dir = os.path.dirname(sample_path)
        self._is_running = False
        self.mutex = QMutex()
        self.observer = None

    def run(self):
        class Handler(FileSystemEventHandler):
            def __init__(self, callback):
                self.callback = callback
            
            def on_modified(self, event):
                self.callback(f"📄 Modified: {os.path.basename(event.src_path)}")

        self._is_running = True
        try:
            self.observer = Observer()
            self.observer.schedule(
                Handler(self.file_activity.emit),
                self.sample_dir,
                recursive=True
            )
            self.observer.start()
            
            while self.is_running():
                time.sleep(0.5)
                
        except Exception as e:
            self.file_activity.emit(f"❌ Monitor error: {str(e)}")
        finally:
            if self.observer:
                self.observer.stop()
                self.observer.join()

    def is_running(self):
        with QMutexLocker(self.mutex):
            return self._is_running

    def stop(self):
        with QMutexLocker(self.mutex):
            self._is_running = False