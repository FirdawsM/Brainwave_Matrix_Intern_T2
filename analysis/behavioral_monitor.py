from PyQt6.QtCore import QObject, pyqtSignal
from monitors.file_monitor import FileMonitorThread
from monitors.process_monitor import ProcessMonitorThread
from monitors.network_sniffer import NetworkSnifferThread

class BehavioralMonitor(QObject):
    activity_detected = pyqtSignal(str, str)  # (monitor_type, message)
    
    def __init__(self, sample_path):
        super().__init__()
        self.sample_path = sample_path
        self.monitors = []
        
    def start(self):
        # File monitoring
        file_monitor = FileMonitorThread(self.sample_path)
        file_monitor.file_activity.connect(
            lambda msg: self.activity_detected.emit("FILE", msg))
        file_monitor.start()
        self.monitors.append(file_monitor)
        
        # Process monitoring
        process_monitor = ProcessMonitorThread()
        process_monitor.process_activity.connect(
            lambda msg: self.activity_detected.emit("PROCESS", msg))
        process_monitor.start()
        self.monitors.append(process_monitor)
        
        # Network monitoring
        network_monitor = NetworkSnifferThread()
        network_monitor.network_activity.connect(
            lambda msg: self.activity_detected.emit("NETWORK", msg))
        network_monitor.start()
        self.monitors.append(network_monitor)
    
    def stop(self):
        for monitor in self.monitors:
            monitor.stop()
            monitor.wait(1000)