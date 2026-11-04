"""In-process event bus. Server-Sent Events clients subscribe to get live toasts and refresh hints."""
import queue
import threading
import time


class Bus:
    def __init__(self):
        self.subs = []
        self.lock = threading.Lock()

    def subscribe(self):
        q = queue.Queue(maxsize=300)
        with self.lock:
            self.subs.append(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            if q in self.subs:
                self.subs.remove(q)

    def publish(self, type_, **data):
        msg = {"type": type_, "ts": time.time(), **data}
        with self.lock:
            subs = list(self.subs)
        for q in subs:
            try:
                q.put_nowait(msg)
            except queue.Full:
                pass  # slow client: drop rather than block the detection loop

    def toast(self, level, title, text="", incident_id=None, critical=False):
        """level: info | success | warning | danger"""
        self.publish("toast", level=level, title=title, text=text,
                     incident_id=incident_id, critical=critical)
