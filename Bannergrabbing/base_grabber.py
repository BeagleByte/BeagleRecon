import socket
from abc import ABC, abstractmethod

class BaseGrabber(ABC):
    def __init__(self, ip, port, timeout=5):
        self.ip = ip
        self.port = port
        self.timeout = timeout

    @abstractmethod
    def grab(self) -> str:
        """Return the banner string or an error description."""
        pass