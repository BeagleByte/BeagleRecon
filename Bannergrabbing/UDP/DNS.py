import socket
from Bannergrabbing.base_grabber import BaseGrabber

class DNSGrabber(BaseGrabber):
    def grab(self):
        # DNS query for "." (root servers) CHAOS class TXT "version.bind"
        query = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03'
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(query, (self.ip, self.port))
            data, _ = sock.recvfrom(512)
            return data.hex()  # will be parsed later
        except Exception as e:
            return f"DNS grab failed: {e}"