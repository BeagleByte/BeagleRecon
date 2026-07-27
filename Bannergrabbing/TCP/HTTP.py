from Bannergrabbing.base_grabber import BaseGrabber
import socket

class HTTPGrabber(BaseGrabber):
    def grab(self):
        try:
            with socket.create_connection((self.ip, self.port), self.timeout) as sock:
                sock.sendall(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % self.ip.encode())
                banner = sock.recv(4096)
                return banner.decode(errors="replace").strip()
        except Exception as e:
            return f"HTTP grab failed: {e}"