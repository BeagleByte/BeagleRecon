import socket
import struct

from services.service_module import ServiceModule


class DnsModule(ServiceModule):
    service_name = "dns"
    default_ports = (53,)
    protocol = "udp"

    def grab_banner(self, ip: str, port: int) -> str:
        query = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
                b"\x07version\x04bind\x00\x00\x10\x00\x03"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                sock.sendto(query, (ip, port))
                data, _ = sock.recvfrom(512)
            return self._parse_version_response(data)
        except Exception as exc:
            return f"DNS banner grab failed: {exc}"

    def _parse_version_response(self, data: bytes) -> str:
        try:
            header_end = 12
            offset = header_end
            while offset < len(data) and data[offset] != 0:
                offset += 1 + data[offset]
            offset += 5
            offset += 2
            if offset + 1 < len(data) and data[offset:offset + 2] == b"\xc0\x0c":
                offset += 2
            offset += 8
            rdlength = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2
            payload = data[offset:offset + rdlength]
            return payload.decode(errors="replace").strip() or data.hex()
        except (struct.error, IndexError):
            return data.hex()

    def nmap_scripts(self) -> list[str]:
        return ["dns-nsid", "dns-recursion"]
