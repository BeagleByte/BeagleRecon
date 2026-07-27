from port_scanner import run_xmas_scan
from banner_grabbers import *   # import all grabbers
from other_services import OtherServicesScanner
from vulnerability_scanners import *  # per-service scanners
from report_generator import generate_report

def main(target_ip):
    # Stage 1
    open_ports = run_xmas_scan(target_ip)   # CSV saved automatically

    # Stage 2 – map ports to grabbers
    # Define known service ports
    tcp_service_map = {
        21: FTPGrabber,
        22: SSHGrabber,
        23: TelnetGrabber,
        25: SMTPGrabber,
        80: HTTPGrabber,
        443: HTTPSGrabber,
        110: POP3Grabber,
        143: IMAPGrabber,
        135: RPCGrabber,   # MSRPC
        445: SMBGrabber,
        3389: RDPGrabber,
    }
    udp_service_map = {
        53: DNSGrabber,
        161: SNMPGrabber,
        67: DHCPGrabber,
    }

    banners = {}
    other_ports = []

    for ip, port, proto, state in open_ports:
        port = int(port)
        if proto == "tcp":
            grabber_cls = tcp_service_map.get(port)
            if grabber_cls:
                grabber = grabber_cls(ip, port)
                banners[f"{grabber_cls.__name__} on {port}"] = grabber.grab()
            else:
                other_ports.append(port)

    # Handle UDP services (they won’t be in open_ports)
    for port, grabber_cls in udp_service_map.items():
        grabber = grabber_cls(target_ip, port)
        banners[f"{grabber_cls.__name__} on {port}"] = grabber.grab()

    # Other services with -sCV
    other_results = OtherServicesScanner(target_ip, other_ports).scan()

    # Stage 3 – Vulnerability scanning
    vuln_data = {}
    # For each service where we have a vulnerability scanner
    for port, grabber_cls in {**tcp_service_map, **udp_service_map}.items():
        # Map grabber to vuln scanner by name convention
        scanner_cls = globals().get(f"{grabber_cls.__name__.replace('Grabber','')}VulnScanner")
        if scanner_cls:
            scanner = scanner_cls(target_ip, port)
            vuln_data[grabber_cls.__name__] = scanner.run()

    # Generate reports
    report_data = {
        "open_ports": open_ports,
        "banners": banners,
        "other_services": other_results,
        "vulnerabilities": vuln_data,
    }
    md_path, html_path = generate_report(report_data, target_ip)
    print(f"Reports saved: {md_path}, {html_path}")

if __name__ == "__main__":
    main("192.168.1.10")