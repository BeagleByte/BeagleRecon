import nmap


class NmapScriptRunner:
    def run_scripts(self, target: str, port: int, protocol: str, scripts: list[str]) -> dict[str, str]:
        if not scripts:
            return {}
        arguments = f"--script={','.join(scripts)}"
        if protocol == "udp":
            arguments += " -sU"
        else:
            arguments += " -sT"
        scanner = nmap.PortScanner()
        try:
            scanner.scan(hosts=target, ports=str(port), arguments=arguments)
        except nmap.PortScannerError as exc:
            return {"error": str(exc)}

        for host in scanner.all_hosts():
            port_data = scanner[host].get(protocol, {}).get(port, {})
            script_output = port_data.get("script", {})
            return {name: str(output).strip() for name, output in script_output.items()}
        return {}
