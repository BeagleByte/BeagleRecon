import os
from datetime import datetime

def generate_report(data, target_ip, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)
    assets_dir = "assets"
    os.makedirs(assets_dir, exist_ok=True)

    date_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    md_name = f"{date_str}_{target_ip}_report.md"
    html_name = f"{date_str}_{target_ip}_report.html"
    md_path = os.path.join(output_dir, md_name)
    html_path = os.path.join(output_dir, html_name)

    # Build Markdown content
    md = f"# Recon Report for {target_ip}\n\n"
    md += "## Open Ports\n\n"
    for ip, port, proto, state in data["open_ports"]:
        md += f"- {port}/{proto} ({state})\n"

    md += "\n## Service Banners\n\n"
    for svc, banner in data["banners"].items():
        md += f"### {svc}\n```\n{banner}\n```\n\n"

    md += "\n## Other Services (nmap -sCV)\n\n"
    for port, info in data["other_services"].items():
        md += f"- {port}: {info}\n"

    md += "\n## Vulnerability Checks\n\n"
    for svc, vuln_output in data["vulnerabilities"].items():
        md += f"### {svc}\n```\n{vuln_output}\n```\n"

    with open(md_path, "w") as f:
        f.write(md)

    # Convert MD to HTML manually or using a lib (markdown, mistune)
    # For simplicity, embed the Markdown as <pre> inside an HTML template
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Recon Report - {target_ip}</title>
    <link rel="stylesheet" href="../assets/style.css">
</head>
<body>
    <div class="report">
        <pre>{md}</pre>
    </div>
</body>
</html>"""
    with open(html_path, "w") as f:
        f.write(html)

    return md_path, html_path