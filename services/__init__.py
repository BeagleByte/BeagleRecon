from services.dns_module import DnsModule
from services.ftp_module import FtpModule
from services.http_module import HttpModule
from services.https_module import HttpsModule
from services.imap_module import ImapModule
from services.pop3_module import Pop3Module
from services.rdp_module import RdpModule
from services.service_registry import ServiceRegistry
from services.smb_module import SmbModule
from services.smtp_module import SmtpModule
from services.snmp_module import SnmpModule
from services.ssh_module import SshModule
from services.telnet_module import TelnetModule


def create_default_registry(timeout: float = 5.0) -> ServiceRegistry:
    registry = ServiceRegistry()
    for module in (
        SshModule(timeout),
        HttpModule(timeout),
        HttpsModule(timeout),
        FtpModule(timeout),
        SmtpModule(timeout),
        TelnetModule(timeout),
        SmbModule(timeout),
        RdpModule(timeout),
        ImapModule(timeout),
        Pop3Module(timeout),
        DnsModule(timeout),
        SnmpModule(timeout),
    ):
        registry.register(module)
    return registry
