from services.service_module import ServiceModule


class GenericModule(ServiceModule):
    service_name = "generic"
    default_ports: tuple[int, ...] = ()
    protocol = "tcp"

    def grab_banner(self, ip: str, port: int) -> str:
        return ""
