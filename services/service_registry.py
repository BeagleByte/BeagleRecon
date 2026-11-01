from services.generic_module import GenericModule
from services.service_module import ServiceModule


class ServiceRegistry:
    def __init__(self):
        self._modules: list[ServiceModule] = []

    def register(self, module: ServiceModule) -> None:
        self._modules.append(module)

    def get_for_port(self, port: int, protocol: str = "tcp") -> ServiceModule:
        for module in self._modules:
            if module.protocol == protocol and module.matches_port(port):
                return module
        fallback = GenericModule()
        fallback.protocol = protocol
        return fallback

    def all(self) -> list[ServiceModule]:
        return list(self._modules)
