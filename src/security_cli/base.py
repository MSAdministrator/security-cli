from security_cli.logger import LoggingBase
from security_cli.config import ConfigManager


class Base(metaclass=LoggingBase):

    def __init__(self) -> None:
        self.__logger.debug("loading ConfigManager config")
        self._config = ConfigManager().load()
