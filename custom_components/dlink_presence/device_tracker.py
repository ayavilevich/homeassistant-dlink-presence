"""Support for D-Link devices."""
import logging
from homeassistant.components.device_tracker import (
    DOMAIN,
    PLATFORM_SCHEMA,
    DeviceScanner,
)
from .dlink_telnet import DLinkTelnet
import voluptuous as vol

from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_USERNAME,
)
from homeassistant.helpers import config_validation as cv

_LOGGER = logging.getLogger(__name__)

CONF_REQUIRE_IP = "require_ip"

DEFAULT_TELNET_PORT = 23
DEFAULT_REQUIRE_IP = False

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_HOST): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
        vol.Required(CONF_USERNAME): cv.string,
        vol.Optional(CONF_PORT, default=DEFAULT_TELNET_PORT): cv.port,
        vol.Optional(CONF_REQUIRE_IP, default=DEFAULT_REQUIRE_IP): cv.boolean,
    }
)

#def get_scanner(hass, config):
#    """Validate the configuration and return a DD-WRT scanner."""
#    try:
#        return DLinkDeviceScanner(config[DOMAIN])
#    except ConnectionError:
#        return None

async def async_get_scanner(hass, config):
    """Validate the configuration and return a D-Link scanner."""
    scanner = DLinkDeviceScanner(config[DOMAIN])
    await scanner.async_connect()
    return scanner if scanner.success_init else None

# based on https://github.com/home-assistant/core/blob/dev/homeassistant/components/asuswrt/
# and https://github.com/home-assistant/core/blob/dev/homeassistant/components/ddwrt/device_tracker.py
class DLinkDeviceScanner(DeviceScanner):
    """This class queries a router running D-Link firmware."""

    def __init__(self, config):
        """Initialize the scanner."""
        self.last_results = {}
        self.success_init = False
        self._connect_error = False
        self.host = config[CONF_HOST]
        self.connection = DLinkTelnet(
            config[CONF_HOST],
            config[CONF_PORT],
            config[CONF_USERNAME],
            config.get(CONF_PASSWORD, ""),
            config[CONF_REQUIRE_IP],
        )
        _LOGGER.info("Starting D-Link scanner, host %s", self.host)

    async def async_connect(self):
        """Initialize connection to the router."""
        # Test the router is accessible.
        try:
            data = await self.connection.async_get_connected_devices()
            self.success_init = data is not None
        except OSError as ex:
            _LOGGER.warning(
                "Error [%s] connecting %s to %s.",
                str(ex),
                DOMAIN,
                self.host,
            )
            raise ConnectionError("Cannot connect to D-Link router")

        if not self.connection.is_connected:
            _LOGGER.error("Error connecting %s to %s", DOMAIN, self.host)
            raise ConnectionError("Cannot connect to D-Link router")

    async def async_scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        await self.async_update_info()
        return list(self.last_results.keys())

    async def async_get_device_name(self, device):
        """Return the name of the given device or None if we don't know."""
        if device not in self.last_results:
            return None
        return self.last_results[device].name

    async def async_update_info(self):
        """Ensure the information from the D-Link router is up to date.

        Return boolean if scanning successful.
        """
        _LOGGER.debug("Checking D-Link, async_update_info")

        try:
            self.last_results = await self.connection.async_get_connected_devices()
            _LOGGER.debug("Checking D-Link, got %d results", len(self.last_results))
            if self._connect_error:
                self._connect_error = False
                _LOGGER.info("Reconnected to D-Link router for device update")

        except OSError as err:
            if not self._connect_error:
                self._connect_error = True
                _LOGGER.error(
                    "Error connecting to D-Link router for device update: %s", err
                )
