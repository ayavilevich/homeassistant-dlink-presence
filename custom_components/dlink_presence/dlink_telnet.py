# this is based on https://github.com/kennedyshead/aioasuswrt
import asyncio
import logging
from asyncio import LimitOverrunError, TimeoutError, IncompleteReadError
#import sys
import inspect
from collections import namedtuple
from datetime import datetime
import re
from math import floor

_LOGGER = logging.getLogger(__name__)

# https://github.com/kennedyshead/aioasuswrt/blob/2820deaa3fc0ea78e2f73a2832f01db5dd2b6885/aioasuswrt/connection.py#L81
# note, when updating, dlink prompt is "$", not "#" as with asus.
# note, on dlink we didn't need the logic using "_PATH_EXPORT_COMMAND" from aioasuswrt
# possibly improve the logic so it times-out when waiting on the server. Reference https://stackoverflow.com/questions/29756507/how-can-i-add-a-connection-timeout-with-asyncio
class TelnetConnection:
    """Maintains a Telnet connection to a device with a shell."""

    def __init__(self, host, port, username, password):
        """Initialize the Telnet connection properties."""
        self._reader = None
        self._writer = None
        self._host = host
        self._port = port or 23
        self._username = username
        self._password = password
        self._prompt_string = None
        self._io_lock = asyncio.Lock()
        self._linebreak = None

    async def async_run_command(self, command, first_try=True):
        """Run a command through a Telnet connection. If first_try is True a second
        attempt will be done if the first try fails."""

        #_LOGGER.debug("TelnetConnection.async_run_command")

        need_retry = False

        async with self._io_lock:
            try:
                if not self.is_connected:
                    await self._async_connect()
                # Let's add the path and send the command
                #full_cmd = f"{_PATH_EXPORT_COMMAND} && {command}"
                full_cmd = command
                self._writer.write((full_cmd + "\n").encode("ascii"))
                # And read back the data till the prompt string
                data = await asyncio.wait_for(
                    self._reader.readuntil(self._prompt_string), 9
                )
            except (BrokenPipeError, LimitOverrunError, IncompleteReadError):
                # Writing has failed, Let's close and retry if necessary
                self.disconnect()
                if first_try:
                    need_retry = True
                else:
                    _LOGGER.warning("connection is lost to host.")
                    return []
            except TimeoutError:
                _LOGGER.error("Host timeout.")
                self.disconnect()
                if first_try:
                    need_retry = True
                else:
                    return []
            except ConnectionError as e:
                _LOGGER.error("ConnectionError.")
                _LOGGER.error(e)
                self.disconnect()
                return []

        if need_retry:
            _LOGGER.debug("Trying one more time")
            return await self.async_run_command(command, False)

        # Let's process the received data
        data = data.split(b"\n")
        # Let's find the number of elements the cmd takes
        cmd_len = len(self._prompt_string) + len(full_cmd)
        # We have to do floor + 1 to handle the infinite case correct
        start_split = floor(cmd_len / self._linebreak) + 1
        data = data[start_split:-1]
        return [line.decode("utf-8", "ignore") for line in data]

    async def async_connect(self):
        """Connect to the ASUS-WRT Telnet server."""
        async with self._io_lock:
            await self._async_connect()

    async def _async_connect(self):
        #_LOGGER.debug("TelnetConnection._async_connect")
        self._reader, self._writer = await asyncio.open_connection(
            self._host, self._port
        )
        #_LOGGER.debug("TelnetConnection._async_connect after connect")

        # Process the login
        # Enter the Username
        try:
            await asyncio.wait_for(self._reader.readuntil(b"login: "), 9)
        except asyncio.IncompleteReadError:
            _LOGGER.error(
                "Unable to read from router on %s:%s" % (self._host, self._port)
            )
            return
        except TimeoutError:
            _LOGGER.error("Host timeout.")
            self.disconnect()
        self._writer.write((self._username + "\n").encode("ascii"))
        #_LOGGER.debug("TelnetConnection._async_connect after username")

        # Enter the password
        await self._reader.readuntil(b"Password: ")
        self._writer.write((self._password + "\n").encode("ascii"))
        #_LOGGER.debug("TelnetConnection._async_connect after password")

        # Now we can determine the prompt string for the commands.
        self._prompt_string = (await self._reader.readuntil(b"$")).split(b"\n")[-1]

        # Let's determine if any linebreaks are added
        # Write some arbitrary long string.
        if self._linebreak is None:
            self._writer.write((" " * 200 + "\n").encode("ascii"))
            self._determine_linebreak(
                await self._reader.readuntil(self._prompt_string)
            )
        #_LOGGER.debug("TelnetConnection._async_connect after prompt")

    def _determine_linebreak(self, input_bytes: bytes):
        """Telnet or asyncio seems to be adding linebreaks due to terminal size,
        try to determine here what the column number is."""
        # Let's convert the data to the expected format
        data = input_bytes.decode("utf-8").replace("\r", "").split("\n")
        if len(data) == 1:
            # There was no split, so assume infinite
            self._linebreak = float("inf")
        else:
            # The linebreak is the length of the prompt string + the first line
            self._linebreak = len(self._prompt_string) + len(data[0])

            if len(data) > 2:
                # We can do a quick sanity check, as there are more linebreaks
                if len(data[1]) != self._linebreak:
                    _LOGGER.warning(
                        f"Inconsistent linebreaks {len(data[1])} != "
                        f"{self._linebreak}"
                    )

    @property
    def is_connected(self):
        """Do we have a connection."""
        return self._reader is not None and self._writer is not None and not self._writer.is_closing()

    def disconnect(self):
        """Disconnects the client"""
        self._writer = None
        self._reader = None

Device = namedtuple('Device', ['mac', 'ip', 'name'])

async def _parse_lines(lines, regex):
    """Parse the lines using the given regular expression.
    If a line can't be parsed it is logged and skipped in the output.
    """
    results = []
    if inspect.iscoroutinefunction(lines):
        lines = await lines
    for line in lines:
        if line:
            match = regex.search(line)
            if not match:
                _LOGGER.debug("Could not parse row: '%s' %d", line, len(line))
                continue
            results.append(match.groupdict())
    return results

CHANGE_TIME_CACHE_DEFAULT = 5  # Default 5s
_IWLIST_CMD = 'iwlist {} ap'
_IWLIST_REGEX = re.compile(
    r'(?P<mac>(([0-9A-F]{2}[:-]){5}([0-9A-F]{2})))' +
    r' : Quality[=:]')

class DLinkTelnet:
    """This is the interface class."""

    def __init__(self, host, port=None, username=None, password=None, require_ip=False,
                 time_cache=CHANGE_TIME_CACHE_DEFAULT):
        """Init function."""
        self.require_ip = require_ip
        self._cache_time = time_cache
        self._trans_cache_timer = None
        self._dev_cache_timer = None
        self._devices_cache = None

        self.connection = TelnetConnection(
            host, port, username, password)

    async def async_get_iwlist(self, interface):
        lines = await self.connection.async_run_command(_IWLIST_CMD.format(interface))
        if not lines:
            return {}
        lines = [line for line in lines if not line.startswith(interface) and not line == '\r']
        result = await _parse_lines(lines, _IWLIST_REGEX)
        devices = {}
        for device in result:
            mac = device['mac'].upper()
            devices[mac] = Device(mac, None, None)
        return devices

    # async def async_get_nvram(self, toGet):
    #     data = {}
    #     if toGet in GET_LIST:
    #         lines = await self.connection.async_run_command('nvram show')
    #         for item in GET_LIST[toGet]:
    #             regex = rf"{item}=([\w.\-/: ]+)"
    #             for line in lines:
    #                 result = re.findall(regex, line)
    #                 if result:
    #                     data[item] = result[0]
    #                     break
    #     return data

    # async def async_get_wl(self):
    #     lines = await self.connection.async_run_command(_WL_CMD)
    #     if not lines:
    #         return {}
    #     result = await _parse_lines(lines, _WL_REGEX)
    #     devices = {}
    #     for device in result:
    #         mac = device['mac'].upper()
    #         devices[mac] = Device(mac, None, None)
    #     return devices

    # async def async_get_leases(self, cur_devices):
    #     lines = await self.connection.async_run_command(
    #         _LEASES_CMD.format(self.dnsmasq))
    #     if not lines:
    #         return {}
    #     lines = [line for line in lines if not line.startswith('duid ')]
    #     result = await _parse_lines(lines, _LEASES_REGEX)
    #     devices = {}
    #     for device in result:
    #         # For leases where the client doesn't set a hostname, ensure it
    #         # is blank and not '*', which breaks entity_id down the line.
    #         host = device['host']
    #         if host == '*':
    #             host = ''
    #         mac = device['mac'].upper()
    #         if mac in cur_devices:
    #             devices[mac] = Device(mac, device['ip'], host)
    #     return devices

    # async def async_get_neigh(self, cur_devices):
    #     lines = await self.connection.async_run_command(_IP_NEIGH_CMD)
    #     if not lines:
    #         return {}
    #     result = await _parse_lines(lines, _IP_NEIGH_REGEX)
    #     devices = {}
    #     for device in result:
    #         status = device['status']
    #         if status is None or status.upper() != 'REACHABLE':
    #             continue
    #         if device['mac'] is not None:
    #             mac = device['mac'].upper()
    #             old_device = cur_devices.get(mac)
    #             old_ip = old_device.ip if old_device else None
    #             devices[mac] = Device(mac, device.get('ip', old_ip), None)
    #     return devices

    # async def async_get_arp(self):
    #     lines = await self.connection.async_run_command(_ARP_CMD)
    #     if not lines:
    #         return {}
    #     result = await _parse_lines(lines, _ARP_REGEX)
    #     devices = {}
    #     for device in result:
    #         if device['mac'] is not None:
    #             mac = device['mac'].upper()
    #             devices[mac] = Device(mac, device['ip'], None)
    #     return devices

    async def async_get_connected_devices(self, use_cache=True):
        """Retrieve data from ASUSWRT.
        Calls various commands on the router and returns the superset of all
        responses. Some commands will not work on some routers.
        """
        now = datetime.utcnow()
        if use_cache and self._dev_cache_timer and self._cache_time > \
                (now - self._dev_cache_timer).total_seconds():
            return self._devices_cache

        devices = {}
        dev = await self.async_get_iwlist('wlan0')
        devices.update(dev)
        dev = await self.async_get_iwlist('wlan1')
        devices.update(dev)
        #dev = await self.async_get_wl()
        #devices.update(dev)
        #dev = await self.async_get_arp()
        #devices.update(dev)
        #dev = await self.async_get_neigh(devices)
        #devices.update(dev)
        #if not self.mode == 'ap':
        #    dev = await self.async_get_leases(devices)
        #    devices.update(dev)

        ret_devices = {}
        for key in devices:
            if not self.require_ip or devices[key].ip is not None:
                ret_devices[key] = devices[key]

        self._devices_cache = ret_devices
        self._dev_cache_timer = now
        return ret_devices

    @property
    def is_connected(self):
        return self.connection.is_connected
