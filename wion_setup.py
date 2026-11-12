#!/usr/bin/env python3
"""Find, provision, and rename legacy WiOn/ECO timers over local UDP."""

import argparse
import datetime
import getpass
import ipaddress
import math
import secrets
import socket
import struct
import sys
import time
import warnings
from dataclasses import dataclass
from pathlib import Path

DISCOVERY_PORTS = (25, 5888)
SETUP_HOSTS = ("192.168.4.1", "192.168.5.1")
GET_SETTINGS = 0x50005
SCAN_WIFI = 0x50012
SET_WIFI = 0x50004
SET_NAME = 0x50013
SET_TIME_ZONE = 0x50015
SET_SOLAR_TABLE = 0x50018
SET_NIGHT_LIGHT = 0x5001B
GET_SETUP_STATUS = 0x50105
HEADER_SIZE = 128
SETTINGS_SIZE = 364


class SetupError(Exception):
    pass


def field(data):
    return data.split(b"\0", 1)[0]


def discovery_packet():
    now = datetime.datetime.now()
    packet = bytearray(128)
    seconds = now.hour * 3600 + now.minute * 60 + now.second
    struct.pack_into("<HBBIi", packet, 24, now.year, now.month, now.day, seconds, 0)
    return packet


@dataclass(frozen=True)
class Timer:
    host: str
    port: int
    identity: bytes
    advertised_ssid: str

    @property
    def device_id(self):
        return field(self.identity[6:38]).decode("ascii")

    @property
    def version(self):
        return field(self.identity[:6]).decode("utf-8", errors="replace")


def parse_discovery(packet, sender):
    if len(packet) != 408:
        return None
    device_id = field(packet[10:42])
    port, = struct.unpack_from("<I", packet, 404)
    if not device_id.startswith(b"ECO-") or not device_id[4:].isalnum():
        return None
    if not 1 <= port <= 65535:
        return None
    ssid = field(packet[120:184]).decode("utf-8", errors="replace")
    return Timer(sender, port, packet[4:106], ssid)


def receive(sock, deadline):
    while (remaining := deadline - time.monotonic()) > 0:
        sock.settimeout(remaining)
        try:
            return sock.recvfrom(2048)
        except ConnectionResetError:
            # Windows can report an ICMP error for one of the discovery ports.
            continue
        except socket.timeout:
            return None
    return None


def discover(target, local_ip, broadcast=False):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        if broadcast:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((local_ip, 8900))
        request = discovery_packet()
        for port in DISCOVERY_PORTS:
            sock.sendto(request, (target, port))
        deadline = time.monotonic() + 1.5
        timers = {}
        while (reply := receive(sock, deadline)) is not None:
            data, (sender, _) = reply
            if not broadcast and sender != target:
                continue
            timer = parse_discovery(data, sender)
            if timer:
                timers[(timer.device_id, timer.host)] = timer
                if not broadcast:
                    break
        return list(timers.values())


def command(sock, timer, client_id, code, payload=b"", timeout=3, *,
            copies=1, attempts=1, identity=None):
    sequence = secrets.randbelow(32727) + 1
    header = bytearray(HEADER_SIZE)
    struct.pack_into("<IHHH", header, 0, code, 0, sequence, len(payload))
    header[10:112] = timer.identity if identity is None else identity
    struct.pack_into("<I", header, 116, int(time.time() * 1000) & 0xFFFFFFFF)
    struct.pack_into("<I", header, 124, client_id)
    peer = (timer.host, timer.port)
    message = header + payload
    for _ in range(attempts):
        for _ in range(copies):
            sock.sendto(message, peer)
        deadline = time.monotonic() + timeout
        while (reply := receive(sock, deadline)) is not None:
            data, sender = reply
            if sender != peer or len(data) < HEADER_SIZE:
                continue
            reply_code, result, reply_sequence, length = struct.unpack_from("<IHHH", data)
            if reply_code == code and reply_sequence == sequence and len(data) == HEADER_SIZE + length:
                return result, data[HEADER_SIZE:]
    return None


def require_reply(reply, operation, length):
    if reply is None:
        raise SetupError(f"The timer did not reply to {operation}.")
    status, payload = reply
    if status != 0:
        raise SetupError(f"The timer refused {operation} (firmware code {status}).")
    if len(payload) != length:
        raise SetupError(f"The timer returned an unexpected {operation} reply.")
    return payload


def get_settings(sock, timer, client_id):
    reply = None
    for _ in range(3):
        reply = command(sock, timer, client_id, GET_SETTINGS, timeout=1.5)
        if reply is not None:
            break
    record = require_reply(reply, "settings read", SETTINGS_SIZE)
    if record[6:38] != timer.identity[6:38]:
        raise SetupError("The settings reply identifies a different timer.")
    return record


def validate_text(value, max_bytes, label):
    encoded = value.encode("utf-8")
    if not 1 <= len(encoded) <= max_bytes or b"\0" in encoded:
        raise SetupError(f"{label} must be 1 to {max_bytes} UTF-8 bytes without NUL characters.")
    return encoded


def read_password(open_network):
    if open_network:
        return b""
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            password = getpass.getpass("Wi-Fi password: ")
        except (getpass.GetPassWarning, EOFError) as error:
            raise SetupError("Run this command in an interactive terminal for hidden password entry.") from error
    if 8 <= len(password) <= 63 and all(32 <= ord(char) <= 126 for char in password):
        return password.encode("ascii")
    if len(password) == 64 and all(char in "0123456789abcdefABCDEF" for char in password):
        return password.encode("ascii")
    raise SetupError("Enter an 8–63 character ASCII passphrase or a 64-digit hex key. Use --open-network for open Wi-Fi.")


def wifi_record(record, ssid, password):
    updated = bytearray(record)
    updated[116:180] = ssid.ljust(64, b"\0")
    updated[180:244] = password.ljust(64, b"\0")
    return updated


def name_payload(record, name):
    payload = bytearray(102)
    payload[38:70] = name.ljust(32, b"\0")
    payload[70:102] = record[70:102]
    return payload


def parse_offset(value):
    sign, text = value[:1], value[1:]
    parts = text.split(":")
    if sign not in ("+", "-") or len(parts) != 2 or any(len(p) != 2 or not p.isascii() or not p.isdigit() for p in parts):
        raise argparse.ArgumentTypeError("Use a signed UTC offset, such as --offset=-05:00.")
    hours, minutes = map(int, parts)
    total = (hours * 60 + minutes) * (-1 if sign == "-" else 1)
    if minutes > 59 or not -720 <= total <= 840:
        raise argparse.ArgumentTypeError("Choose an offset from -12:00 through +14:00.")
    return total * 60


def read_zone(record):
    year, = struct.unpack_from("<H", record, 104)
    offset, = struct.unpack_from("<i", record, 112)
    return offset + 8 * 3600, bool(year & 0x1000)


def format_zone(offset, dst):
    hours, remainder = divmod(abs(offset), 3600)
    sign = "+" if offset >= 0 else "-"
    return f"UTC{sign}{hours:02}:{remainder // 60:02}, DST {'on' if dst else 'off'}"


def clock_payload(offset, dst):
    # The vendor writes local standard time and a signed offset relative to UTC+08:00.
    local = datetime.datetime.now(datetime.timezone(datetime.timedelta(seconds=offset)))
    seconds = local.hour * 3600 + local.minute * 60 + local.second
    year = local.year | (0x1000 if dst else 0)
    return struct.pack("<HBBIi", year, local.month, local.day, seconds, offset - 8 * 3600)


def solar_table(zip_code, offset):
    coordinates = None
    if zip_code is not None:
        with Path(__file__).with_name("zip-coordinates.csv").open(encoding="ascii") as source:
            for row in source:
                code, latitude, longitude = row.split(",")
                if code == zip_code:
                    coordinates = math.radians(float(latitude)), float(longitude)
                    break
        if coordinates is None:
            raise SetupError(f"No coordinates were found for ZIP {zip_code}.")

    table = bytearray()
    for day in range(366):
        sunrise, sunset = 360, 1080
        if coordinates is not None:
            # NOAA fractional-year approximation, in local standard time.
            latitude, longitude = coordinates
            angle = math.tau * day / 366
            cos, sin = math.cos, math.sin
            equation_of_time = 229.18 * (
                0.000075 + 0.001868 * cos(angle) - 0.032077 * sin(angle)
                - 0.014615 * cos(2 * angle) - 0.040849 * sin(2 * angle)
            )
            declination = (
                0.006918 - 0.399912 * cos(angle) + 0.070257 * sin(angle)
                - 0.006758 * cos(2 * angle) + 0.000907 * sin(2 * angle)
                - 0.002697 * cos(3 * angle) + 0.00148 * sin(3 * angle)
            )
            cosine = (cos(math.radians(90.833)) - sin(latitude) * sin(declination)) / (
                cos(latitude) * cos(declination)
            )
            if not -1 <= cosine <= 1:
                raise SetupError("This ZIP has days without sunrise or sunset. The timer’s table needs both.")
            noon = 720 - 4 * longitude - equation_of_time + offset / 60
            minutes_to_horizon = math.degrees(math.acos(cosine)) * 4
            sunrise = math.floor(noon - minutes_to_horizon) % 1440
            sunset = math.floor(noon + minutes_to_horizon) % 1440
        table.extend(((sunrise << 12) | sunset).to_bytes(3, "little"))
    return table


def local_setup_ip(host, requested_ip):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        if requested_ip != "0.0.0.0":
            sock.bind((requested_ip, 0))
        sock.connect((host, 25))
        address = ipaddress.IPv4Address(sock.getsockname()[0])
    if address not in ipaddress.IPv4Network(f"{host}/24", strict=False) or str(address) == host:
        raise SetupError("Join the timer’s ECO setup Wi-Fi first. Use --local-ip if multiple networks overlap.")
    return str(address)


def run(args):
    if args.action == "discover":
        timers = discover(args.broadcast, args.local_ip, broadcast=True)
        if not timers:
            raise SetupError("No legacy ECO timers replied. Check the local network, firewall, and broadcast address.")
        for timer in sorted(timers, key=lambda item: (item.device_id, item.host)):
            print(f"{timer.device_id}  {timer.host}:{timer.port}  firmware {timer.version}")
        return 0

    address = local_setup_ip(args.host, args.local_ip) if args.action == "wifi" else args.local_ip
    timers = discover(args.host, address)
    if not timers:
        raise SetupError(f"No legacy ECO timer replied at {args.host}.")
    timer = timers[0]
    if args.device_id and args.device_id != timer.device_id:
        raise SetupError(f"Expected {args.device_id}, but {timer.device_id} replied.")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((address, 0))
        client_id = secrets.randbelow(2**31 - 1) + 1
        record = get_settings(sock, timer, client_id)
        if args.action == "info":
            name = field(record[38:70]).decode("utf-8", errors="replace")
            ssid = field(record[116:180]).decode("utf-8", errors="replace")
            print(f"{timer.device_id} at {timer.host}, firmware {timer.version}\nName: {name}\nDiscovery SSID: {timer.advertised_ssid}\nSettings-record SSID: {ssid}")
            print(f"Time zone: {format_zone(*read_zone(record))}")
            return 0
        if args.action == "timezone":
            offset, dst = read_zone(record)
            offset = args.offset
            if args.dst is not None:
                dst = args.dst == "on"
            reply = command(sock, timer, client_id, SET_TIME_ZONE, clock_payload(offset, dst))
            require_reply(reply, "time-zone update", 0)
            actual = read_zone(get_settings(sock, timer, client_id))
            if actual != (offset, dst):
                raise SetupError(f"The timer reports {format_zone(*actual)} after the update.")
            print(f"Verified {format_zone(*actual)} on {timer.device_id}.")
            return 0
        if args.action == "name":
            name = validate_text(args.name.strip(), 30, "Timer name")
            reply = command(sock, timer, client_id, SET_NAME, name_payload(record, name))
            if reply is not None and reply[0] != 0:
                require_reply(reply, "rename", 0)
            for attempt in range(3):
                if attempt:
                    time.sleep(0.4)
                if field(get_settings(sock, timer, client_id)[38:70]) == name:
                    print(f"Verified the saved name on {timer.device_id}.")
                    return 0
            raise SetupError("The timer still reports its previous name.")

        ssid = validate_text(args.ssid, 32, "SSID")
        print(f"Configuring {timer.device_id} at {timer.host}.")
        password = read_password(args.open_network)
        require_reply(command(sock, timer, client_id, SCAN_WIFI, timeout=8), "Wi-Fi scan", 976)
        updated = wifi_record(record, ssid, password)
        if args.name is not None:
            name = validate_text(args.name.strip(), 30, "Timer name")
            updated[38:70] = name.ljust(32, b"\0")
        if args.zip is not None:
            updated[246:256] = b"001".ljust(10, b"\0")
            updated[256:266] = str(int(args.zip)).encode("ascii").ljust(10, b"\0")
        if args.offset is not None:
            _, dst = read_zone(record)
            updated[104:116] = clock_payload(args.offset, dst if args.dst is None else args.dst == "on")
        table = solar_table(args.zip, read_zone(updated)[0])
        setup_steps = (
            (SET_NIGHT_LIGHT, b"\x01\x00", "night-light setting"),
            (SET_SOLAR_TABLE, table, "sunrise/sunset table"),
        )

        def send_setup(attempts=1):
            for code, payload, operation in setup_steps:
                reply = command(sock, timer, client_id, code, payload, timeout=0.15, copies=2)
                if reply is not None and reply[0] != 0:
                    print(f"The timer refused the {operation} (firmware code {reply[0]}).", file=sys.stderr)
            return command(sock, timer, client_id, SET_WIFI, updated, timeout=2,
                           copies=2, attempts=attempts, identity=updated[:102])

        reply = send_setup(attempts=2)
        start = time.monotonic() - 3
        for index in range(1, 5):
            time.sleep(max(0, start + index * 3 - time.monotonic()))
            try:
                status = command(sock, timer, client_id, GET_SETUP_STATUS, timeout=1,
                                 copies=2, identity=updated[:102])
            except OSError:
                continue
            if status is not None and status[0] == 0:
                print("The timer reported setup complete. Sending the setup sequence again, as Android does.")
                try:
                    send_setup()
                except OSError:
                    print("The timer disconnected during the second setup write.", file=sys.stderr)
                break
        else:
            if reply is not None and reply[0] == 3:
                print("The timer refused the first Wi-Fi settings write (code 3).", file=sys.stderr)
            print("The timer did not report setup complete on its ECO network.")
        print("Allow time for it to join, then reconnect to your home Wi-Fi and run discover and info.")
        return 0


def ipv4(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as error:
        raise argparse.ArgumentTypeError("Enter an IPv4 address.") from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    search = actions.add_parser("discover", help="List legacy timers on the local network")
    search.add_argument("--broadcast", type=ipv4, default="255.255.255.255")
    wifi = actions.add_parser("wifi", help="Send Wi-Fi settings over the timer’s setup network")
    wifi.add_argument("ssid")
    wifi.add_argument("--host", choices=SETUP_HOSTS, default=SETUP_HOSTS[0])
    wifi.add_argument("--open-network", action="store_true")
    wifi.add_argument("--name", help="Optional display name to save during onboarding")
    wifi.add_argument("--zip", help="Optional five-digit US ZIP code to save during onboarding")
    wifi.add_argument("--offset", type=parse_offset, help="Optional standard UTC offset, e.g. --offset=-05:00")
    wifi.add_argument("--dst", choices=("on", "off"), help="Daylight saving time, used with --offset")
    info = actions.add_parser("info", help="Read a timer’s saved SSID and name")
    info.add_argument("host", type=ipv4)
    name = actions.add_parser("name", help="Set and verify a timer’s display name")
    name.add_argument("host", type=ipv4)
    name.add_argument("name")
    zone = actions.add_parser("timezone", help="Set the standard UTC offset and optional daylight saving flag")
    zone.add_argument("host", type=ipv4)
    zone.add_argument("--offset", type=parse_offset, required=True, help="Standard UTC offset, e.g. --offset=-05:00")
    zone.add_argument("--dst", choices=("on", "off"), help="Preserve the current flag if omitted")
    for action in (search, wifi, info, name, zone):
        action.add_argument("--local-ip", type=ipv4, default="0.0.0.0", help="Bind to this local IPv4 address")
    for action in (wifi, info, name, zone):
        action.add_argument("--device-id", help="Require this ECO device ID before proceeding")
    try:
        args = parser.parse_args()
        if args.action == "wifi":
            if args.dst is not None and args.offset is None:
                wifi.error("--dst requires --offset")
            if args.zip is not None and (
                len(args.zip) != 5 or not args.zip.isascii() or not args.zip.isdigit() or args.zip == "00000"
            ):
                wifi.error("--zip requires a five-digit US ZIP code")
        return run(args)
    except (OSError, SetupError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
