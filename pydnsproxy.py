#!/usr/bin/env python3
import json
import logging
import random
import re
import socket
import ssl
import struct
import urllib.request
from argparse import ArgumentParser
from copy import deepcopy
from datetime import datetime, timedelta
from enum import Enum
from logging import error, info
from socketserver import BaseRequestHandler, DatagramRequestHandler, ThreadingUDPServer
from threading import Thread
from time import sleep
from typing import Any, Callable, Dict, List, Set, \
    Optional, Tuple, Union

##########
# Config #
##########


JsonObject = Dict[str, Any]


class ConfigError(Exception):
    pass


def is_type(to_test: Any, type_: Any) -> None:
    if not isinstance(to_test, type_):
        raise ConfigError(f"Expected {to_test} to be {str(type_)}. Was {str(type(to_test))}.")


def test_is_type():
    # pylint: disable=import-outside-toplevel
    import pytest #type: ignore
    is_type('hello world', str)
    with pytest.raises(ConfigError):
        is_type('hello world', int)


class ConfigBind:
    host_name: str
    port: int

    def to_host_tuple(self) -> Tuple[str, int]:
        return (self.host_name, self.port,)

    @staticmethod
    def validate_json(obj: JsonObject) -> None:
        try:
            is_type(obj['host'], str)
            is_type(obj['port'], int)
        except KeyError as error:
            raise ConfigError(f"Expected {error.args[0]} in bind section.")

    @staticmethod
    def from_json(obj: JsonObject) -> 'ConfigBind':
        ConfigBind.validate_json(obj)
        bind = ConfigBind()
        bind.host_name = obj['host']
        bind.port = obj['port']
        return bind


def test_config_bind():
    # pylint: disable=import-outside-toplevel
    import pytest # type: ignore
    correct = {
        'host': '127.0.0.1',
        'port': 53535
    }
    incorrect = {}

    assert ConfigBind.from_json(correct)

    with pytest.raises(ConfigError):
        ConfigBind.from_json(incorrect)


class ResourceKind(Enum):
    HTTP = 1
    FILE = 2

    @staticmethod
    def from_str(str_: str) -> 'ResourceKind':
        if str_.lower() == 'http':
            return ResourceKind.HTTP

        if str_.lower() == 'file':
            return ResourceKind.FILE

        raise ConfigError(f"Unknown resource kind: {str_}")


def test_resource_kind():
    # pylint: disable=import-outside-toplevel
    import pytest # type: ignore
    assert ResourceKind.from_str('http') == ResourceKind.HTTP
    assert ResourceKind.from_str('file') == ResourceKind.FILE

    with pytest.raises(ConfigError):
        ResourceKind.from_str('does not work')


class BlockListFormat(Enum):
    ONE_PER_LINE = 1
    HOSTS = 2

    @staticmethod
    def from_str(str_: str) -> 'BlockListFormat':
        if str_.lower() == 'one per line':
            return BlockListFormat.ONE_PER_LINE

        if str_.lower() == 'hosts':
            return BlockListFormat.HOSTS

        raise ConfigError(f"Unknown block list format: {str_}")


def test_blocklist_format():
    # pylint: disable=import-outside-toplevel
    import pytest # type: ignore
    assert BlockListFormat.from_str('one per line') == BlockListFormat.ONE_PER_LINE
    assert BlockListFormat.from_str('hosts') == BlockListFormat.HOSTS

    with pytest.raises(ConfigError):
        BlockListFormat.from_str('should not work')


class ConfigBlockList:
    resource_kind: ResourceKind
    location: str
    list_format: BlockListFormat

    @staticmethod
    def validate_json(obj: JsonObject) -> None:
        try:
            is_type(ResourceKind.from_str(obj['kind']), ResourceKind)
            is_type(obj['location'], str)
            is_type(BlockListFormat.from_str(obj['format']), BlockListFormat)
        except KeyError as error:
            raise ConfigError(f"Expected {error.args[0]} in block list. Got {str(obj)}")

    @staticmethod
    def from_json(obj: JsonObject) -> 'ConfigBlockList':
        ConfigBlockList.validate_json(obj)

        blocklist = ConfigBlockList()
        blocklist.resource_kind = ResourceKind.from_str(obj['kind'])
        blocklist.location = obj['location']
        blocklist.list_format = BlockListFormat.from_str(obj['format'])

        return blocklist


def test_block_list():
    # pylint: disable=import-outside-toplevel
    import pytest # type: ignore
    correct = {
        'kind': 'http',
        'location': 'https://127.0.0.1:8000/list.txt',
        'format': 'one per line'
    }
    incorrect = {}

    assert ConfigBlockList.from_json(correct)

    with pytest.raises(ConfigError):
        ConfigBlockList.from_json(incorrect)


class ConfigResolver:
    host: str
    port: int
    tls_hostname: str

    @staticmethod
    def validate_json(obj: JsonObject) -> None:
        try:
            is_type(obj['host'], str)
            is_type(obj['port'], int)
            is_type(obj['tls_hostname'], str)
        except KeyError as err:
            raise ConfigError(f"Expected {err.args[0]} in resolver. Got {str(obj)}")

    @staticmethod
    def from_json(obj: JsonObject) -> 'ConfigResolver':
        ConfigResolver.validate_json(obj)

        resolver = ConfigResolver()
        resolver.host = obj['host']
        resolver.port = obj['port']
        resolver.tls_hostname = obj['tls_hostname']

        return resolver


def test_config_resolver():
    # pylint: disable=import-outside-toplevel
    import pytest # type: ignore
    correct = {
        'host': '8.8.8.8',
        'port': 853,
        'tls_hostname': 'dns.google'
    }
    incorrect = {}

    assert ConfigResolver.from_json(correct)
    with pytest.raises(ConfigError):
        ConfigResolver.from_json(incorrect)


class Config:
    bind: ConfigBind
    block_lists: List[ConfigBlockList]
    upgrade_block_lists_minutes: int
    resolvers: List[ConfigResolver]

    @staticmethod
    def validate_json(obj: JsonObject) -> None:
        try:
            is_type(obj['bind_config'], dict)
            is_type(obj['upgrade_block_lists_minutes'], int)
            is_type(obj['block_lists'], list)
            is_type(obj['resolvers'], list)
        except KeyError as error:
            raise ConfigError(f"Expected {error.args[0]} in config.")

    @staticmethod
    def from_json(obj: JsonObject) -> 'Config':
        # Validate root object
        Config.validate_json(obj)

        # Unpack child sections
        bind = ConfigBind.from_json(obj['bind_config'])
        block_lists = []
        for _list in obj['block_lists']:
            block_lists.append(ConfigBlockList.from_json(_list))

        resolvers = []
        for resolver in obj['resolvers']:
            resolvers.append(ConfigResolver.from_json(resolver))

        # Construct and return config object
        config = Config()
        config.bind = bind
        config.block_lists = block_lists
        config.upgrade_block_lists_minutes = obj['upgrade_block_lists_minutes']
        config.resolvers = resolvers

        return config

    @staticmethod
    def from_json_file(path: str) -> 'Config':
        with open(path, 'r') as _file:
            obj = json.load(_file)
        return Config.from_json(obj)


def test_config():
    correct = {
        'bind_config': {
            'host': '127.0.0.1',
            'port': 53535
        },
        'upgrade_block_lists_minutes': 1,
        'block_lists': [
            {
                'kind': 'http',
                'location': 'http://127.0.0.1:8000/list1.txt',
                'format': 'one per line'
            },
            {
                'kind': 'file',
                'location': '/tmp/list2.txt',
                'format': 'hosts'
            }
        ],
        'resolvers': [
            {
                'host': '8.8.8.8',
                'port': 853,
                'tls_hostname': 'dns.google'
            },
            {
                'host': '1.1.1.1',
                'port': 853,
                'tls_hostname': 'cloudflare-dns.com'
            }
        ]
    }

    config = Config.from_json(correct)
    assert config
    assert len(config.block_lists) == 2

########################################
# Block Lists (including auto-updates) #
########################################

class BlockListError(Exception):
    pass


class BlockList:

    def __init__(self):
        self.blocked_domains: Set[str] = set()
        self.comment_regex: re.Pattern = re.compile(r"((^|\s+)#(.|\s)+)$")
        self.hosts_regex: re.Pattern = re.compile(r"^.+\s+")
        self.whitespace_regex: re.Pattern = re.compile(r"\s+")
        self.upgrade_thread: Optional[Thread] = None

    def _extract_hostname(self, input_line: Union[str, bytes],
                          format_: BlockListFormat) -> Optional[str]:

        # Decode from bytes to string if required
        if isinstance(input_line, bytes):
            line = input_line.decode()
        else:
            line = input_line

        # Firstly, strip comments
        line = self.comment_regex.sub("", line).strip()

        if line == "" or line == '#' or self.whitespace_regex.match(line):
            return None

        # If hosts file format, strip out the leading IP address
        if format_ == BlockListFormat.HOSTS:
            line = self.hosts_regex.sub("", line).strip()

        return line.strip()

    def _upgrade_http(self, url: str, set_: Set[str], format_: BlockListFormat) -> None:
        with urllib.request.urlopen(url) as _http:
            for line in _http:
                hostname = self._extract_hostname(line, format_)
                if hostname:
                    set_.add(hostname)

    def _upgrade_file(self, path: str, set_: Set[str], format_: BlockListFormat) -> None:
        with open(path, 'r') as _file:
            for line in _file:
                hostname = self._extract_hostname(line, format_)
                if hostname:
                    set_.add(hostname)

    def upgrade(self, config: Config) -> None:
        new_block_list: Set[str] = set()

        info("Upgrading block lists...")

        for block_list in config.block_lists:
            try:
                if block_list.resource_kind == ResourceKind.HTTP:
                    self._upgrade_http(block_list.location, new_block_list, block_list.list_format)
                elif block_list.resource_kind == ResourceKind.FILE:
                    self._upgrade_file(block_list.location, new_block_list, block_list.list_format)
                else:
                    raise BlockListError(f"Unknown block list format"
                                         f"{str(block_list.resource_kind)}")

                info(f"Upgraded {block_list.location}")
            except Exception as err: # pylint: disable=broad-except
                error(f"Couldn't update {block_list.location}. Error: {str(err)}")
                continue

        self.blocked_domains = new_block_list

    def start_upgrade_thread(self, config: Config) -> None:
        def upgrader() -> None:
            try:
                info(f"Started block list upgrader thread. Will run every"
                     f" {config.upgrade_block_lists_minutes} minutes.")
                self.upgrade(config)
                next_run = datetime.now() + timedelta(minutes=config.upgrade_block_lists_minutes)
                while True:
                    if datetime.now() > next_run:
                        self.upgrade(config)
                        next_run = datetime.now() + \
                            timedelta(minutes=config.upgrade_block_lists_minutes)
                    else:
                        sleep(5)
            except Exception as err: # pylint: disable=broad-except
                error(f"Unexpected error in upgrader thread: {str(err)}")

        if len(config.block_lists) == 0:
            info("No block lists - not starting block list upgrader thread")
            return

        self.upgrade_thread = Thread(target=upgrader)
        self.upgrade_thread.daemon = True
        self.upgrade_thread.start()

    def is_blocked(self, to_check: str) -> bool:
        for entry in self.blocked_domains:
            if to_check == entry:
                return True
        return False


def test_block_lists():
    block_list = BlockList()
    block_list.blocked_domains.add('test.com')

    assert block_list.is_blocked('test.com') is True
    assert block_list.is_blocked('allowed.com') is False


def test_extract_hostname():
    block_list = BlockList()
    extract = block_list._extract_hostname # pylint: disable=protected-access
    assert extract("127.0.0.1 example.com", BlockListFormat.HOSTS) == "example.com"
    assert extract("example.com", BlockListFormat.ONE_PER_LINE) == "example.com"
    assert extract("# This is a comment", BlockListFormat.HOSTS) is None
    assert extract("127.0.0.1 example.com # comment", BlockListFormat.HOSTS) == "example.com"


def test_upgrade_file():
    # pylint: disable=import-outside-toplevel,protected-access
    from tempfile import NamedTemporaryFile # type: ignore
    with NamedTemporaryFile() as temp:
        temp.write("google.com\nask.com".encode())
        temp.flush()

        lists = BlockList()
        set_: Set[str] = set()
        lists._upgrade_file(temp.name, set_, BlockListFormat.ONE_PER_LINE)

        assert 'google.com' in set_
        assert 'ask.com' in set_
        assert 'example.com' not in set_


def test_upgrade_http():
    # pylint: disable=import-outside-toplevel,protected-access,redefined-outer-name,reimported
    from http.server import HTTPServer, BaseHTTPRequestHandler # type: ignore
    from threading import Thread # type: ignore

    class Server(HTTPServer):
        def handle_error(self, _a, _b):
            pass

    class Handler(BaseHTTPRequestHandler):

        # pylint: disable=invalid-name
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write("google.com\nask.com\n".encode())
            self.wfile.close()

    httpd = Server(('127.0.0.1', 8001), Handler)
    runner = Thread(target=httpd.serve_forever)
    runner.start()

    lists = BlockList()
    set_: Set[str] = set()
    lists._upgrade_http("http://127.0.0.1:8001/", set_, BlockListFormat.ONE_PER_LINE)

    httpd.shutdown()
    runner.join()

    assert 'google.com' in set_
    assert 'ask.com' in set_
    assert 'example.com' not in set_



#######################
# DNS Message Parsing #
#######################

class DNSMessageError(Exception):
    pass


class DNSMessage:
    # pylint: disable=too-few-public-methods

    bytes_: bytes

    def __init__(self, bytes_: bytes):
        self.bytes_ = bytes_

    def questions(self) -> int:
        return struct.unpack("!H", self.bytes_[4:6])[0]

    def to_nxdomain(self) -> bytes:
        bytes_ = bytearray(deepcopy(self.bytes_))
        bytes_[2] = 0x81
        bytes_[3] = 0x83

        return bytes(bytes_)

    def hostname(self):
        try:
            if self.questions() != 1:
                raise DNSMessageError("Will only parse DNS messages that have one question")

            # Jump to first question
            hostname = ""
            offset = 12
            while True:
                # Get the current size. If zero, we've finished
                size = int(self.bytes_[offset]); offset += 1
                if size == 0:
                    break

                this = self.bytes_[offset:(offset + size)]; offset += size
                hostname += this.decode() + "."

            return hostname[:-1]
        except IndexError:
            raise DNSMessageError("Message was too small at {len(self.bytes_)} bytes")


def test_dns_hostname():
    from binascii import unhexlify
    msg_bytes = unhexlify("e47201200001000000000001046d61"
                          "696c06676f6f676c6503636f6d0000"
                          "0100010000291000000000000000")
    msg = DNSMessage(msg_bytes)
    assert msg.hostname() == 'mail.google.com'


def test_dns_questions():
    from binascii import unhexlify
    msg_bytes = unhexlify("e47201200001000000000001046d61"
                          "696c06676f6f676c6503636f6d0000"
                          "0100010000291000000000000000")
    msg = DNSMessage(msg_bytes)
    assert msg.questions() == 1

#######################
# DNS to DNS-over-TLS #
#######################


def proxy_request(req: bytes, upstream: ConfigResolver) -> bytes:
    host = upstream.host
    port = upstream.port
    hostname = upstream.tls_hostname

    ctx = ssl.create_default_context()

    with socket.create_connection((host, port)) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            ssock.write(struct.pack("!H", len(req)))
            ssock.write(req)
            resp_size = struct.unpack("!H", ssock.read(len=2))[0]
            resp = ssock.read(len=resp_size)

            return resp


class ProxyHandler(DatagramRequestHandler):
    def handle(self):
        msg = self.rfile.read()
        server = random.choice(self.server.config.resolvers)

        try:
            dns_msg = DNSMessage(msg)
            hostname = dns_msg.hostname()
            if self.server.block_list.is_blocked(hostname):
                self.wfile.write(dns_msg.to_nxdomain())
                return
        except DNSMessageError:
            pass

        self.wfile.write(proxy_request(msg, server))


class ProxyServer(ThreadingUDPServer):
    config: Config

    def __init__(self, config: Config, block_list: BlockList,
                 handler: Callable[..., BaseRequestHandler]):
        self.config = config
        self.block_list = block_list
        super().__init__(config.bind.to_host_tuple(), handler)

################
# Entry Points #
################

def parse_args() -> Config:
    parser = ArgumentParser()
    parser.add_argument("-c", "--config", required=True,
                        help="Path to a configuration file")
    args = parser.parse_args()

    return Config.from_json_file(args.config)


def main() -> None:
    logging.getLogger().setLevel(logging.INFO)

    config = parse_args()
    block_list = BlockList()
    block_list.start_upgrade_thread(config)

    try:
        server = ProxyServer(config, block_list, ProxyHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        info("Done!")


if __name__ == '__main__':
    main()
