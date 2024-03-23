from contextlib import suppress

from consts import *


def parse_bind_addr(arg: str) -> tuple[str, int]:
	with suppress(ValueError):
		match arg.split(':'):
			case ['']:
				return DEFAULT_BIND_IP, DEFAULT_BIND_PORT
			case ['', port]:
				return '0.0.0.0', int(port)
			case [ip, port]:
				return ip, int(port)
			case [ip]:
				return ip, DEFAULT_BIND_PORT

	raise RuntimeError('Invalid argument(s)')

def parse_front_addr(arg: str) -> tuple[str, int, str | None]:
	with suppress(ValueError):
		match arg.split(':'):
			case ['']:
				return DEFAULT_FRONT_HOST, 443, None
			case [host]:
				return host, 443, None
			case [host, port]:
				return host, int(port), None
			case [host, port, resolve_addr]:
				return host, int(port), resolve_addr

	raise RuntimeError('Invalid argument(s)')