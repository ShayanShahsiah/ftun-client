#!/usr/bin/env python3
import logging
import pathlib
import signal
import socket
import ssl
import sys
import threading
import random
from contextlib import suppress
from functools import cache
from select import select
from uuid import uuid4

import dns.exception
import dns.resolver
import h2.connection
import h2.events
import h2.exceptions
import h2.windows
from consts import *
from http_utils import get_ssl_ctx, req_headers_get, req_headers_post


@cache
def auth() -> str:
    with open(pathlib.Path(__file__).parent / 'auth.txt') as f:
        return f.readline().strip()

class ClientThread(threading.Thread):
	def __init__(self, s, downstream_sock: socket.socket, upstream_addr, server_name: str):
		super().__init__()
		self.s = s
		self.downstream_sock = downstream_sock

		if upstream_addr:
			self.upstream_addr = upstream_addr
			self.server_name = server_name
		else:
			front = random.choice(fronts)
			logging.debug(f'Using {front}')
			self.upstream_addr = (front, 443)
			self.server_name = front

		self.downstream_sock.setblocking(False)

		self.downstream_buf = bytearray()
		self.upstream_buf = bytearray()

		self.upstream_eof = False
		self.downstream_eof = False

		self.conn = h2.connection.H2Connection()
		self.sid = str(uuid4())

	def max_out(self, stream_id, _max) -> int:
		return min(self.conn.local_flow_control_window(stream_id), self.conn.max_outbound_frame_size, _max)
		
	def run(self):
		# import pydevd
		# pydevd.settrace(suspend=False)
		logging.debug('ClientThread started')
		
		plain_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.upstream_sock = get_ssl_ctx().wrap_socket(plain_sock, server_hostname=self.server_name)
		interrupted = False
		try:
			self.upstream_sock.settimeout(CONN_TIMEOUT)
			self.upstream_sock.connect(self.upstream_addr)

			self.upstream_sock.settimeout(INIT_TIMEOUT)
			self.conn.initiate_connection()
			self.upstream_sock.sendall(self.conn.data_to_send())

			self.conn.send_headers(0x01, req_headers_get(self.sid, auth()), end_stream=True)
			self.conn.send_headers(0x03, req_headers_post(self.sid, auth()), end_stream=False)
			self.conn.send_data(0x03, b'.')
			self.upstream_sock.sendall(self.conn.data_to_send())

			self.upstream_sock.settimeout(0)  # set as non-blocking
			interrupted = self.relay()
		except (OSError, TimeoutError, h2.exceptions.H2Error) as e:
			if SHORTEN_ERRS:
				logging.warning(e)
			else:
				logging.warning(e, exc_info=True)
		finally:
			self.upstream_sock.close()
			self.downstream_sock.close()
			if interrupted:
				logging.info('Interrupt: ClientThread terminating')
			else:
				logging.debug('ClientThread terminating')

	def relay(self) -> bool:
		while not self.upstream_eof or not self.downstream_eof:
			ins, outs = [self.s], []

			if not self.downstream_eof and len(self.upstream_buf) < BUF_LEN:
				ins.append(self.downstream_sock)

			if not self.upstream_eof and len(self.downstream_buf) < BUF_LEN and len(self.upstream_buf) < BUF_LEN:
				ins.append(self.upstream_sock)

			if self.downstream_buf:
				outs.append(self.downstream_sock)
			
			if self.upstream_buf:
				outs.append(self.upstream_sock)

			if (pending := [s for s in ins if isinstance(s, ssl.SSLSocket) and s.pending()]):
				rdy_ins, rdy_outs = pending, []
			else:
				rdy_ins, rdy_outs, _ = select(ins, outs, [], SEL_TIMEOUT)  # TODO: ValueError: filedescriptor out of range in select()

			if self.s in rdy_ins:
				return True
				
			if self.downstream_sock in rdy_ins:
				self.on_downstream_recv()

			if self.upstream_sock in rdy_ins:
				self.on_upstream_recv()
				
			if self.downstream_sock in rdy_outs:
				self.on_downstream_send()

			if self.upstream_sock in rdy_outs:
				self.on_upstream_send()

		return False
	
	def on_downstream_recv(self):
		data = self.downstream_sock.recv(self.max_out(0x03, RECV_BUF))
		if data:
			self.conn.send_data(0x03, data)
		else:
			self.downstream_eof = True
			logging.debug('Downstream at EOF')
			self.conn.end_stream(0x03)
		self.upstream_buf += self.conn.data_to_send()

	def on_upstream_recv(self):
		try:
			data = self.upstream_sock.recv(RECV_BUF)
		except ssl.SSLWantReadError:
			return

		if data:
			for event in self.conn.receive_data(data):
				self.on_upstream_event(event)
		else:
			raise ConnectionError('HTTP2 unexpected EOF')

	@staticmethod
	def maximize_flow_control_window(conn: h2.connection.H2Connection):
		with suppress(h2.exceptions.StreamClosedError):
			inc = h2.windows.LARGEST_FLOW_CONTROL_WINDOW - conn.remote_flow_control_window(0x01)
			if inc > 0:
				conn.increment_flow_control_window(inc, 0x01)
				conn.increment_flow_control_window(inc)

	def on_upstream_event(self, event):
		match event:
			case h2.events.DataReceived(stream_id=0x01):
				self.downstream_buf += event.data
				# self.conn.acknowledge_received_data(event.flow_controlled_length, 0x01)
				self.maximize_flow_control_window(self.conn)
				self.upstream_buf += self.conn.data_to_send()

			case h2.events.StreamEnded(stream_id=0x01):
				self.upstream_eof = True
				logging.debug('Upstream at EOF')
				if not self.downstream_buf:
					with suppress(OSError):
						self.downstream_sock.shutdown(socket.SHUT_WR)

	def on_downstream_send(self):
		n_bytes = self.downstream_sock.send(self.downstream_buf)
		self.downstream_buf = self.downstream_buf[n_bytes:]
		if not self.downstream_buf and self.upstream_eof:
			with suppress(OSError):
				self.downstream_sock.shutdown(socket.SHUT_WR)
	
	def on_upstream_send(self):
		try:
			n_bytes = self.upstream_sock.send(self.upstream_buf)
		except ssl.SSLWantWriteError:
			return

		self.upstream_buf = self.upstream_buf[n_bytes:]


class SigtermInterrupt(BaseException):
	pass

win32_end_program = False
def win32_wait_for_eof():
	global win32_end_program
	sys.stdin.read()
	win32_end_program = True

def client_loop(bind_addr, upstream_addr=None, server_name=None):
	serve_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serve_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	serve_sock.bind(bind_addr)
	serve_sock.listen(8)
	logging.info(f'Serving on {bind_addr}')

	if sys.platform == 'win32':
		serve_sock.settimeout(1)
		threading.Thread(target=win32_wait_for_eof).start()

	signal.signal(signal.SIGTERM, lambda *_: exec('raise SigtermInterrupt'))

	s1, s2 = socket.socketpair()
	try:
		while True:
			try:
				downstream_sock, _ = serve_sock.accept()
			except TimeoutError:
				assert sys.platform == 'win32'
				if win32_end_program:
					raise KeyboardInterrupt
			else:
				if not upstream_addr:
					with open('fronts.txt') as f:
						global fronts
						fronts = [line.strip() for line in f.readlines()]
				ClientThread(s2, downstream_sock, upstream_addr, server_name).start()
	except (KeyboardInterrupt, SigtermInterrupt) as e:
		logging.info('Interrupt, exiting...')
		serve_sock.close()
		s1.close()  # send EOF to s2
		for th in threading.enumerate():
			with suppress(RuntimeError):
				th.join()
		s2.close()
		logging.info('Closed all')

		if isinstance(e, KeyboardInterrupt):
			return 130
		elif isinstance(e, SigtermInterrupt):
			return 143
		else:
			raise AssertionError

if __name__ == '__main__':
	import argparse

	from parse_utils import parse_bind_addr, parse_front_addr

	class HelpFormatter(argparse.HelpFormatter):
		def _format_action_invocation(self, action: argparse.Action) -> str:
			formatted = super()._format_action_invocation(action)
			if action.option_strings and action.nargs != 0:
				formatted = formatted.replace(
					f" {self._format_args(action, self._get_default_metavar_for_optional(action))}",
					"",
					len(action.option_strings) - 1,
				)

			return formatted

	parser = argparse.ArgumentParser(formatter_class=HelpFormatter)
	parser.add_argument('-b', '--bind', metavar='<IP>[:PORT]', default='',
					help='bind to IP (=127.0.0.1) and PORT (=9080)')
	parser.add_argument('-f', '--front', metavar='<HOST>[:PORT][:RESOLVE_IP]', default='',
					help='use HOST as the front domain using PORT (=443), resolve domain to RESOLVE_IP')
	parser.add_argument('-info', action='store_true', help='set debugging level to INFO')
	parser.add_argument('-r', '--randomize', action='store_true', help='set debugging level to INFO')
	args = parser.parse_args()

	# disable other loggers
	for v in logging.Logger.manager.loggerDict.values():
		if isinstance(v, logging.Logger):
			v.disabled = True

	if args.info:
		logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.INFO)
	else:
		logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

	bind_addr = parse_bind_addr(args.bind)
	host, port, resolve = parse_front_addr(args.front)

	if args.randomize:
		sys.exit(client_loop(bind_addr))

	if not resolve:
		logging.info(f'Resolving dns for: {host}')
		try:
			r = dns.resolver.Resolver()
			r.lifetime = r.timeout = DNS_TIMEOUT
			ans = r.resolve(host)
		except dns.exception.DNSException as e:
			if SHORTEN_ERRS:
				logging.critical(e)
			else:
				logging.critical(e, exc_info=True)
			sys.exit(8)
		else:
			resolve = next(ipval for ipval in ans).to_text()
			logging.info(f'Using IP: {resolve}')

	sys.exit(client_loop(bind_addr, (resolve, port), host))