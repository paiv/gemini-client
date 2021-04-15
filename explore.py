#!/usr/bin/env python
import codecs
import logging
import os
import readline
import socket
import ssl
import sys
from urllib.parse import quote as urlquote, urlparse, urlsplit, urlunsplit
from collections import namedtuple


logging.basicConfig()
logger = logging.getLogger('GeminiClient')


class GeminiClient:
    'gemini://gemini.circumlunar.space/docs/specification.gmi'

    def __init__(self, client_identity=None):
        self.client_identity = client_identity

    def get(self, url, port=None, stream=False):
        def redirected(url, level, history):
            if level > 5:
                raise Exception((url, history))

            try:
                with GeminiTransport(url, port, self.client_identity) as cli:
                    r = cli.get(url, stream=stream)
            except:
                raise Exception((url, history))

            if 20 <= r.status <= 29:
                return r
            elif 30 <= r.status <= 39:
                history.append(r)
                return redirected(_urljoin(url, r.meta), level+1, history)
            elif 10 <= r.status <= 19:
                r.needs_input = True
                return r
            else:
                if history:
                    raise Exception((r.status, r.meta, url, history))
                raise Exception((r.status, r.meta, url))

        return redirected(url, 0, list())


class GeminiResponse:
    def __init__(self, socket, ssocket, url, status, meta, stream=False):
        self.s = socket
        self.ss = ssocket
        self.url = url
        self.status = status
        self.meta = meta
        self.stream = stream
        self.needs_input = False
        self.has_content = 20 <= status <= 29
        self.content = None

        codec = self._get_codec(meta)
        self.is_binary = codec is None
        if self.has_content:
            reader = codec(self.ss, errors='ignore') if codec else self.ss
            if stream:
                self.content = reader
            else:
                self.content = reader.read()
                self.close()
        else:
            self.close()

    def close(self):
        if self.ss:
            self.ss.close()
        if self.s:
            self.s.close()

    def _get_codec(self, meta):
        parts = meta.lower().split(';')
        mime = parts[0]
        if mime and (not mime.startswith('text/')):
            return None
        codec = 'utf-8'
        if len(parts) > 1:
            for param in parts[1:]:
                nv = param.split('=', maxsplit=1)
                if len(nv) == 2:
                    if nv[0].strip() == 'charset':
                        codec = nv[1].strip()
        try:
            return codecs.getreader(codec)
        except LookupError:
            return None


class GeminiTransport:
    def __init__(self, url, port=None, client_identity=None):
        self.is_detached = False
        uri = urlparse(url)
        self.hostname = uri.hostname or url.strip()
        self.hostport = port or uri.port or 1965

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if client_identity:
            context.load_cert_chain(client_identity)
        self.tls_context = context
        self.tls_version = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def open(self):
        self.s = socket.create_connection((self.hostname, self.hostport))
        self.ss = self.tls_context.wrap_socket(self.s, server_hostname=self.hostname)
        self.tls_version = self.ss.version()

    def close(self):
        if not self.is_detached:
            if self.ss:
                self.ss.close()
            if self.s:
                self.s.close()

    def get(self, url, stream=False):
        if not '://' in url:
            url = 'gemini://' + url
        logger.info(f'get {url!r}')
        self._write_request(url)
        code, meta = self._read_response_status()
        self.is_detached = True
        return GeminiResponse(socket=self.s, ssocket=self.ss, url=url, status=code, meta=meta, stream=stream)

    def _write_request(self, url):
        r = url.encode('utf-8') + b'\r\n'
        self.ss.write(r)

    def _read_response_status(self):
        buf = b''
        while not buf.endswith(b'\r\n') and len(buf) < 1030:
            s = self.ss.read(1)
            buf += s
            if not s: break

        if not buf.endswith(b'\r\n'):
            raise Exception(buf)

        s = buf.decode('utf-8').strip()
        r = s.split(maxsplit=1)
        if len(r) == 2:
            code, meta = r
            return int(code, 10), meta
        elif len(r) == 1:
            return int(s, 10), ''
        raise Exception(buf)


def _urljoin(url, path, query=None):
    if path and ('://' in path):
        return path
    p = urlsplit(url)
    return urlunsplit((p[0], p[1], path or p[2], query or '', ''))


def main(url, port, client_identity, outfile, remote_name):
    def open_output(outfile, binary):
        logger.info(f'open_output {outfile} binary? {binary}')
        so = outfile
        if outfile is None:
            if remote_name:
                uri = urlparse(url)
                outfile = os.path.basename(uri.path)
                so = open(outfile, 'wb' if binary else 'w')
            else:
                so = sys.stdout.buffer if binary else sys.stdout
        elif isinstance(outfile, str):
            so = open(outfile, 'wb' if binary else 'w')
        return so

    outstream = None
    def dump_stream(r, buffer_size=1):
        nonlocal outstream
        logger.info(f'status {r.status} {r.meta!r}')
        if not r.has_content: return
        if outstream is None:
            outstream = open_output(outfile, binary=r.is_binary)
        while True:
            chunk = r.content.read(buffer_size)
            if not chunk: break
            outstream.write(chunk)
        r.close()

    cli = GeminiClient(client_identity)
    r = cli.get(url, port=port, stream=True)
    dump_stream(r)
    while r.needs_input:
        s = input(r.meta + '> ')
        url = _urljoin(r.url, '', query=urlquote(s))
        r = cli.get(url, port=port, stream=True)
        dump_stream(r)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('url', help='gemini:// URL')
    parser.add_argument('-p', '--port', type=int, help='Override default port 1965')
    parser.add_argument('-i', '--identity', metavar='ID', help='Client certificate file (.pem)')
    parser.add_argument('-o', '--output', metavar='FILE', help='Output file name')
    parser.add_argument('-O', '--remote-name', action='store_true', help='Use file name from the URL')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    if args.verbose:
        logger.level = logging.INFO

    main(url=args.url, port=args.port, client_identity=args.identity,
        outfile=args.output, remote_name=args.remote_name)
