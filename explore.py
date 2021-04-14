#!/usr/bin/env python
import codecs
import logging
import readline
import socket
import ssl
import sys
from urllib.parse import quote as urlquote, urlparse, urlsplit, urlunsplit
from collections import namedtuple


logging.basicConfig()
logger = logging.getLogger('GeminiClient')


GeminiResponse = namedtuple('GeminiResponse',
    'uri status meta content needs_input', defaults=(False,))


class GeminiClient:
    'gemini://gemini.circumlunar.space/docs/specification.gmi'

    def __init__(self, client_identity=None):
        self.client_identity = client_identity

    def get(self, uri, port=None, stream=False):
        def redirected(uri, level, history):
            if level > 5:
                raise Exception((uri, history))

            try:
                with GeminiTransport(uri, port, self.client_identity) as cli:
                    r = cli.get(uri, stream=stream)
            except:
                raise Exception((uri, history))

            if 20 <= r.status <= 29:
                return r
            elif 30 <= r.status <= 39:
                history.append(r)
                return redirected(_urljoin(uri, r.meta), level+1, history)
            elif 10 <= r.status <= 19:
                return GeminiResponse(uri=r.uri, status=r.status, meta=r.meta, content=r.content, needs_input=True)
            else:
                if history:
                    raise Exception((r.status, r.meta, uri, history))
                raise Exception((r.status, r.meta, uri))

        return redirected(uri, 0, list())


class GeminiTransport:
    def __init__(self, uri, port=None, client_identity=None):
        url = urlparse(uri)
        self.hostname = url.hostname or uri.strip()
        self.hostport = port or url.port or 1965

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
        if self.ss:
            self.ss.close()
            self.ss = None
        if self.s:
            self.s.close()
            self.s = None

    def get(self, uri, stream=False):
        if not '://' in uri:
            uri = 'gemini://' + uri
        logger.info(f'get {uri!r}')
        self._write_request(uri)
        code, meta = self._read_response_status()
        codec = self._get_codec(meta)
        body = self._read_response_content(codec, stream=stream)
        if stream:
            self.ss = None
            self.s = None
        return GeminiResponse(uri=uri, status=code, meta=meta, content=body)

    def _write_request(self, uri):
        r = uri.encode('utf-8') + b'\r\n'
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

    def _get_codec(self, meta):
        parts = meta.lower().split(';')
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

    def _read_response_content(self, codec, stream=False):
        reader = codec(self.ss, errors='ignore') if codec else self.ss
        if stream:
            return reader
        return reader.read()


def _urljoin(url, path, query=None):
    if path and ('://' in path):
        return path
    p = urlsplit(url)
    return urlunsplit((p[0], p[1], path or p[2], query or '', ''))


def main(uri, port, client_identity, outfile):
    outstream = None
    def dump_stream(r, buffer_size=1):
        nonlocal outstream
        logger.info(f'status {r.status} {r.meta!r}')
        if not r.content: return
        if outstream is None:
            outstream = outfile
            if isinstance(outfile, str):
                outstream = open(outfile, 'w')
        while True:
            chunk = r.content.read(buffer_size)
            if not chunk: break
            outstream.write(chunk)
        r.content.close()

    cli = GeminiClient(client_identity)
    r = cli.get(uri, port=port, stream=True)
    dump_stream(r)
    while r.needs_input:
        s = input(r.meta + '> ')
        uri = _urljoin(r.uri, '', query=urlquote(s))
        r = cli.get(uri, port=port, stream=True)
        dump_stream(r)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('uri', help='gemini:// URI')
    parser.add_argument('-p', '--port', type=int, help='Override default port 1965')
    parser.add_argument('-i', '--identity', metavar='ID', help='Client certificate file (.pem)')
    parser.add_argument('-o', '--output', metavar='FILE', help='Output file name')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    if args.verbose:
        logger.level = logging.INFO

    main(uri=args.uri, port=args.port, client_identity=args.identity,
        outfile=args.output or sys.stdout)
