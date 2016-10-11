#! /usr/bin/python
# by pts@fazekas.hu at Tue Oct 11 13:12:47 CEST 2016

""":" #megapubdl: Download public files from MEGA (mega.nz).

type python2.7 >/dev/null 2>&1 && exec python2.7 -- "$0" ${1+"$@"}
type python2.6 >/dev/null 2>&1 && exec python2.6 -- "$0" ${1+"$@"}
type python2.5 >/dev/null 2>&1 && exec python2.5 -- "$0" ${1+"$@"}
type python2.4 >/dev/null 2>&1 && exec python2.4 -- "$0" ${1+"$@"}
exec python -- ${1+"$@"}; exit 1

megapubdl is command-line tool for Unix implemented as a Python script to
download public files (with a public URL) from MEGA (mega.nz, mega.co.nz).
Works with Python 2.6 and 2.7, and needs only the `openssl' external tool.

Usage:

  megapubdl.py "https://mega.nz/#!..."
"""

#
# TODO(pts): Improve error handling (especially socket errors and parse errors).
#

import base64
import urllib  # For urlencode.
import httplib
import json  # Needs Python >=2.6.
import os
import random
import re
import select
import socket
import struct
import subprocess
import sys
import traceback


class RequestError(ValueError):
  """Error in API request."""


def aes_cbc(is_encrypt, data, key):
  if len(key) != 16:
    raise ValueError
  encdec = ('-d', '-e')[bool(is_encrypt)]
  p = subprocess.Popen(
      ('openssl', 'enc', encdec, '-aes-128-cbc', '-nopad', '-K', key.encode('hex'), '-iv', '0' * 32),
      stdin=subprocess.PIPE, stdout=subprocess.PIPE)
  try:
    got, _ = p.communicate(data)
  finally:
    p.stdin.close()
    exitcode = p.wait()
  if exitcode:
    raise ValueError('Error running openssl enc.')
  if len(got) != len(data):
    raise ValueError('openssl enc output size mismatch.')
  assert len(got) == len(data)
  return got


def aes_cbc_encrypt_a32(data, key):
  return str_to_a32(aes_cbc(True, a32_to_str(data), a32_to_str(key)))


def aes_cbc_decrypt_a32(data, key):
  return str_to_a32(aes_cbc(False, a32_to_str(data), a32_to_str(key)))


def stringhash(str, aeskey):
  s32 = str_to_a32(str)
  h32 = [0, 0, 0, 0]
  for i in xrange(len(s32)):
    h32[i % 4] ^= s32[i]
  for r in xrange(0x4000):
    h32 = aes_cbc_encrypt_a32(h32, aeskey)
  return a32_to_base64((h32[0], h32[2]))


def encrypt_key(a, key):
  return sum(
    (aes_cbc_encrypt_a32(a[i:i + 4], key)
      for i in xrange(0, len(a), 4)), ())


def decrypt_key(a, key):
  return sum(
    (aes_cbc_decrypt_a32(a[i:i + 4], key)
      for i in xrange(0, len(a), 4)), ())


def decrypt_attr(attr, key):
  attr = aes_cbc(False, attr, a32_to_str(key)).rstrip('\0')
  return json.loads(attr[4:]) if attr[:6] == 'MEGA{"' else False


def a32_to_str(a):
  return struct.pack('>%dI' % len(a), *a)


def str_to_a32(b):
  if len(b) % 4:
    # pad to multiple of 4
    b += '\0' * (4 - len(b) % 4)
  return struct.unpack('>%dI' % (len(b) / 4), b)


def base64_url_decode(data):
  data += '=='[(2 - len(data) * 3) % 4:]
  for search, replace in (('-', '+'), ('_', '/'), (',', '')):
    data = data.replace(search, replace)
  return base64.b64decode(data)


def base64_to_a32(s):
  return str_to_a32(base64_url_decode(s))


def base64_url_encode(data):
  data = base64.b64encode(data)
  for search, replace in (('+', '-'), ('/', '_'), ('=', '')):
    data = data.replace(search, replace)
  return data


def a32_to_base64(a):
  return base64_url_encode(a32_to_str(a))


# more general functions
def make_id(length):
  possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  return ''.join(random.choice(possible) for _ in xrange(length))


URL_RE = re.compile(r'([a-z0-9]+)://([^/:@?#]+)(?::(\d+))?')


def send_http_request(url, data=None, timeout=None):
  """Return a httplib.HTTPResponse object."""
  match = URL_RE.match(url)
  if not match:
    raise ValueError('Bad URL: %s' % url)
  schema = match.group(1)
  if schema not in ('http', 'https'):
    raise ValueError('Unknown schema: %s' % schema)
  host = match.group(2)
  if match.group(3):
    port = int(match.group(3))
  else:
    port = (80, 443)[schema == 'https']
  path = url[match.end():] or '/'
  ipaddr = socket.gethostbyname(host)  # Force IPv4. Needed by Mega.
  hc_cls = (httplib.HTTPConnection, httplib.HTTPSConnection)[schema == 'https']
  # TODO(pts): Call hc.close() eventually.
  hc = hc_cls(ipaddr, port, timeout=timeout)
  if data is None:
    hc.request('GET', path)
  else:
    hc.request('POST', path, data)
  return hc.getresponse()  # HTTPResponse.


class Mega(object):
  def __init__(self, options=None):
    self.bufsize = 65536
    self.schema = 'https'
    self.domain = 'mega.co.nz'
    self.timeout = 160  # max time (secs) to wait for resp from api requests
    self.sid = None
    self.sequence_num = random.randint(0, 0xFFFFFFFF)
    self.request_id = make_id(10)

    if options is None:
      options = {}
    self.options = options

  def _login(self):
    master_key = [random.randint(0, 0xFFFFFFFF)] * 4
    password_key = [random.randint(0, 0xFFFFFFFF)] * 4
    session_self_challenge = [random.randint(0, 0xFFFFFFFF)] * 4

    user = self._api_request({
      'a': 'up',
      'k': a32_to_base64(encrypt_key(master_key, password_key)),
      'ts': base64_url_encode(a32_to_str(session_self_challenge) +
                  a32_to_str(encrypt_key(session_self_challenge, master_key)))
    })

    resp = self._api_request({'a': 'us', 'user': user})
    #if numeric error code response
    if isinstance(resp, int):
      raise RequestError(resp)
    encrypted_master_key = base64_to_a32(resp['k'])
    self.master_key = decrypt_key(encrypted_master_key, password_key)
    if 'tsid' not in resp:
      raise RequestError('Missing tsid.')
    tsid = base64_url_decode(resp['tsid'])
    key_encrypted = a32_to_str(
      encrypt_key(str_to_a32(tsid[:16]), self.master_key))
    if key_encrypted == tsid[-16:]:
      self.sid = resp['tsid']

  def _api_request(self, data):
    params = {'id': self.sequence_num}
    self.sequence_num += 1

    if self.sid:
      params.update({'sid': self.sid})

    #ensure input data is a list
    if not isinstance(data, list):
      data = [data]

    url = '%s://g.api.%s/cs?%s' % (self.schema, self.domain, urllib.urlencode(params))
    hr = send_http_request(url, data=json.dumps(data), timeout=self.timeout)
    if hr.status != 200:
      raise RequestError('HTTP not OK: %s %s' % (hr.status, hr.reason))
    json_resp = json.loads(hr.read())
    #if numeric error code response
    if isinstance(json_resp, int):
      raise RequestError(json_resp)
    return json_resp[0]

  def download_url(self, url):
    """Starts downloading a file from Mega, based on URL.

    Example usage:

      mega = Mega()
      dl = mega.download_url('https://mega.nz/#!ptJElSYC!qEPvI7qJkjvreVxpLU7CoJc4sxF3X7p1DH5WEMmPs5U')
      dl_info = dl.next()
      print (dl_info['name'], dl_info['size'])
      dl.next()  # Start the download.
      f = open(dl_info['name'], 'wb')
      try:
        for data in dl:
          f.write(data)
      finally:
        f.close()
    """
    if self.sid is None:
      self._login()
    i = url.find('/#!')
    if i < 0:
      raise RequestError('Key missing from URL.')
    path = url[i + 3:].split('!')
    file_handle = path[0]
    file_key = path[1]
    file_key = base64_to_a32(file_key)  # if is_public:
    file_data = self._api_request({'a': 'g', 'g': 1, 'p': file_handle})
    k = (file_key[0] ^ file_key[4], file_key[1] ^ file_key[5],
       file_key[2] ^ file_key[6], file_key[3] ^ file_key[7])
    iv = file_key[4:6] + (0, 0)
    meta_mac = file_key[6:8]

    # Seems to happens sometime... When  this occurs, files are
    # inaccessible also in the official also in the official web app.
    # Strangely, files can come back later.
    if 'g' not in file_data:
      raise RequestError('File not accessible now.')
    file_url = file_data['g'].encode('UTF-8')
    file_size = int(file_data['s'])  # Was already an int.
    attribs = base64_url_decode(file_data['at'])
    attribs = decrypt_attr(attribs, k)
    file_name = attribs['n'].encode('UTF-8')
    key_str = a32_to_str(k)
    assert len(key_str) == 16
    iv_str = struct.pack('>LLLL', iv[0], iv[1], 0, 0)
    assert len(iv_str) == 16

    yield {'name': file_name, 'size': file_size, 'url': file_url, 'key': key_str, 'iv': iv_str}

    hr = send_http_request(file_url, timeout=self.timeout)
    if hr.status != 200:
      raise RequestError('HTTP download link not OK: %s %s' % (hr.status, hr.reason))
    ct = hr.getheader('content-type', '').lower()
    if ct.startswith('text/'):  # Typically 'application/octet-stream'.
      raise RequestError('Unexpected content-type: %s' % ct)

    p = subprocess.Popen(
        ('openssl', 'enc', '-d', '-aes-128-ctr', '-nopad', '-K', key_str.encode('hex'), '-iv', iv_str.encode('hex')),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    bufsize = self.bufsize
    wfd = p.stdin.fileno()
    rfd = p.stdout.fileno()
    read_size = write_size = 0
    go = True
    # We don't do MAC verification on the downloaded data, that would
    # need additional crypto operations.
    try:
      yield ''
      assert wfd >= 0
      while go:
        data = hr.read(bufsize)
        if not data:
          p.stdin.close()  # os.close(wfd)
          wfd = -1
          while 1:
            pdata = os.read(rfd, bufsize)
            if not pdata:
              go = False
              break
            read_size += len(pdata)
            yield pdata
          break
        i = 0
        while i < len(data):
          rfds, wfds, _ = select.select((rfd,), (wfd,), (), None)
          if rfds:
            pdata = os.read(rfd, bufsize)
            if not pdata:
              go = False
              break
            read_size += len(pdata)
            yield pdata
          if wfds:
            got = os.write(wfd, buffer(data, i, i + bufsize))
            i += got
            write_size += got
    finally:
      exitcode = p.wait()
    if exitcode:
      raise ValueError('Error running openssl enc.')
    if read_size != write_size:
      raise ValueError('openssl enc output size mismatch: read_size=%d write_size=%d' % (read_size, write_size))
    if read_size != file_size:
      raise ValueError('File size mismatch.')


def get_module_docstring():
  return __doc__


def get_doc(doc=None):
  if doc is None:
    doc = get_module_docstring()
  doc = doc.rstrip()
  doc = re.sub(r'\A:"\s*#', '', doc, 1)
  doc = re.sub(r'\n(\ntype python.*)+\nexec python -- .*', '', doc, 1)
  return doc


def main(argv):
  if len(argv) < 2 or argv[1] == '--help':
    print get_doc()
    sys.exit(0)
  mega = Mega()
  had_error = False
  for url in argv[1:]:
    print >>sys.stderr, 'info: Downloading URL: %s' % url
    try:
      dl = mega.download_url(url)
      dl_info = dl.next()
      print >>sys.stderr, 'info: Saving file of %s bytes to file: %s' % (dl_info['size'], dl_info['name'])
      dl.next()  # Start the download.
      f = open(dl_info['name'], 'wb')
      try:
        for data in dl:
          f.write(data)
      finally:
        f.close()
    except (socket.error, IOError, OSError, ValueError):
      traceback.print_exc()
      had_error = True
  sys.exit(2 * bool(had_error))


if __name__ == '__main__':
  sys.exit(main(sys.argv))
