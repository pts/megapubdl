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
Works with Python 2.6 and 2.7, and needs only the `openssl' external tool or
PyCrypto installed.

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
import ssl
import struct
import subprocess
import sys
import traceback

# This solves the HTTP connection problem on Ubuntu Lucid (10.04), but openssl
# there is still too old: openssl: unknown option '-aes-128-ctr'
#import ssl
#from functools import partial
#class fake_ssl:
#  wrap_socket = partial(ssl.wrap_socket, ssl_version=ssl.PROTOCOL_TLSv1)  # Good.
#httplib.ssl = fake_ssl


class RequestError(ValueError):
  """Error in API request."""


def import_get(module, name, default):
  try:
    __import__(module)
  except ImportError:
    return default
  return getattr(__import__('sys').modules[module], name, default)


openssl_prog = False


# Don't use this, alo-aes doesn't have AES-CTR, so we'd have to use openssl
# anyway.
if 0:
  def aes_cbc(is_encrypt, data, key, iv='\0' * 16):
    if len(key) != 16:
      raise ValueError
    if len(iv) != 16:
      raise ValueError
    # https://pypi.python.org/pypi/alo-aes/0.3 , implemented in C.
    import aes
    aes_obj = aes.Keysetup(key)
    if is_encrypt:
      return aes_obj.cbcencrypt(iv, data)[1]
    else:
      return aes_obj.cbcdecrypt(iv, data)[1]
elif import_get('Crypto.Cipher.AES', 'MODE_CBC', None) is not None:
  # PyCrypto, implemented in C (no Python implementation). Tested and found
  # working with pycrypto-2.3.
  def aes_cbc(is_encrypt, data, key, iv='\0' * 16):
    if len(key) != 16:
      raise ValueError
    if len(iv) != 16:
      raise ValueError
    from Crypto.Cipher import AES
    aes_obj = AES.new(key, AES.MODE_CBC, iv)
    if is_encrypt:
      return aes_obj.encrypt(data)
    else:
      return aes_obj.decrypt(data)
else:
  openssl_prog = True
  def aes_cbc(is_encrypt, data, key, iv='\0' * 16):
    if len(key) != 16:
      raise ValueError
    if len(iv) != 16:
      raise ValueError
    encdec = ('-d', '-e')[bool(is_encrypt)]
    p = subprocess.Popen(
        (openssl_prog, 'enc', encdec, '-aes-128-cbc', '-nopad',
         '-K', key.encode('hex'), '-iv', iv.encode('hex')),
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


def test_crypto_aes_cbc():
  key = 'k' * 16
  plaintext = 'a' * 64
  ciphertext = 'c8a97171fe2841736c27863f5da199d199bd3d757aacf7da7dd1805dcf2bb652e638f58d25420ab367966acdde3c8a1a9994b7e7fd32ed91bf0ea646fdd874a3'.decode('hex')
  assert aes_cbc(True,  plaintext, key) == ciphertext
  assert aes_cbc(False, ciphertext, key) == plaintext


if import_get('Crypto.Cipher.AES', 'MODE_CTR', None) is not None:
  # PyCrypto, implemented in C (no Python implementation). Tested and found
  # working with pycrypto-2.3.
  def yield_aes_ctr(data_iter, key, iv='\0' * 16, bufsize=None):
    if len(key) != 16:
      raise ValueError
    if len(iv) != 16:
      raise ValueError
    if isinstance(data_iter, str):
      data_iter = (data_iter,)
    data_iter = iter(data_iter)
    # PyCrypto, implemented in C (no Python implementation).
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
    counter = Counter.new(8 * len(key), initial_value=int(iv.encode('hex'), 16))
    aes_obj = AES.new(key, AES.MODE_CTR, counter=counter)
    yield ''  # This is important, it signifies that decryption has started.
    encrypt = aes_obj.encrypt  # .encrypt and .decrypt do the same.
    for data in data_iter:
      yield encrypt(data)
else:
  openssl_prog = True
  def yield_aes_ctr(data_iter, key, iv='\0' * 16, bufsize=65536):
    if len(key) != 16:
      raise ValueError
    if len(iv) != 16:
      raise ValueError
    if isinstance(data_iter, str):
      data_iter = (data_iter,)
    data_iter = iter(data_iter)
    # Ubuntu Lucid has openssl-0.9.8k (2009-03-15) and openssl-0.9.8zh (2016)
    # don't have -aes-128-ctr.
    p = subprocess.Popen(
        (openssl_prog, 'enc', '-d', '-aes-128-ctr', '-nopad',
         '-K', key.encode('hex'), '-iv', iv.encode('hex')),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    wfd = p.stdin.fileno()
    rfd = p.stdout.fileno()
    file_size = read_size = write_size = 0
    go = True
    # We don't do MAC verification on the downloaded data, that would
    # need additional crypto operations.
    try:
      yield ''  # This is important, it signifies that decryption has started.
      assert wfd >= 0
      while go:
        data = ''
        for data in data_iter:
          file_size += len(data)
          break  # Just get one (next) string.
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


def test_crypto_aes_ctr():
  key = 'k' * 16
  plaintext = 'a' * 63  # Not divisible by 16.
  # With default iv: ciphertext = 'f442c33f3a194b34800aa6c6a1387a1e51a61c628a5d9cf4dfc404a5853bbdb2a35e5ffa6454a3f994189ecba05b4d106c80c5976b9b0d5825988eff547d15'.decode('hex')
  ciphertext = '98ebbfa0932e0c3cf867b2ab5a7cd191a4d207475ec0340b49782d2e1083955c5838cf0b84ee87cf4b95a9b94b7e8f29de835be1ad0d7d078d505fb9bec167'.decode('hex')
  iv = '\0\1\2\3' * 4
  #assert aes_ctr(plaintext, key, iv) == ciphertext
  #assert aes_ctr(ciphertext, key, iv) == plaintext
  assert ''.join(yield_aes_ctr(plaintext, key, iv)) == ciphertext
  assert ''.join(yield_aes_ctr(ciphertext, key, iv)) == plaintext
  assert ''.join(yield_aes_ctr('foo\n', '\0' * 16)) == '\x00\x86\x24\xde'
  # Does the encryption 1 byte at a time.
  assert ''.join(yield_aes_ctr(iter('foo\n'), '\0' * 16)) == '\x00\x86\x24\xde'


def check_aes_128_ctr():
  # Ubuntu Lucid has openssl-0.9.8k (2009-03-15), which doesn't have
  # -aes-128-ctr.
  try:
    data = ''.join(yield_aes_ctr('foo\n', '\0' * 16))
  except (OSError, IOError, ValueError):
    raise ValueError(
        'Error starting crypto -- '
        'you may need to upgrade your openssl command or install pycrypto.')
  if data != '\x00\x86\x24\xde':
    raise ValueError(
        'Incorrect result from crypto -- '
        'you may need to reinstall your openssl command or install pycrypto.')


def find_custom_openssl():
  global openssl_prog
  if openssl_prog is not True:
    return
  import os
  import os.path
  prog = __file__
  try:
    target = os.readlink(prog)
  except (OSError, AttributeError):
    target = None
  if target is not None:
    if not target.startswith('/'):
      prog = os.path.join(os.path.dirname(prog), target)
  progdir = os.path.dirname(prog)
  if not progdir:
    progdir = '.'
  for name in ('openssl-megapubdl',
               'openssl-core2.static', 'openssl.static', 'openssl'):
    pathname = os.path.join(progdir, name)
    if os.path.isfile(pathname):
      openssl_prog = pathname
      break
  else:
    openssl_prog = 'openssl'


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
  # TODO(pts): Cleanup: Call hc.close() eventually.
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
    yield_size = 0
    for pdata in yield_aes_ctr(
        iter(lambda bufsize=self.bufsize: hr.read(bufsize), ''),
        key_str, iv_str, self.bufsize):
      yield pdata
      yield_size += len(pdata)
    if yield_size != file_size:
      raise RequestError('File size mismatch: got=%d expected=%d' %
                         (yield_size, file_size))


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
  find_custom_openssl()
  check_aes_128_ctr()
  if len(argv) > 1 and argv[1] == '--test-crypto':
    test_crypto_aes_cbc()
    test_crypto_aes_ctr()
    print '%s --test-crypto OK.' % argv[0]
    return
  if (not os.environ.get('PYTHONHTTPSVERIFY', '') and
      getattr(ssl, '_create_unverified_context', None)):
    # Prevent staticpython from trying to load /usr/local/ssl/cert.pem .
    # `export PYTHONHTTPSVERIFY=1' would also work from the shell.
    ssl._create_default_https_context = ssl._create_unverified_context
    pass
  mega = Mega()
  had_error = False
  for url in argv[1:]:
    print >>sys.stderr, 'info: Downloading URL: %s' % url
    try:
      dl = mega.download_url(url)
      dl_info = dl.next()
      print >>sys.stderr, 'info: Saving file of %s bytes to file: %s' % (dl_info['size'], dl_info['name'])
      marker = dl.next()  # Start the download.
      assert marker == ''
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
