README for megapubdl
""""""""""""""""""""

megapubdl is command-line tool for Unix implemented as a Python script to
download public files (with a public URL) from MEGA (mega.nz, mega.co.nz).
It works with Python 2.6 and 2.7, and needs only the `openssl' external tool or
PyCrypto installed. It can be made work with Python 2.4 and 2.5 as well.

The implementation of megapubdl is based on
https://github.com/richardasaurus/mega.py/blob/master/mega/mega.py

Differences from mega.py:

* megapubdl is a single .py file (with no .py library dependencies).
* megapubdl doesn't have `requests' as a dependency.
* megapubdl works with either `pycrypto' or the `openssl' external tool,
  while mega.py depends on the former.
* megapubdl needs a Unix system to run. (Porting to Windows is possible.)
* megapubdl supports only 1 use case: downloading public files.
* megapubdl works with older versions of Python: 2.4, 2.5, 2.6 and 2.7.
* megapubdl works with older versions of libssl.

__END__
