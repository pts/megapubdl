README for megapubdl
""""""""""""""""""""

megapubdl is command-line tool for Unix implemented as a Python script to
download public files (with a public URL) from MEGA (mega.nz, mega.co.nz).
It works with Python 2.6 and 2.7, and needs only the `openssl' external tool or
PyCrypto installed. It can be made work with Python 2.4 and 2.5 as well.

The implementation of megapubdl is based on
https://github.com/richardasaurus/mega.py/blob/master/mega/mega.py

Differences from mega.py:

* megapubdl doesn't have `requests' and `pycrypto' as a dependency.
* megapubdl depends on the `openssl' external tool.
* megapubdl needs a Unix system to run. (Porting to Windows is possible.)
* megapubdl supports only 1 use case: downloading public files.

__END__
