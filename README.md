# GM-OSSL for Go
GM SM2/3/4 library based on [OpenSSL@1.1](https://github.com/openssl/openssl)

## Install OpenSSL v1.1

### Using on macOS
1. Install [homebrew](http://brew.sh/)
2. `$ brew install openssl` or `$ brew install openssl@1.1`

### Using on Linux
http://www.openssl.org/source/

### Using on Windows
1. Install [mingw-w64](http://mingw-w64.sourceforge.net/)
2. Install [pkg-config-lite](http://sourceforge.net/projects/pkgconfiglite)
3. Build (or install precompiled) openssl for mingw32-w64
4. Set __PKG\_CONFIG\_PATH__ to the directory containing openssl.pc
   (i.e. c:\mingw64\mingw64\lib\pkgconfig)
   
## References
- https://github.com/openssl/openssl
- https://github.com/spacemonkeygo/openssl