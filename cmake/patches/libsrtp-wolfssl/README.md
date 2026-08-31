# libSRTP 2.8.0 wolfCrypt backend

This directory is the reviewed patch payload for the LSP security target. It
adds wolfSSL 5.9.2 as a libSRTP CMake crypto choice without routing SRTP through
OpenSSL.

Apply it to an unmodified Cisco libSRTP 2.8.0 source tree in this order:

```text
copy aes_gcm_wolfssl.c -> crypto/cipher/aes_gcm_wolfssl.c
copy aes_icm_wolfssl.c -> crypto/cipher/aes_icm_wolfssl.c
patch -p1 < libsrtp-2.8.0-wolfssl.patch
cmake ... -DENABLE_WOLFSSL=ON -DENABLE_OPENSSL=OFF
```

The GCM backend uses wolfCrypt in place and supports AES-128-GCM and
AES-256-GCM. LSP selects only the 16-byte `SRTP_AEAD_AES_128_GCM` protection
profile. The ICM backend supplies
libSRTP's AES-CTR KDF and RFC 6904 encrypted-header-extension path through
wolfCrypt as well. libSRTP retains its own SSRC rollover and replay databases;
the backend does not replace or bypass them.

Production wolfSSL keeps its default 12-byte minimum authentication-tag policy.
The patch therefore omits libSRTP's optional 8-byte GCM vector from production
crypto-kernel startup while retaining the 16-byte known-answer vectors. Do not
set `WOLFSSL_MIN_AUTH_TAG_SZ=8` in Lumen or Umbra production builds. Upstream
libSRTP's broad `cipher_driver` and `srtp_driver` also exercise the optional
8-byte GCM profile. A dependency-proof-only wolfSSL and libSRTP build may both
use `-DWOLFSSL_MIN_AUTH_TAG_SZ=8` to run those compatibility cases; that define
is intentionally absent from the production patch.

The patch requires the exported CMake target `wolfssl::wolfssl`. On Apple, the
static wolfSSL build used for the proof also requires the Security and
CoreFoundation frameworks. Windows continues to receive `ws2_32` from
libSRTP's existing platform branch.
