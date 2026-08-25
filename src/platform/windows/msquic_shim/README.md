# Lumen MsQuic shim

This DLL is the only translation unit that includes Microsoft's `msquic.h`.
Build it with MSVC v143 against the hash-pinned official 2.6.0 Schannel NuGet
package. Lumen's MSYS2/MinGW build links only the stable C ABI in
`lumen_msquic_shim.h`; it never parses the MSVC-specific upstream header.

The shim is experimental and not loaded unless `LUMEN_EXPERIMENTAL_MSQUIC=ON`.
It disables server resumption/0-RTT, exposes exact callback-scoped receive
buffers, retains callback contexts through reentrant close, and uses documented
abort-plus-immediate stream shutdown before handle retirement.

Before importing a PKCS#12 credential, the caller must configure an absolute,
access-controlled path with `lumen_msquic_set_cng_journal_path`. The shim first
reaps only exact provider/container/unique-name records from that bounded
journal, records each imported persisted key before its handle escapes import,
and retains the record whenever deletion fails. `NCryptDeleteKey` is the single
terminal operation on success; a failed delete is followed by exactly one
`NCryptFreeObject` and remains eligible for the next reaper pass.
