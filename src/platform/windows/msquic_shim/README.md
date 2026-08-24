# Lumen MsQuic shim

This DLL is the only translation unit that includes Microsoft's `msquic.h`.
Build it with MSVC v143 against the hash-pinned official 2.6.0 Schannel NuGet
package. Lumen's MSYS2/MinGW build links only the stable C ABI in
`lumen_msquic_shim.h`; it never parses the MSVC-specific upstream header.

The shim is experimental and not loaded unless `LUMEN_EXPERIMENTAL_MSQUIC=ON`.
It disables server resumption/0-RTT, exposes exact callback-scoped receive
buffers, retains callback contexts through reentrant close, and uses documented
abort-plus-immediate stream shutdown before handle retirement.
