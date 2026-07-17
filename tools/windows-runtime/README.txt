RBX Luau Runtime for Windows

windows-x64/rbx_luau_runtime.exe   Windows 10/11 x64
windows-arm64/rbx_luau_runtime.exe Windows 11 ARM64

Run either profile from Command Prompt:

  rbx_luau_runtime.exe --profile roblox-client script.luau
  rbx_luau_runtime.exe --profile executor-client script.luau

Both are Release builds of the release-729 runtime. libcurl is linked statically
and uses Windows Schannel. OpenSSL Crypto is linked statically for owner-signature
verification, so no OpenSSL or libcurl DLL is included. The x64 binary was
smoke-tested under Wine. The ARM64 binary was validated by its PE/COFF header and
import table because it cannot execute under the x64 Wine container.
