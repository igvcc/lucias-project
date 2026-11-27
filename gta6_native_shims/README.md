# GTA VI Native PC Shim Suite & PE32+ Patcher

Standalone, non-destructive PE32+ IAT/subsystem/VFS patcher and Win64 console-to-PC shim DLL suite for `game_scarlett_master.exe`.

## Crates
- `crates/pe_native_patcher`: PE32+ analyzer, console DLL IAT remapper, subsystem/flags patcher, optional VFS hook importer, and dry-run/full-file validator.
- `crates/shims/*`: Compilable Win64 `cdylib` DLLs matching every console DLL & symbol imported by `game_scarlett_master.exe` (12 console DLLs, 110 symbols including C++ mangled `XboxBvhBuilder` exports and ordinal `#1` `GameInput`), plus `vfs_pc.dll` (`G:\` / `T:\` virtual drive root redirection).
- `crates/shim_integration_tests`: Automated tests verifying PE patcher correctness, `LoadLibrary` + `GetProcAddress` coverage for 100% of console imports, and functional tests of `xmem_pc`, `xcrd_pc`, `ffx_pc`, `vfs_pc`, and `pe_native_patcher`.

## Quick Commands
```powershell
cargo test --workspace
cargo build --workspace
```
