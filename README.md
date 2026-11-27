# LUCIAS PROJECT

Kod źródłowy warstwy natywnej PC dla **LUCIAS PROJECT** (bez plików i zasobów gry).

## Struktura

- `gta6_native_shims/` — workspace Rust z natywnymi shimami (`dx12xs_pc`, `xgameruntime_pc`, `xcrd_pc`, `vfs_pc`, `audio_pc`, `xg_pc`, `xmem_pc`, `hc_pc`, `xbvh_pc`, `bink2_pc`, `chad_pc`, `ffx_pc`, `gi_pc`, `gameinput_shim`, `shim_common`), patcherem PE (`pe_native_patcher`) oraz testami integracyjnymi.
- `gta6_native_stage/` — skrypty PowerShell do stagingu, weryfikacji integralności (`verify_native_stage.ps1`) oraz narzędzie `boot_probe`.
- `gta6_native_tools/` — narzędzia pomocnicze do analizy i konwersji formatów.
- `gta6_native_renderer/` — komponenty renderera natywnego.

## Budowanie i testy

```powershell
cd gta6_native_shims
cargo test --workspace --offline
cargo clippy --workspace --all-targets --offline -- -D warnings
```
