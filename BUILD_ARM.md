# Build pour Apple Silicon (M1/M2/M3)

## Compilation native ARM64

Le projet est configuré pour compiler nativement en ARM64 sur les Macs Apple Silicon.

### Build automatique

```bash
cargo build --release
```

Le binaire sera généré dans :
```
target/aarch64-apple-darwin/release/bruteforce-wifi
```

### Vérification de l'architecture

```bash
file target/aarch64-apple-darwin/release/bruteforce-wifi
# Output: Mach-O 64-bit executable arm64
```

### Installation locale

```bash
# Copier dans /usr/local/bin
sudo cp target/aarch64-apple-darwin/release/bruteforce-wifi /usr/local/bin/

# Ou créer un alias
echo 'alias bruteforce-wifi="/Users/max/Documents/Code/bruteforce-wifi/target/aarch64-apple-darwin/release/bruteforce-wifi"' >> ~/.zshrc
source ~/.zshrc
```

### Optimisations ARM64

Le binaire est compilé avec :
- `target-cpu=native` : Utilise les instructions ARM64 natives (NEON, etc.)
- Optimisations de compilation complètes (`lto`, `opt-level=3`)
- Performance maximale sur Apple Silicon

### Désactiver la compilation ARM64

Si vous voulez compiler en x86_64 (Rosetta 2), supprimez `.cargo/config.toml`.
