# Supported platforms: macOS on Apple silicon and Linux on x86_64 and arm64

enclos supports macOS on Apple silicon and Linux on x86_64 and arm64, including Raspberry Pi. On Windows it will run later through WSL2, using the Linux build and the bubblewrap backend; there is no native Windows backend. Intel Macs are out of scope because macOS 26 is their last release. CI tests every supported platform, and `deny.toml` checks dependencies for exactly these targets.
