# Supported platforms: Linux x86_64 and arm64, macOS arm64

enclos supports Linux on x86_64 and arm64 (including Raspberry Pi) and macOS on Apple silicon. Windows would need a third sandbox implementation (AppContainer) with a very different model from [0002](0002-linux-landlock-and-seccomp.md) and [0003](0003-macos-seatbelt.md), so it is out of scope until there is demand. Intel Macs are out of scope because macOS 26 is the last release for them. CI tests every supported platform, and `deny.toml` checks dependencies for exactly these targets.
