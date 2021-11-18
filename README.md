# mlware 

[![x86_64](https://github.com/marirs/mlware/actions/workflows/linux_x86_64.yml/badge.svg?branch=master)](https://github.com/marirs/mlware/actions/workflows/linux_x86_64.yml)
[![Arm7](https://github.com/marirs/mlware/actions/workflows/linux_arm.yml/badge.svg?branch=master)](https://github.com/marirs/mlware/actions/workflows/linux_arm.yml)

Static malware detection using machine learning.

### Requirements
- Rust 1.50+
- CMake
- LightGBM

### Prerequisites

- macOS
```bash
brew install cmake libomp lightgbm
```

- Linux
```bash
apt install -y cmake libclang-dev libc++-dev gcc-multilib
```

### Compiling 
```bash
cargo b --release
```

### Example
```bash
cargo b --example test
```

---
