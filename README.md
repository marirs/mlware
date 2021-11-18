# mlware 

[![Intel](https://github.com/marirs/mlware/actions/workflows/linux_intel.yml/badge.svg?branch=master)](https://github.com/marirs/mlware/actions/workflows/linux_intel.yml)
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

- Linux Intel
```bash
apt install -y cmake libclang-dev libc++-dev gcc-multilib
```

- Linux Arm
```bash
apt install -y cmake libclang-dev libc++-dev gcc-multilib-arm-linux-gnueabihf
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
