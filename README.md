# DeepMal 

Static malware analysis using machine learning.

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
