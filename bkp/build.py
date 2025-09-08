import subprocess
import os

# Compila Cython
subprocess.check_call(["python", "setup.py", "build_ext", "--inplace"])

# Compila Rust
os.chdir("core/rust_loader")
subprocess.check_call(["cargo", "build", "--release"])
os.chdir("../../")

print("[*] Build finalizado")
