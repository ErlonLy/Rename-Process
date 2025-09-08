# build_all.py
import os
import shutil
import subprocess
import glob
import sys

def clean_build():
    print("[*] Limpando arquivos antigos...")
    paths = [
        "build",
        "core/__pycache__",
        "core/*.pyd",
        "core/winapi.c",
        "core/winapi.cp*"
    ]
    for path in paths:
        if "*" in path:
            for file in glob.glob(path):
                try:
                    os.remove(file)
                    print(f"  [CLEAN] Removido: {file}")
                except Exception:
                    pass
        elif os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
            print(f"  [CLEAN] Removido diretório: {path}")
        elif os.path.isfile(path):
            os.remove(path)
            print(f"  [CLEAN] Removido arquivo: {path}")

def build_rust():
    print("[*] Compilando módulo Rust...")
    rust_dir = os.path.join("core", "rust_loader")
    try:
        subprocess.check_call(["cargo", "build", "--release"], cwd=rust_dir)
        print("[*] Rust compilado com sucesso")
    except subprocess.CalledProcessError as e:
        print(f"[!] Erro ao compilar Rust: {e}")
    except FileNotFoundError:
        print("[!] Cargo não encontrado. Certifique-se de que o Rust está instalado.")

def main():
    clean_build()
    build_rust()
    print("\n✅ Build concluído com sucesso!")
    print("Agora você pode rodar:")
    print("    python main.py")

if __name__ == "__main__":
    main()