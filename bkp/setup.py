# setup.py
from setuptools import setup, Extension
from Cython.Build import cythonize
import os

# Configuração para compilar com Windows SDK
extra_compile_args = ["/DWIN32", "/D_WINDOWS", "/D_USRDLL"]
extra_link_args = ["/DLL", "/NODEFAULTLIB:LIBCMT"]

extensions = [
    Extension(
        "winapi",
        ["core/winapi.pyx"],
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
        libraries=["kernel32", "user32"],
        language="c++",
    )
]

setup(
    name="winapi",
    ext_modules=cythonize(extensions),
    zip_safe=False,
)