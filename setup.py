"""Build the optisocks5._core C++ extension (the sans-IO SOCKS5 codec).

Metadata lives in pyproject.toml; this file only declares the C++ extension,
which setuptools cannot express declaratively. Built automatically by uv / pip.
"""
from setuptools import Extension, setup

core = Extension(
    "optisocks5._core",
    sources=["csrc/module.cpp", "csrc/socks5_codec.cpp"],
    include_dirs=["csrc"],
    language="c++",
    extra_compile_args=["-std=c++20", "-O2", "-Wall", "-Wextra", "-Wpedantic"],
)

setup(ext_modules=[core])
