project(sslscan)

cmake_minimum_required(VERSION 2.6)

# Prefer Python 3.x
set(Python_ADDITIONAL_VERSIONS 3.3 3.2 2.7)
find_package(PythonLibs REQUIRED)
find_package(OpenSSL REQUIRED)

add_subdirectory(python)
add_subdirectory(src)
