project(sslscan)

cmake_minimum_required(VERSION 2.6)

set(Python_ADDITIONAL_VERSIONS 3.2 3.3)
find_package(PythonLibs REQUIRED)
find_package(OpenSSL REQUIRED)

add_subdirectory(python)
add_subdirectory(src)
