project(sslscan)

cmake_minimum_required(VERSION 2.6)
include(GNUInstallDirs)

# Prefer Python 3.x
set(Python_ADDITIONAL_VERSIONS 3.3 3.2 2.7 2.6)
find_package(PythonInterp REQUIRED)
set(Python_ADDITIONAL_VERSIONS ${PYTHON_VERSION_STRING})
find_package(PythonLibs REQUIRED)
find_package(OpenSSL REQUIRED)

add_subdirectory(python)
add_subdirectory(src)

install(FILES
	"doc/man/sslscan.1"
	DESTINATION "${CMAKE_INSTALL_FULL_MANDIR}/man1" COMPONENT doc)
