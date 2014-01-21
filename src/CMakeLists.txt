# Support multiple cmake version
# cmake 2.6: PYTHON_INCLUDE_PATH
# cmake 2.8: PYTHON_INCLUDE_DIRS

include_directories(
	${PYTHON_INCLUDE_PATH}
	${PYTHON_INCLUDE_DIRS}
	${CMAKE_SOURCE_DIR}/python
	${OPENSSL_INCLUDE_DIR}
)

set(sslscan_SRCS
	main.c
	main.h
	helper.c
	probe.c
)

add_executable (sslscan ${sslscan_SRCS})

# Support multiple cmake version
# cmake 2.6: PYTHON_LIBRARY
# cmake 2.8: PYTHON_LIBRARIES

target_link_libraries(sslscan
	${PYTHON_LIBRARY}
	${PYTHON_LIBRARIES}
	${OPENSSL_LIBRARIES}
)

install(TARGETS sslscan
	RUNTIME DESTINATION bin
)
