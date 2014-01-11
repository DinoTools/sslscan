include_directories(
	${PYTHON_INCLUDE_DIRS}
	${CMAKE_SOURCE_DIR}/python
	${OPENSSL_INCLUDE_DIR}
)

set(sslscan_SRCS
	main.c
	helper.c
	helper.h
)

add_executable (sslscan ${sslscan_SRCS})

target_link_libraries(sslscan
	${PYTHON_LIBRARIES}
	${OPENSSL_LIBRARIES}
)

install(TARGETS sslscan
	RUNTIME DESTINATION bin
)
