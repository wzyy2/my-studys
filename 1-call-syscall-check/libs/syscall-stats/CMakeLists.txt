project(syscall-stats)

add_library(${PROJECT_NAME} SHARED
	syscall-stats.cpp
	syscall-stubs.cpp
	syscall-init.cpp
)

add_library(libs::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

set(CMAKE_CXX_FLAGS ${ADDITIONAL_CMAKE_CXX_FLAGS} " -fpermissive -fPIC -Wl,--no-as-needed")

target_link_libraries(${PROJECT_NAME}
	PUBLIC
	dl pthread rt
)

target_include_directories(${PROJECT_NAME}
	PUBLIC
		$<INSTALL_INTERFACE:include>
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(${PROJECT_NAME}
	PRIVATE
		cxx_std_11
)

# if(BUILD_TESTING)
# 	add_subdirectory(tests)
# endif()
