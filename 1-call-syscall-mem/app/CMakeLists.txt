project(app)

add_definitions(-std=c++11)

set(CXX_FLAGS "-Wall")
set(CMAKE_CXX_FLAGS "${CXX_FLAGS}")

set(sources src/PID.cpp src/main.cpp)

include_directories(/usr/local/include)
link_directories(/usr/local/lib)

add_executable(${PROJECT_NAME}
	${sources}
)

target_link_libraries(${PROJECT_NAME}
	PRIVATE
	syscall-stats  z ssl uv uWS
)
