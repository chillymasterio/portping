cmake_minimum_required(VERSION 3.10)
project(portping VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)

add_executable(portping portping.c)

if(WIN32)
    target_link_libraries(portping ws2_32)
else()
    target_link_libraries(portping m)
endif()

install(TARGETS portping RUNTIME DESTINATION bin)
