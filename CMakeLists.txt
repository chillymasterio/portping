cmake_minimum_required(VERSION 3.10)
project(portping LANGUAGES C)

set(CMAKE_C_STANDARD 99)

add_executable(portping portping.c)

if(WIN32)
    target_link_libraries(portping ws2_32)
else()
    target_link_libraries(portping m)
endif()

install(TARGETS portping DESTINATION bin)
install(FILES portping.1 DESTINATION share/man/man1)
