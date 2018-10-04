cmake_minimum_required(VERSION 3.1)
project(trojan)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_STANDARD 11)
if(NOT MSVC)
    add_definitions(-Wall -Wextra)
endif()
set(THREADS_PREFER_PTHREAD_FLAG ON)
add_executable(trojan
    src/authenticator.cpp
    src/clientsession.cpp
    src/config.cpp
    src/forwardsession.cpp
    src/log.cpp
    src/main.cpp
    src/serversession.cpp
    src/service.cpp
    src/session.cpp
    src/socks5address.cpp
    src/ssldefaults.cpp
    src/sslsession.cpp
    src/trojanrequest.cpp
    src/udppacket.cpp
    src/version.cpp)
find_package(Threads REQUIRED)
target_link_libraries(trojan ${CMAKE_THREAD_LIBS_INIT})
find_package(Boost 1.54.0 REQUIRED COMPONENTS system program_options)
include_directories(${Boost_INCLUDE_DIR})
target_link_libraries(trojan ${Boost_LIBRARIES})
if(MSVC)
    add_definitions(-DBOOST_DATE_TIME_NO_LIB)
endif()
find_package(OpenSSL 1.0.2 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(trojan ${OPENSSL_LIBRARIES})
option(ENABLE_MYSQL "Build with MySQL support" ON)
if(ENABLE_MYSQL)
    find_package(MySQL REQUIRED)
    include_directories(${MYSQL_INCLUDE_DIR})
    target_link_libraries(trojan ${MYSQL_LIBRARIES})
    add_definitions(-DENABLE_MYSQL)
endif()
if(WIN32)
    target_link_libraries(trojan wsock32 ws2_32 crypt32)
else()
    set(SYSTEMD_SERVICE AUTO CACHE STRING "Install systemd service")
    set_property(CACHE SYSTEMD_SERVICE PROPERTY STRINGS AUTO ON OFF)
    set(SYSTEMD_SERVICE_PATH /lib/systemd/system CACHE PATH "Systemd service path")
    include(GNUInstallDirs)
    install(TARGETS trojan DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES examples/server.json-example DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/trojan RENAME config.json)
    add_definitions(-DDEFAULT_CONFIG="${CMAKE_INSTALL_FULL_SYSCONFDIR}/trojan/config.json")
    install(FILES docs/trojan.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
    install(DIRECTORY docs/ DESTINATION ${CMAKE_INSTALL_DOCDIR} FILES_MATCHING PATTERN "*.md")
    install(DIRECTORY examples DESTINATION ${CMAKE_INSTALL_DOCDIR} FILES_MATCHING PATTERN "*.json-example")
    if(SYSTEMD_SERVICE STREQUAL AUTO)
        if(EXISTS /usr/lib/systemd/system)
            set(SYSTEMD_SERVICE ON)
            set(SYSTEMD_SERVICE_PATH /usr/lib/systemd/system CACHE PATH "Systemd service path" FORCE)
        elseif(EXISTS /lib/systemd/system)
            set(SYSTEMD_SERVICE ON)
            set(SYSTEMD_SERVICE_PATH /lib/systemd/system CACHE PATH "Systemd service path" FORCE)
        endif()
    endif()
    if(SYSTEMD_SERVICE STREQUAL ON)
        set(CONFIG_NAME config)
        configure_file(examples/trojan.service-example trojan.service)
        set(CONFIG_NAME %i)
        configure_file(examples/trojan.service-example trojan@.service)
        install(FILES ${CMAKE_BINARY_DIR}/trojan.service ${CMAKE_BINARY_DIR}/trojan@.service DESTINATION ${SYSTEMD_SERVICE_PATH})
    endif()
    enable_testing()
    add_test(NAME LinuxSmokeTest-basic
             COMMAND sh ${CMAKE_SOURCE_DIR}/tests/LinuxSmokeTest/basic.sh ${CMAKE_BINARY_DIR}/trojan
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests/LinuxSmokeTest)
    add_test(NAME LinuxSmokeTest-fake-client
             COMMAND sh ${CMAKE_SOURCE_DIR}/tests/LinuxSmokeTest/fake-client.sh ${CMAKE_BINARY_DIR}/trojan
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests/LinuxSmokeTest)
endif()
