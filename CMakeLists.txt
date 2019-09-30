cmake_minimum_required(VERSION 3.7.2)
project(trojan)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_STANDARD 11)
if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
    add_definitions(-Wall -Wextra)
endif()

add_executable(trojan
    src/core/authenticator.cpp
    src/core/config.cpp
    src/core/log.cpp
    src/core/service.cpp
    src/core/version.cpp
    src/main.cpp
    src/proto/socks5address.cpp
    src/proto/trojanrequest.cpp
    src/proto/udppacket.cpp
    src/session/clientsession.cpp
    src/session/forwardsession.cpp
    src/session/natsession.cpp
    src/session/serversession.cpp
    src/session/session.cpp
    src/session/udpforwardsession.cpp
    src/ssl/ssldefaults.cpp
    src/ssl/sslsession.cpp)
include_directories(src)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(trojan ${CMAKE_THREAD_LIBS_INIT})

find_package(Boost 1.66.0 REQUIRED COMPONENTS system program_options)
include_directories(${Boost_INCLUDE_DIR})
target_link_libraries(trojan ${Boost_LIBRARIES})
if(MSVC)
    add_definitions(-DBOOST_DATE_TIME_NO_LIB)
endif()

find_package(OpenSSL 1.0.2 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(trojan ${OPENSSL_LIBRARIES})
if(OPENSSL_VERSION VERSION_GREATER_EQUAL 1.1.1)
    option(ENABLE_SSL_KEYLOG "Build with SSL KeyLog support" ON)
    if(ENABLE_SSL_KEYLOG)
        add_definitions(-DENABLE_SSL_KEYLOG)
    endif()
endif()

option(ENABLE_MYSQL "Build with MySQL support" ON)
if(ENABLE_MYSQL)
    find_package(MySQL REQUIRED)
    include_directories(${MYSQL_INCLUDE_DIR})
    target_link_libraries(trojan ${MYSQL_LIBRARIES})
    add_definitions(-DENABLE_MYSQL)
endif()

option(FORCE_TCP_FASTOPEN "Force build with TCP Fast Open support" OFF)
if(FORCE_TCP_FASTOPEN)
    add_definitions(-DTCP_FASTOPEN=23 -DTCP_FASTOPEN_CONNECT=30)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL Linux)
    option(ENABLE_NAT "Build with NAT support" ON)
    if(ENABLE_NAT)
        add_definitions(-DENABLE_NAT)
    endif()
endif()

if(WIN32)
    target_link_libraries(trojan wsock32 ws2_32 crypt32)
else()
    set(SYSTEMD_SERVICE AUTO CACHE STRING "Install systemd service")
    set_property(CACHE SYSTEMD_SERVICE PROPERTY STRINGS AUTO ON OFF)
    set(SYSTEMD_SERVICE_PATH /lib/systemd/system CACHE PATH "Systemd service path")
    if(SYSTEMD_SERVICE STREQUAL AUTO)
        if(EXISTS /usr/lib/systemd/system)
            set(SYSTEMD_SERVICE ON)
            set(SYSTEMD_SERVICE_PATH /usr/lib/systemd/system CACHE PATH "Systemd service path" FORCE)
        elseif(EXISTS /lib/systemd/system)
            set(SYSTEMD_SERVICE ON)
            set(SYSTEMD_SERVICE_PATH /lib/systemd/system CACHE PATH "Systemd service path" FORCE)
        endif()
    endif()

    include(GNUInstallDirs)
    install(TARGETS trojan DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES examples/server.json-example DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/trojan RENAME config.json)
    set(DEFAULT_CONFIG ${CMAKE_INSTALL_FULL_SYSCONFDIR}/trojan/config.json CACHE STRING "Default config path")
    add_definitions(-DDEFAULT_CONFIG="${DEFAULT_CONFIG}")
    install(FILES docs/trojan.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
    install(DIRECTORY docs/ DESTINATION ${CMAKE_INSTALL_DOCDIR} FILES_MATCHING PATTERN "*.md")
    install(DIRECTORY examples DESTINATION ${CMAKE_INSTALL_DOCDIR} FILES_MATCHING PATTERN "*.json-example")
    if(SYSTEMD_SERVICE STREQUAL ON)
        set(CONFIG_NAME config)
        configure_file(examples/trojan.service-example trojan.service)
        set(CONFIG_NAME %i)
        configure_file(examples/trojan.service-example trojan@.service)
        install(FILES ${CMAKE_BINARY_DIR}/trojan.service ${CMAKE_BINARY_DIR}/trojan@.service DESTINATION ${SYSTEMD_SERVICE_PATH})
    endif()

    enable_testing()
    add_test(NAME LinuxSmokeTest-basic
             COMMAND bash ${CMAKE_SOURCE_DIR}/tests/LinuxSmokeTest/basic.sh ${CMAKE_BINARY_DIR}/trojan)
    add_test(NAME LinuxSmokeTest-fake-client
             COMMAND bash ${CMAKE_SOURCE_DIR}/tests/LinuxSmokeTest/fake-client.sh ${CMAKE_BINARY_DIR}/trojan)
endif()
