/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2019  GreaterFire
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cstdlib>
#include <csignal>
#include <iostream>
#include <boost/program_options.hpp>
#include <boost/version.hpp>
#include <openssl/opensslv.h>

#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef ENABLE_MYSQL
#include <mysql.h>
#endif // ENABLE_MYSQL

#include "service.h"
#include "version.h"

using namespace std;
namespace po = boost::program_options;

#ifndef DEFAULT_CONFIG
#define DEFAULT_CONFIG "config.json"
#endif // DEFAULT_CONFIG

#ifndef DEFAULT_PAC_CONFIG
#define DEFAULT_PAC_CONFIG "pac.conf"
#endif // DEFAULT_PAC_CONFIG
char *pac_fcontent = NULL;

int startPacServer(uint16_t pacServerPort, std::string pac_server_flag, std::string local_addr, uint16_t localSockPort);

Service *service;
bool restart;
uint16_t pac_local_port;

void handleTermination(int) {
    service->stop();
}

void restartService(int) {
    restart = true;
    service->stop();
}

int main(int argc, const char *argv[]) {
    try {
        Log::log("Welcome to trojan " + Version::get_version(), Log::FATAL);
        string config_file;
        string log_file;
        string keylog_file;
        bool test;
        po::options_description desc("options");
        desc.add_options()
                ("config,c", po::value<string>(&config_file)->default_value(DEFAULT_CONFIG)->value_name("CONFIG"),
                 "specify config file")
                ("help,h", "print help message")
                ("keylog,k", po::value<string>(&keylog_file)->value_name("KEYLOG"),
                 "specify keylog file location (OpenSSL >= 1.1.1)")
                ("log,l", po::value<string>(&log_file)->value_name("LOG"), "specify log file location")
                ("test,t", po::bool_switch(&test), "test config file")
                ("version,v", "print version and build info");
        po::positional_options_description pd;
        pd.add("config", 1);
        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).options(desc).positional(pd).run(), vm);
        po::notify(vm);
        if (vm.count("help")) {
            Log::log(string("usage: ") + argv[0] + " [-htv] [-l LOG] [-k KEYLOG] [[-c] CONFIG]", Log::FATAL);
            cerr << desc;
            exit(EXIT_SUCCESS);
        }
        if (vm.count("version")) {
            Log::log(string("Boost ") + BOOST_LIB_VERSION + ", " + OPENSSL_VERSION_TEXT, Log::FATAL);
#ifdef ENABLE_MYSQL
            Log::log(string(" [Enabled] MySQL Support (") + mysql_get_client_info() + ')', Log::FATAL);
#else // ENABLE_MYSQL
            Log::log("[Disabled] MySQL Support", Log::FATAL);
#endif // ENABLE_MYSQL
#ifdef TCP_FASTOPEN
            Log::log(" [Enabled] TCP_FASTOPEN Support", Log::FATAL);
#else // TCP_FASTOPEN
            Log::log("[Disabled] TCP_FASTOPEN Support", Log::FATAL);
#endif // TCP_FASTOPEN
#ifdef TCP_FASTOPEN_CONNECT
            Log::log(" [Enabled] TCP_FASTOPEN_CONNECT Support", Log::FATAL);
#else // TCP_FASTOPEN_CONNECT
            Log::log("[Disabled] TCP_FASTOPEN_CONNECT Support", Log::FATAL);
#endif // TCP_FASTOPEN_CONNECT
#if ENABLE_SSL_KEYLOG
            Log::log(" [Enabled] SSL KeyLog Support", Log::FATAL);
#else // ENABLE_SSL_KEYLOG
            Log::log("[Disabled] SSL KeyLog Support", Log::FATAL);
#endif // ENABLE_SSL_KEYLOG
            exit(EXIT_SUCCESS);
        }
        if (vm.count("log")) {
            Log::redirect(log_file);
        }
        if (vm.count("keylog")) {
            Log::redirect_keylog(keylog_file);
        }
        Config config;
        do {
            restart = false;
            if (config.sip003()) {
                Log::log_with_date_time("SIP003 is loaded", Log::FATAL);
            } else {
                config.load(config_file);
            }
            pac_local_port = config.local_port;
            service = new Service(config, test);
            if (test) {
                Log::log("The config file looks good.", Log::OFF);
                exit(EXIT_SUCCESS);
            }
            signal(SIGINT, handleTermination);
            signal(SIGTERM, handleTermination);
#ifndef _WIN32
            signal(SIGHUP, restartService);
#endif // _WIN32

            // start pac http server

            int pacServerStat = startPacServer(config.pac_server_port, config.pac_server_flag, config.local_addr,
                                               config.local_port);
            if (pacServerStat != 0) {
                Log::log_with_date_time("Pac server failed to open.", Log::FATAL);
            } else {
                Log::log_with_date_time("Start PAC Server : http://127.0.0.1:" + std::to_string(config.pac_server_port), Log::INFO);
            }

            service->run();
            delete service;
            if (restart) {
                Log::log_with_date_time("trojan service restarting. . . ", Log::FATAL);
            }
        } while (restart);
        Log::reset();
        exit(EXIT_SUCCESS);
    } catch (const exception &e) {
        Log::log_with_date_time(string("fatal: ") + e.what(), Log::FATAL);
        Log::log_with_date_time("exiting. . . ", Log::FATAL);
        exit(EXIT_FAILURE);
    }
}

char *createPacPage(const char *fileUri) {

    FILE *fp;
    fp = fopen(fileUri, "r");
    char *fcontent = NULL;
    if (fp == NULL) {
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size) {
        fcontent = (char *) malloc(size * sizeof(char) + 100);
        int point = sprintf(fcontent, "var proxy = \"SOCKS5 127.0.0.1:%d\"; \n", pac_local_port);

        if (point > 0) {
            long readsize = fread(fcontent + point, 1, size, fp);
        }

    }
    fclose(fp);

    return fcontent;
}

static int
answer_to_connection(void *cls, struct MHD_Connection *connection,
                     const char *url, const char *method,
                     const char *version, const char *upload_data,
                     size_t *upload_data_size, void **con_cls) {


    if (pac_fcontent == NULL) {
        pac_fcontent = createPacPage(DEFAULT_PAC_CONFIG);
    }

    struct MHD_Response *response;
    int ret;

    response =
            MHD_create_response_from_buffer(strlen(pac_fcontent), (void *) pac_fcontent,
                                            MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);

    return ret;
}

int
startPacServer(uint16_t pacServerPort, std::string pac_server_flag, std::string local_addr, uint16_t localSockPort) {

    struct MHD_Daemon *daemon;

    daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, pacServerPort, NULL, NULL,
                              &answer_to_connection, NULL, MHD_OPTION_END);
    if (NULL == daemon)
        return -1;

    //getchar ();

    //MHD_stop_daemon (daemon);
    return 0;


}

