/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2018  GreaterFire
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

Service *service;
bool restart;

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
            ("config,c", po::value<string>(&config_file)->default_value(DEFAULT_CONFIG)->value_name("CONFIG"), "specify config file")
            ("help,h", "print help message")
            ("keylog,k", po::value<string>(&keylog_file)->value_name("KEYLOG"), "specify keylog file location (OpenSSL >= 1.1.1)")
            ("log,l", po::value<string>(&log_file)->value_name("LOG"), "specify log file location")
            ("test,t", po::bool_switch(&test), "test config file")
            ("version,v", "print version and build info")
        ;
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
