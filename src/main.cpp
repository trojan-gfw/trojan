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
#include "service.h"
#include "version.h"
using namespace std;

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
    Log::log("Welcome to trojan " + Version::get_version(), Log::FATAL);
    if (argc != 2) {
        Log::log(string("usage: ") + argv[0] + " config_file", Log::FATAL);
        exit(1);
    }
    signal(SIGINT, handleTermination);
    signal(SIGTERM, handleTermination);
#ifndef _WIN32
    signal(SIGHUP, restartService);
#endif // _WIN32
    Config config;
    try {
        do {
            restart = false;
            config.load(argv[1]);
            service = new Service(config);
            service->run();
            delete service;
            if (restart) {
                Log::log_with_date_time("trojan service restarting. . . ", Log::FATAL);
            }
        } while (restart);
        return 0;
    } catch (const exception &e) {
        Log::log_with_date_time(string("fatal: ") + e.what(), Log::FATAL);
        Log::log_with_date_time("exiting. . . ", Log::FATAL);
        exit(1);
    }
}
