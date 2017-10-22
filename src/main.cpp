/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism to bypass GFW.
 * Copyright (C) 2017  GreaterFire
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
#include <string>
#include <iostream>
#include "log.h"
#include "config.h"
#include "service.h"
#include "version.h"
using namespace std;

int main(int argc, const char *argv[]) {
    puts(("Welcome to trojan " + Version::get_version()).c_str());
    if (argc != 2) {
        Log::log(string("usage: ") + argv[0] + " config_file");
        exit(1);
    }
    Config config;
    try {
        config.load(argv[1]);
        Service service(config);
        return service.run();
    } catch (const exception &e) {
        Log::log_with_date_time(string("fatal: ") + e.what());
        Log::log_with_date_time("exiting. . . ");
        exit(1);
    }
}
