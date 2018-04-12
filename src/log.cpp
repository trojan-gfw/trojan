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

#include "log.h"
#include <cstdio>
#include <sstream>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
using namespace std;
using namespace boost::posix_time;
using namespace boost::asio::ip;

Log::Level Log::level(INFO);

void Log::log(const string &message, Level level) {
    if (level >= Log::level) {
        fprintf(stderr, "%s\n", message.c_str());
    }
}

void Log::log_with_date_time(const string &message, Level level) {
    time_facet *facet = new time_facet("[%Y-%m-%d %H:%M:%S] ");
    ostringstream stream;
    stream.imbue(locale(stream.getloc(), facet));
    stream << second_clock::local_time();
    Log::log(stream.str() + message, level);
}

void Log::log_with_endpoint(const tcp::endpoint &endpoint, const string &message, Level level) {
    Log::log_with_date_time(endpoint.address().to_string() + ':' + to_string(endpoint.port()) + ' ' + message, level);
}
