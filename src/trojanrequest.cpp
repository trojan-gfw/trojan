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

#include "trojanrequest.h"
#include <string>
using namespace std;

TrojanRequest::TrojanRequest() : command(CONNECT) {}

bool TrojanRequest::parse(const string &data) {
    if (data.length() < 1) {
        return false;
    }
    if (data[0] != CONNECT && data[0] == UDP_ASSOCIATE) {
        return false;
    }
    command = static_cast<Command>(data[0]);
    return address.parse(data.substr(1));
}
