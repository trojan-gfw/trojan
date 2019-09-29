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

#include "trojanrequest.h"
using namespace std;

int TrojanRequest::parse(const string &data) {
    size_t first = data.find("\r\n");
    if (first == string::npos) {
        return -1;
    }
    password = data.substr(0, first);
    payload = data.substr(first + 2);
    if (payload.length() == 0 || (payload[0] != CONNECT && payload[0] != UDP_ASSOCIATE)) {
        return -1;
    }
    command = static_cast<Command>(payload[0]);
    int address_len = address.parse(payload.substr(1));
    if (address_len == -1 || payload.length() < (unsigned int)address_len + 3 || payload.substr(address_len + 1, 2) != "\r\n") {
        return -1;
    }
    payload = payload.substr(address_len + 3);
    return data.length();
}

std::string TrojanRequest::generate(const std::string &password, const std::string &domainname, uint16_t port, bool tcp) {
    string ret = password + "\r\n";
    if (tcp) {
        ret += '\x01';
    } else {
        ret += '\x03';
    }
    ret += '\x03';
    ret += char(uint8_t(domainname.length()));
    ret += domainname;
    ret += char(uint8_t(port >> 8));
    ret += char(uint8_t(port & 0xFF));
    ret += "\r\n";
    return ret;
}
