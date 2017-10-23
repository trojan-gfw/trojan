/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
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

#include "trojanrequest.h"
#include <cstdio>
#include <cstdint>
#include <string>
using namespace std;

TrojanRequest::TrojanRequest() : command(CONNECT),
                                 address_type(IPv4),
                                 address("0.0.0.0"),
                                 port(0) {}

bool TrojanRequest::parse(const string &data) {
    if (data.length() >= 2) {
        command = static_cast<Command>(data[0]);
        address_type = static_cast<AddressType>(data[1]);
        switch (address_type) {
            case IPv4: {
                if (data.length() == 8) {
                    address = to_string(uint8_t(data[2])) + '.' +
                              to_string(uint8_t(data[3])) + '.' +
                              to_string(uint8_t(data[4])) + '.' +
                              to_string(uint8_t(data[5]));
                    port = (uint8_t(data[6]) << 8) | uint8_t(data[7]);
                    return true;
                }
                break;
            }
            case DOMAINNAME: {
                if (data.length() == data[2] + 5) {
                    address = data.substr(3, data[2]);
                    port = (uint8_t(data[data[2] + 3]) << 8) | uint8_t(data[data[2] + 4]);
                    return true;
                }
                break;
            }
            case IPv6: {
                if (data.length() == 20) {
                    char t[40];
                    sprintf(t, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                            uint8_t(data[2]), uint8_t(data[3]), uint8_t(data[4]), uint8_t(data[5]),
                            uint8_t(data[6]), uint8_t(data[7]), uint8_t(data[8]), uint8_t(data[9]),
                            uint8_t(data[10]), uint8_t(data[11]), uint8_t(data[12]), uint8_t(data[13]),
                            uint8_t(data[14]), uint8_t(data[15]), uint8_t(data[16]), uint8_t(data[17]));
                    address = t;
                    port = (uint8_t(data[18]) << 8) | uint8_t(data[19]);
                    return true;
                }
                break;
            }
        }
    }
    return false;
}
