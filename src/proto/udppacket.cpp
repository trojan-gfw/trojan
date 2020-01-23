/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2020  The Trojan Authors.
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

#include "udppacket.h"
using namespace std;
using namespace boost::asio::ip;

bool UDPPacket::parse(const string &data, size_t &udp_packet_len) {
    if (data.length() <= 0) {
        return false;
    }
    size_t address_len;
    bool is_addr_valid = address.parse(data, address_len);
    if (!is_addr_valid || data.length() < address_len + 2) {
        return false;
    }
    length = (uint8_t(data[address_len]) << 8) | uint8_t(data[address_len + 1]);
    if (data.length() < address_len + 4 + length || data.substr(address_len + 2, 2) != "\r\n") {
        return false;
    }
    payload = data.substr(address_len + 4, length);
    udp_packet_len = address_len + 4 + length;
    return true;
}

string UDPPacket::generate(const udp::endpoint &endpoint, const string &payload) {
    string ret = SOCKS5Address::generate(endpoint);
    ret += char(uint8_t(payload.length() >> 8));
    ret += char(uint8_t(payload.length() & 0xFF));
    ret += "\r\n";
    ret += payload;
    return ret;
}

string UDPPacket::generate(const string &domainname, uint16_t port, const string &payload) {
    string ret = "\x03";
    ret += char(uint8_t(domainname.length()));
    ret += domainname;
    ret += char(uint8_t(port >> 8));
    ret += char(uint8_t(port & 0xFF));
    ret += char(uint8_t(payload.length() >> 8));
    ret += char(uint8_t(payload.length() & 0xFF));
    ret += "\r\n";
    ret += payload;
    return ret;
}
