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

#ifndef ICMP_HEADER_HPP
#define ICMP_HEADER_HPP

#include <algorithm>
#include <istream>
#include <ostream>

// ICMP header for both IPv4 and IPv6.
//
// The wire format of an ICMP header is:
//
// 0               8               16                             31
// +---------------+---------------+------------------------------+      ---
// |               |               |                              |       ^
// |     type      |     code      |          checksum            |       |
// |               |               |                              |       |
// +---------------+---------------+------------------------------+    8 bytes
// |                               |                              |       |
// |          identifier           |       sequence number        |       |
// |                               |                              |       v
// +-------------------------------+------------------------------+      ---

class icmp_header {
public:
    enum {
        echo_reply = 0,
        destination_unreachable = 3,
        source_quench = 4,
        redirect = 5,
        echo_request = 8,
        time_exceeded = 11,
        parameter_problem = 12,
        timestamp_request = 13,
        timestamp_reply = 14,
        info_request = 15,
        info_reply = 16,
        address_request = 17,
        address_reply = 18
    };

    enum{
        HEADER_LENGTH = 8
    };

    icmp_header() { std::fill(rep_, rep_ + sizeof(rep_), 0); }
    const uint8_t *raw() { return rep_; }
    
    uint8_t type() const { return rep_[0]; }
    uint8_t code() const { return rep_[1]; }
    uint16_t checksum() const { return decode(2, 3); }

    std::string to_string() const {
        std::ostringstream os;
        os << "type: " << (int)type() << std::endl
           << "code: " << (int)code() << std::endl
           << "checksum: 0x" << std::hex << (int)checksum() << std::endl;
        return os.str();
    }

    // following functions are used for ping type
    uint16_t identifier() const { return decode(4, 5); }
    uint16_t sequence_number() const { return decode(6, 7); }

    void type(uint8_t n) { rep_[0] = n; }
    void code(uint8_t n) { rep_[1] = n; }
    void checksum(uint16_t n) { encode(2, 3, n); }
    void identifier(uint16_t n) { encode(4, 5, n); }
    void sequence_number(uint16_t n) { encode(6, 7, n); }

    friend std::istream &operator>>(std::istream &is, icmp_header &header) {
        return is.read(reinterpret_cast<char *>(header.rep_), HEADER_LENGTH);
    }

    friend std::ostream &operator<<(std::ostream &os, const icmp_header &header) {
        return os.write(reinterpret_cast<const char *>(header.rep_), HEADER_LENGTH);
    }

    void assign_checksum(std::string body) {
        unsigned int sum = (type() << 8) + code() + identifier() + sequence_number();

        auto body_iter = body.begin();
        while (body_iter != body.end()) {
            sum += (static_cast<uint8_t>(*body_iter++) << 8);
            if (body_iter != body.end())
                sum += static_cast<uint8_t>(*body_iter++);
        }

        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        checksum(static_cast<uint16_t>(~sum));
    }

    void assign_checksum() {
        unsigned int sum = (type() << 8) + code() + identifier() + sequence_number();
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        checksum(static_cast<uint16_t>(~sum));
    }

private:
    uint16_t decode(int a, int b) const {
        return (rep_[a] << 8) + rep_[b];
    }

    void encode(int a, int b, uint16_t n) {
        rep_[a] = static_cast<uint8_t>(n >> 8);
        rep_[b] = static_cast<uint8_t>(n & 0xFF);
    }

    uint8_t rep_[HEADER_LENGTH];
};

#endif  // ICMP_HEADER_HPP