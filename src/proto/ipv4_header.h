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

#ifndef IPV4_HEADER_HPP
#define IPV4_HEADER_HPP

#include <iostream>
#include <algorithm>
#include <boost/asio/ip/address_v4.hpp>

// Packet header for IPv4.
//
// The wire format of an IPv4 header is:
//
// 0               8               16                             31
// +-------+-------+---------------+------------------------------+      ---
// |       |       |               |                              |       ^
// |version|header |    type of    |    total length in bytes     |       |
// |  (4)  | length|    service    |                              |       |
// +-------+-------+---------------+-+-+-+------------------------+       |
// |                               | | | |                        |       |
// |        identification         |0|D|M|    fragment offset     |       |
// |                               | |F|F|                        |       |
// +---------------+---------------+-+-+-+------------------------+       |
// |               |               |                              |       |
// | time to live  |   protocol    |       header checksum        |   20 bytes
// |               |               |                              |       |
// +---------------+---------------+------------------------------+       |
// |                                                              |       |
// |                      source IPv4 address                     |       |
// |                                                              |       |
// +--------------------------------------------------------------+       |
// |                                                              |       |
// |                   destination IPv4 address                   |       |
// |                                                              |       v
// +--------------------------------------------------------------+      ---
// |                                                              |       ^
// |                                                              |       |
// /                        options (if any)                      /    0 - 40
// /                                                              /     bytes
// |                                                              |       |
// |                                                              |       v
// +--------------------------------------------------------------+      ---

class ipv4_header {
   public:
    enum {
        HEADER_FIXED_LENGTH = 20,
        HEADER_OPTIONS_LENGTH = 40,
        HEADER_MAX_LENGTH = HEADER_FIXED_LENGTH + HEADER_OPTIONS_LENGTH
    };

    ipv4_header() { clear(); }
    void clear() { std::fill(rep_, rep_ + sizeof(rep_), 0); }
    const unsigned char* raw(){ return rep_; }    

    unsigned char version() const { return (rep_[0] >> 4) & 0xF; }
    unsigned short header_length() const { return (rep_[0] & 0xF) * 4; }
    unsigned char type_of_service() const { return rep_[1]; }
    unsigned short total_length() const { return decode(2, 3); }
    unsigned short identification() const { return decode(4, 5); }
    bool dont_fragment() const { return (rep_[6] & 0x40) != 0; }
    bool more_fragments() const { return (rep_[6] & 0x20) != 0; }
    unsigned short fragment_offset() const { return decode(6, 7) & 0x1FFF; }
    unsigned int time_to_live() const { return rep_[8]; }
    unsigned char protocol() const { return rep_[9]; }
    unsigned short header_checksum() const { return decode(10, 11); }

    std::string to_string()const{
        std::ostringstream os;
        os << "version: " << (int)version() << std::endl
           << "header_length: " << (int)header_length() << std::endl
           << "type_of_service: " << (int)type_of_service() << std::endl
           << "total_length: " << (int)total_length() << std::endl
           << "identification: " << (int)identification() << std::endl
           << "dont_fragment: " << (int)dont_fragment() << std::endl
           << "more_fragments: " << (int)more_fragments() << std::endl
           << "fragment_offset: " << (int)fragment_offset() << std::endl
           << "time_to_live: " << (int)time_to_live() << std::endl
           << "protocol: " << (int)protocol() << std::endl
           << "header_checksum: 0x" << std::hex << (int)header_checksum() << std::endl;
        return os.str();
    }

    void time_to_live(uint8_t v) { rep_[8] = v; }
    void identification(unsigned short v) { encode(4, 5, v); }
    void header_checksum(unsigned short v) { return encode(10, 11, v); }
    void total_length(unsigned short v) { return encode(2, 3, v); }

    boost::asio::ip::address_v4 source_address() const {
        boost::asio::ip::address_v4::bytes_type bytes = {{rep_[12], rep_[13], rep_[14], rep_[15]}};
        return boost::asio::ip::address_v4(bytes);
    }

    boost::asio::ip::address_v4 destination_address() const {
        boost::asio::ip::address_v4::bytes_type bytes = {{rep_[16], rep_[17], rep_[18], rep_[19]}};
        return boost::asio::ip::address_v4(bytes);
    }
    void source_address(const boost::asio::ip::address_v4& addr) {
        auto bytes = addr.to_bytes();
        rep_[12] = bytes[0];
        rep_[13] = bytes[1];
        rep_[14] = bytes[2];
        rep_[15] = bytes[3];
    }

    void destination_address(const boost::asio::ip::address_v4 &addr) {
        auto bytes = addr.to_bytes();
        rep_[16] = bytes[0];
        rep_[17] = bytes[1];
        rep_[18] = bytes[2];
        rep_[19] = bytes[3];
    }

    friend std::istream &operator>>(std::istream &is, ipv4_header &header) {
        is.read(reinterpret_cast<char *>(header.rep_), HEADER_FIXED_LENGTH);
        if (header.version() != 4)
            is.setstate(std::ios::failbit);
        std::streamsize options_length = header.header_length() - HEADER_FIXED_LENGTH;
        if (options_length < 0 || options_length > HEADER_OPTIONS_LENGTH)
            is.setstate(std::ios::failbit);
        else
            is.read(reinterpret_cast<char *>(header.rep_) + HEADER_FIXED_LENGTH, options_length);
        return is;
    }

    friend std::ostream &operator<<(std::ostream &os, const ipv4_header &header) {
        os.write(reinterpret_cast<const char *>(header.rep_), HEADER_FIXED_LENGTH);
        auto options_length = header.header_length() - HEADER_FIXED_LENGTH;
        if (options_length < 0) {
            os.setstate(std::ios::failbit);
        }else{
            if (options_length > 0) {
                os.write(reinterpret_cast<const char *>(header.rep_) + HEADER_FIXED_LENGTH, options_length);
            }
        } 
        return os;
    }

    void assign_header_checksum(){
        header_checksum(0);

        unsigned int sum = 0;
        for (int i = 0; i < HEADER_FIXED_LENGTH; i += 2) {
            sum += static_cast<uint8_t>(rep_[i]) << 8;
            sum += static_cast<uint8_t>(rep_[i + 1]);
        }

        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        header_checksum(static_cast<uint16_t>(~sum));
    }

   private:
    unsigned short decode(int a, int b) const {
        return (rep_[a] << 8) + rep_[b];
    }

    void encode(int a, int b, unsigned short n) {
        rep_[a] = static_cast<unsigned char>(n >> 8);
        rep_[b] = static_cast<unsigned char>(n & 0xFF);
    }

    unsigned char rep_[HEADER_MAX_LENGTH];
};

#endif  // IPV4_HEADER_HPP