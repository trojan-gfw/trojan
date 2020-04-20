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

#include "pipelinerequest.h"
#include <string>

using namespace std;

static 
uint32_t parse_uint32(int start_pos, const string& data){
    return uint32_t(data[0 + start_pos]) << 24 | 
           uint32_t(data[1 + start_pos]) << 16 | 
           uint32_t(data[2 + start_pos]) << 8 | 
           uint32_t(data[3 + start_pos]);
}

static 
void generate_uint32(string& data, uint32_t value){
    data += char(value >> 24);
    data += char(value >> 16 & 0xff);
    data += char(value >> 8 & 0xff);
    data += char(value & 0xff);
}

int PipelineRequest::parse(std::string &data){
    /*
        |-------------------|-------------------|-----------------------|---------------------|
        | 4 bytes as length | 1 byte as command | 4 bytes as session id | trojan request data |
        |-------------------|-------------------|-----------------------|---------------------|
    */
    const uint32_t HEADER_LENGTH = 9;

    if(data.length() < HEADER_LENGTH){
        return -1;
    }

    uint32_t trojan_request_length = parse_uint32(0, data);
    
    if(data.size() < HEADER_LENGTH + trojan_request_length){
        return -1;
    }

    uint8_t cmd = data[4];
    bool compress = (cmd & 0x80) != 0;
    cmd = cmd & 0x7f;

    if(cmd >= (MAX_COMMANDS)){
        return -2;
    }

    command = (Command) cmd;

    session_id = parse_uint32(5, data);

    if(compress){
        // TODO compress
    }else{
        packet_data = data.substr(HEADER_LENGTH, HEADER_LENGTH + trojan_request_length);
    }

    data = data.substr(HEADER_LENGTH + trojan_request_length);

    return packet_data.length();
}

std::string PipelineRequest::generate(enum Command cmd, uint32_t session_id, const std::string& data){
    size_t length = data.size();
    string ret_data;
    generate_uint32(ret_data, length);

    // TODO compress

    ret_data += char(cmd);
    
    generate_uint32(ret_data, session_id);

    ret_data += data;

    return ret_data;
}