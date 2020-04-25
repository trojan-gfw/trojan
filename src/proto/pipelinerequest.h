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


#ifndef _PIPELINEREQUEST_H_
#define _PIPELINEREQUEST_H_

#include <string>
#include <stdint.h>

class PipelineRequest {
public:
    std::string packet_data;
    uint32_t session_id;
    enum Command {
        CONNECT = 0,
        DATA,
        ACK,
        CLOSE,
        MAX_COMMANDS
    } command;
    int parse(std::string &data);
    inline std::string get_cmd_string() const { return get_cmd_string(command); }
    static inline std::string get_cmd_string(enum Command cmd){
        switch(cmd){
            case CONNECT: return "CONNECT";
            case DATA: return "DATA";
            case ACK: return "ACK";
            case CLOSE: return "CLOSE";
            default:return "UNKNOW!!";
        }
    }
    static std::string generate(enum Command cmd, uint32_t session_id, const std::string& data);
};

#endif // _PIPELINEREQUEST_H_