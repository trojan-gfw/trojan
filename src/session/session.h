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

#ifndef _SESSION_H_
#define _SESSION_H_

#include <ctime>
#include <set>
#include <memory>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include "core/config.h"

class Service;
class Session : public std::enable_shared_from_this<Session> {

public:
    typedef uint16_t SessionIdType;
    enum {
        MAX_BUF_LENGTH = 8192,
    };

private:

    // session id counter for pipeline mode
    static SessionIdType s_session_id_counter;
    static std::set<SessionIdType>  s_session_used_ids;

protected:
    
    uint8_t in_read_buf[MAX_BUF_LENGTH]{};
    uint8_t out_read_buf[MAX_BUF_LENGTH]{};
    uint8_t udp_read_buf[MAX_BUF_LENGTH]{};
    uint64_t recv_len;
    uint64_t sent_len;
    time_t start_time{};
    std::string out_write_buf;
    std::string udp_data_buf;
    boost::asio::ip::tcp::resolver resolver;
    
    boost::asio::ip::udp::socket udp_socket;
    boost::asio::ip::udp::endpoint udp_recv_endpoint;
    Service* pipeline_client_service;
    bool is_udp_forward_session;
    int pipeline_ack_counter;
    bool pipeline_wait_for_ack;
    bool pipeline_first_call_ack;

    void allocate_session_id();
    void free_session_id();
public:
    Session(const Config &config, boost::asio::io_context &io_context);
    virtual boost::asio::ip::tcp::socket& accept_socket() = 0;
    virtual void start() = 0;
    virtual ~Session();
    virtual void destroy(bool pipeline_call = false) = 0;
    const Config &config;
    boost::asio::ip::tcp::endpoint in_endpoint;

    SessionIdType session_id;
    inline void set_use_pipeline(Service* service, bool is_udp_forward) { 
        pipeline_client_service = service; 
        is_udp_forward_session = is_udp_forward;
    };
    inline bool is_udp_forward()const { return is_udp_forward_session; }
    inline void recv_ack_cmd(){ pipeline_ack_counter++;}
    inline bool is_wait_for_pipeline_ack()const { return pipeline_wait_for_ack; }

    inline bool pre_call_ack_func(){
        if(!pipeline_first_call_ack){
            if(pipeline_ack_counter <= 0){
                pipeline_wait_for_ack = true;
                return false;
            }
            pipeline_ack_counter--;
        }
        pipeline_wait_for_ack = false;
        pipeline_first_call_ack = false;
        return true;
    }
};

#endif // _SESSION_H_
