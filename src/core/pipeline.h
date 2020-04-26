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

#ifndef _PIPELINE_H_
#define _PIPELINE_H_

#include <memory>
#include <deque>
#include <functional>
#include <time.h>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ip/tcp.hpp>
#include "proto/pipelinerequest.h"
#include "core/config.h"
#include "session/session.h"


class Pipeline : public std::enable_shared_from_this<Pipeline> {
public:
    typedef std::function<void(const boost::system::error_code ec)> SentHandler;

    class SendData{
    public:
        std::string send_data;
        SentHandler sent_handler;
        SendData(std::string data, SentHandler handler):send_data(data),sent_handler(handler){}
    };

private:
    enum {
        MAX_LENGTH = 8192,
        STAT_SENT_DATA_SPEED_INTERVAL = 5
    };

    static uint32_t s_pipeline_id_counter;   

    std::list<std::shared_ptr<SendData>> sending_data_cache;
    bool destroyed;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>out_socket;
    bool connected;
    bool is_async_sending;
    uint32_t sent_data_length;
    clock_t sent_data_former_time;
    uint32_t sent_data_speed;
    char out_read_buf[MAX_LENGTH];
    std::string out_read_data;
    boost::asio::ip::tcp::resolver resolver; 
    std::vector<std::shared_ptr<Session>> sessions;
    uint32_t pipeline_id;

    void out_async_recv();
    void out_async_send();
public:
    Pipeline(const Config& config, boost::asio::io_context& io_context, boost::asio::ssl::context &ssl_context);
    void start();
    void destroy();
    const Config& config;
    uint32_t get_sent_data_speed()const{ return sent_data_speed; }

    void session_start(Session& session,  SentHandler started_handler);
    void session_async_send_cmd(PipelineRequest::Command cmd, Session& session, const std::string& send_data, SentHandler sent_handler);
    void session_destroyed(Session& session);

    inline bool is_connected()const { return connected; }
    bool is_in_pipeline(Session& session);
    
    uint32_t get_pipeline_id()const{ return pipeline_id; }
};

#endif // _PIPELINE_H_
