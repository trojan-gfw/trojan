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
#include <vector>
#include <functional>
#include <time.h>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "proto/pipelinerequest.h"
#include "core/config.h"
#include "session/session.h"
#include "core/icmpd.h"

class Pipeline : public std::enable_shared_from_this<Pipeline> {

public:

    typedef std::function<void(const boost::system::error_code ec)> SentHandler;
    typedef std::function<void(const std::string& data, SentHandler handler)> AsyncWriter;
    typedef std::function<bool()> ConnectionFunc;

    typedef std::function<void(const std::string& data)> ReadHandler;


    class SendDataCache{
        std::vector<SentHandler> handler_queue;
        std::string data_queue;

        std::string sending_data_buff;
        std::vector<SentHandler> sending_data_handler;

        bool is_async_sending;
        AsyncWriter async_writer;
        ConnectionFunc is_connected;

    public: 
        SendDataCache() : is_async_sending(false) {
            is_connected = []() { return true; };
        }

        inline void set_async_writer(AsyncWriter&& writer){
            async_writer = std::move(writer);
        }

        inline void set_is_connected_func(ConnectionFunc&& func){
            is_connected = std::move(func);
        }

        inline void insert_data(std::string&& data) {
            data_queue = data + data_queue;
            async_send();
        }

        inline void push_data(std::string&& data, SentHandler&& handler) {
            data_queue += data;
            handler_queue.emplace_back(std::move(handler));
            async_send();
        }

        inline void async_send(){
            if (data_queue.empty() || !is_connected() || is_async_sending) {
                return;
            }

            is_async_sending = true;

            sending_data_buff = data_queue;
            data_queue.clear();

            std::move(handler_queue.begin(), handler_queue.end(), std::back_inserter(sending_data_handler));
            handler_queue.clear();

            async_writer(sending_data_buff, [this](const boost::system::error_code ec) {
                is_async_sending = false;

                if (!ec) {
                    for (size_t i = 0;i < sending_data_handler.size();i++) {
                        sending_data_handler[i](ec);
                    }
                    sending_data_handler.clear();
                    async_send();
                }
            });
        }
    };

    class ReadDataCache{
        std::list<std::string> data_queue;
        ReadHandler read_handler;
        bool is_waiting;
    public :
        ReadDataCache(): is_waiting(false){}
        inline void push_data(std::string&& data) {
            if (is_waiting) {
                read_handler(data);
                is_waiting = false;
            }else{
                data_queue.emplace_back(std::move(data));
            }
        }

        inline void async_read(ReadHandler&& handler) {
            if (data_queue.empty()) {
                is_waiting = true;
                read_handler = std::move(handler);
            }else{
                handler(data_queue.front());
                data_queue.pop_front();
            }
        }
    };

private:

    enum {
        MAX_BUF_LENGTH = 8192,
        STAT_SENT_DATA_SPEED_INTERVAL = 5
    };

    static uint32_t s_pipeline_id_counter;

    SendDataCache sending_data_cache;
    bool destroyed;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>out_socket;
    bool connected;
    bool is_async_sending;
    char out_read_buf[MAX_BUF_LENGTH];
    std::string out_read_data;
    boost::asio::ip::tcp::resolver resolver; 
    std::vector<std::shared_ptr<Session>> sessions;
    uint32_t pipeline_id;
    std::shared_ptr<icmpd> icmp_processor;
    boost::asio::ip::tcp::endpoint out_socket_endpoint;

    void out_async_recv();
public:

    Pipeline(const Config& config, boost::asio::io_context& io_context, boost::asio::ssl::context &ssl_context);
    void start();
    void destroy();
    const Config& config;

    void session_start(Session& session,  SentHandler&& started_handler);
    void session_async_send_cmd(PipelineRequest::Command cmd, Session& session, const std::string& send_data, SentHandler&& sent_handler);
    void session_async_send_icmp(const std::string& send_data, SentHandler&& sent_handler);
    void session_destroyed(Session& session);

    inline bool is_connected()const { return connected; }
    bool is_in_pipeline(Session& session);
    
    uint32_t get_pipeline_id()const{ return pipeline_id; }

    void set_icmpd(std::shared_ptr<icmpd> icmp){ icmp_processor = icmp; }
    boost::asio::ip::tcp::endpoint get_out_socket_endpoint() const { return out_socket_endpoint;}
};

#endif // _PIPELINE_H_
