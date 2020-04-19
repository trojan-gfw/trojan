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

#include "pipeline.h"
#include "proto/pipelinerequest.h"
#include "core/service.h"

using namespace std;
using namespace boost::asio::ip;

Pipeline::Pipeline(const Config& config, boost::asio::io_context& io_context, boost::asio::ssl::context &ssl_context):
    destroyed(false),
    config(config),
    out_socket(io_context,ssl_context),
    connected(false),
    sent_data_length(0),
    resolver(io_context){
}

void Pipeline::start(){
    auto self = shared_from_this();
    connect_remote_server(config, resolver, out_socket, this, tcp::endpoint(), [this, self](){
        connected = true;

        string data(config.password.cbegin()->first);
        data += "\r\n";
        data += cache_out_send_data;
        cache_out_send_data = "";

        async_send_data(data, cache_out_sent_handler);
        out_async_recv();
    });
}

void Pipeline::async_send_data(const std::string& data, function<void(boost::system::error_code ec)> sent_handler){
    if(!connected){
        cache_out_send_data += data;
        cache_out_sent_handler = sent_handler;
    }else{
        auto self = shared_from_this();
        auto data_copy = make_shared<string>(data);
        boost::asio::async_write(out_socket, boost::asio::buffer(*data_copy), [this, self, data_copy, sent_handler](const boost::system::error_code error, size_t) {
            if (error) {
                destroy();
            }else{
                sent_data_length += data_copy->length();
            }        
            sent_handler(error);
        });
    }    
}

void Pipeline::async_send_cmd(PipelineRequest::Command cmd, uint32_t session_id, const std::string& send_data, function<void(boost::system::error_code ec)> sent_handler){
    if(destroyed){
        sent_handler(boost::asio::error::broken_pipe);
        return;
    }
    async_send_data(PipelineRequest::generate(cmd, session_id, send_data), sent_handler);
}

void Pipeline::session_start(uint32_t session_id, function<void(boost::system::error_code ec)> started_handler){
    sessions.insert(session_id);
    async_send_cmd(PipelineRequest::CONNECT, session_id, "", started_handler);
}

void Pipeline::session_async_send(uint32_t session_id, const std::string& send_data, function<void(boost::system::error_code ec)> sent_handler){
    async_send_cmd(PipelineRequest::DATA, session_id, send_data, sent_handler);
}

void Pipeline::session_destroyed(uint32_t session_id){
    sessions.erase(session_id);
    async_send_cmd(PipelineRequest::CLOSE, session_id, "", [](boost::system::error_code){});
}

bool Pipeline::is_in_pipeline(Session& session)const{

}

void Pipeline::out_async_recv(){
    auto self = shared_from_this();
    out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (error) {
            destroy();
        }else{
            out_read_data += string((const char*)out_read_buf, length);
            PipelineRequest req;
            int ret = req.parse(out_read_data);
            if(ret == -1){
                out_async_recv();
                return;
            }

            if(ret == -2){
                destroy();
                return;
            }

            recv_handler(error, req.session_id, req.packet_data);
        }
    });
}


void Pipeline::destroy(){
    if(destroyed){
        return;
    }
    destroyed = true;
    Log::log("pipeline destroyed.", Log::INFO);

    // TODO
    shutdown_ssl_socket(this, out_socket);
}