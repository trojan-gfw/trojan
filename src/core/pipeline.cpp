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
#include "session/clientsession.h"

using namespace std;
using namespace boost::asio::ip;

uint32_t Pipeline::s_pipeline_id_counter = 0;

Pipeline::Pipeline(const Config& config, boost::asio::io_context& io_context, boost::asio::ssl::context &ssl_context):
    destroyed(false),
    out_socket(io_context,ssl_context),
    connected(false),
    sent_data_length(0),
    sent_data_speed(0),
    resolver(io_context),
    config(config){
    sent_data_former_time = time(NULL);
    pipeline_id = s_pipeline_id_counter++;
}

void Pipeline::start(){
    auto self = shared_from_this();
    connect_remote_server_ssl(this, config.remote_addr, to_string(config.remote_port), resolver, out_socket, tcp::endpoint(), [this, self](){
        connected = true;

        string data(config.password.cbegin()->first);
        data += "\r\n";
        data += cache_out_send_data;
        
        _log_with_date_time("pipeline " + to_string(get_pipeline_id()) + " is going to connect remote server and send password...");

        if(cache_out_send_data.length() == 0){
            async_send_data(data, [](boost::system::error_code){});
        }else{
            async_send_data(data, cache_out_sent_handler);
            cache_out_send_data = "";
        }

        out_async_recv();
    });
}

void Pipeline::async_send_data(const std::string& data, function<void(boost::system::error_code ec)> sent_handler){
    if(!connected){
        cache_out_send_data += data;
        cache_out_sent_handler = sent_handler;
        _log_with_date_time("pipeline " + to_string(get_pipeline_id()) + " haven't connected, cache data length:" + to_string(cache_out_send_data.length()));
    }else{
        auto self = shared_from_this();
        auto data_copy = make_shared<string>(data);
        boost::asio::async_write(out_socket, boost::asio::buffer(*data_copy), [this, self, data_copy, sent_handler](const boost::system::error_code error, size_t) {
            if (error) {
                output_debug_info_ec(error);
                destroy();
            }else{
                auto current_time = time(NULL);
                if(current_time - sent_data_former_time > STAT_SENT_DATA_SPEED_INTERVAL){
                    sent_data_speed = sent_data_length / (current_time - sent_data_former_time);
                    sent_data_former_time = current_time;
                    sent_data_length = 0;
                }
                sent_data_length += data_copy->length();
            }
              
            sent_handler(error);
        });
    }    
}

void Pipeline::session_async_send_cmd(PipelineRequest::Command cmd, Session& session, const std::string& send_data, function<void(boost::system::error_code ec)> sent_handler){
    if(destroyed){
        sent_handler(boost::asio::error::broken_pipe);
        return;
    }
    _log_with_date_time("pipeline " + to_string(get_pipeline_id()) + " send to server cmd: " +  PipelineRequest::get_cmd_string(cmd) + " session_id: " + to_string(session.session_id) + " data length:" + to_string(send_data.length()));
    async_send_data(PipelineRequest::generate(cmd, session.session_id, send_data), sent_handler);
}

void Pipeline::session_start(Session& session, function<void(boost::system::error_code ec)> started_handler){
    sessions.emplace_back(session.shared_from_this());
    session_async_send_cmd(PipelineRequest::CONNECT, session, "", started_handler);
}

void Pipeline::session_destroyed(Session& session){
    if(!destroyed){    
        auto it = sessions.begin();
        while(it != sessions.end()){
            if(it->get() == &session){
                it = sessions.erase(it);
            }else{
                ++it;
            }            
        }
        _log_with_date_time("pipeline " + to_string(get_pipeline_id()) + " send command to close session_id: " + to_string(session.session_id));
        session_async_send_cmd(PipelineRequest::CLOSE, session, "", [](boost::system::error_code){});
    }
}

bool Pipeline::is_in_pipeline(Session& session){
    auto it = sessions.begin();
    while(it != sessions.end()){
        if(it->get() == &session){
            return true;
        }else{
            ++it;
        }        
    }

    return false;
}

void Pipeline::out_async_recv(){
    auto self = shared_from_this();
    out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (error) {
            output_debug_info_ec(error);
            destroy();
        }else{
            out_read_data += string((const char*)out_read_buf, length);

            while(!out_read_data.empty()){
                PipelineRequest req;
                int ret = req.parse(out_read_data);
                if(ret == -1){
                    break;
                }

                if(ret == -2){
                    output_debug_info();
                    destroy();
                    return;
                }

                _log_with_date_time("pipeline " + to_string(get_pipeline_id()) + " recv from server cmd: " + req.get_cmd_string() + " session_id: " + to_string(req.session_id) + " data length:" + to_string(req.packet_data.length()));
                
                bool found = false;
                auto it = sessions.begin();
                while(it != sessions.end()){
                    auto session = it->get();
                    if(session->session_id == req.session_id){
                        if(req.command == PipelineRequest::CLOSE){
                            session->destroy(true);
                            it = sessions.erase(it);
                        }else if(req.command == PipelineRequest::ACK){
                            if(session->is_udp_forward()){
                                _log_with_date_time("UDP don't need ACK command", Log::ERROR);
                            }else{
                                auto client = static_cast<ClientSession*>(session);
                                client->recv_ack_cmd();
                                if(client->is_wait_for_pipeline_ack()){
                                    client->in_async_read();
                                }
                            }
                        }else{
                            if(session->is_udp_forward()){
                                static_cast<UDPForwardSession*>(session)->out_recv(req.packet_data);
                            }else{
                                static_cast<ClientSession*>(session)->out_recv(req.packet_data);
                            }
                        }
                        found = true;
                        break;
                    }else{
                        ++it;
                    }
                    
                }
                
                if(!found){
                    _log_with_date_time("pipeline " + to_string(get_pipeline_id()) + " cannot find session:" + to_string(req.session_id) + " current sessions:" + to_string(sessions.size()));
                }
            }            

            out_async_recv();
        }
    });
}

void Pipeline::destroy(){
    if(destroyed){
        return;
    }
    destroyed = true;
    _log_with_date_time("pipeline " + to_string(get_pipeline_id()) + " destroyed. close all " + to_string(sessions.size()) + " sessions in this pipeline.");

    // close all sessions
    for(auto it = sessions.begin(); it != sessions.end(); ++it){
        auto session = it->get();
        session->destroy(true);
    }
    sessions.clear();
    shutdown_ssl_socket(this, out_socket);
}