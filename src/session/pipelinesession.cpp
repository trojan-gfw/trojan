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

#include "pipelinesession.h"
#include "serversession.h"
#include "proto/trojanrequest.h"
#include "core/authenticator.h"
#include "core/service.h"
#include <boost/asio/ssl.hpp>

using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

PipelineSession::PipelineSession(const Config &config, boost::asio::io_context &io_context, 
    boost::asio::ssl::context &ssl_context, Authenticator *auth, const std::string &plain_http_response):
    Session(config, io_context),
    status(HANDSHAKE),
    auth(auth),
    plain_http_response(plain_http_response),
    live_socket(io_context, ssl_context),
    gc_timer(io_context),
    io_context(io_context),
    ssl_context(ssl_context){
}

tcp::socket& PipelineSession::accept_socket(){
    return (tcp::socket&)live_socket.next_layer();
}

void PipelineSession::start(){
    boost::system::error_code ec;
    start_time = time(NULL);
    timer_async_wait();
    in_endpoint = live_socket.next_layer().remote_endpoint(ec);
    if (ec) {
        output_debug_info_ec(ec);
        destroy();
        return;
    }
    auto self = shared_from_this();
    live_socket.async_handshake(stream_base::server, [this, self](const boost::system::error_code error) {
        if (error) {
            _log_with_endpoint(in_endpoint, "SSL handshake failed: " + error.message(), Log::ERROR);
            if (error.message() == "http request" && plain_http_response != "") {
                recv_len += plain_http_response.length();
                boost::asio::async_write(accept_socket(), boost::asio::buffer(plain_http_response), [this, self](const boost::system::error_code ec, size_t) {
                    output_debug_info_ec(ec);
                    destroy();
                });
                return;
            }
            output_debug_info();
            destroy();
            return;
        }
        in_async_read();
    });
}

void PipelineSession::in_async_read(){
    auto self = shared_from_this();
    live_socket.async_read_some(boost::asio::buffer(in_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (error) {
            output_debug_info_ec(error);
            destroy();
            return;
        }
        in_recv(string((const char*)in_read_buf, length));
    });
}

void PipelineSession::in_recv(const string &data) {
    if(status == HANDSHAKE){
        int npos = data.find("\r\n");
        if(npos == -1){
            in_async_read();
            return;
        }

        if(data.substr(0, npos) != config.password.cbegin()->first){
            _log_with_endpoint(in_endpoint, "PipelineSession error password");
            destroy();
            return;
        }else{
            _log_with_endpoint(in_endpoint, "PipelineSession handshake done!");
        }

        gc_timer.cancel();
        status = STREAMING;
        in_recv_streaming_data += data.substr(npos + 2);
        process_streaming_data();
        
    }else if(status == STREAMING){
        in_recv_streaming_data += data;
        process_streaming_data();
    }
}

void PipelineSession::in_send(PipelineRequest::Command cmd, ServerSession& session, const std::string& session_data, std::function<void()> sent_handler){
    auto found = find_and_process_session(session.session_id, [&](SessionsList::iterator&){

        _log_with_endpoint(in_endpoint, "PipelineSession send session: " + to_string(session.session_id) + " cmd:" + to_string(cmd) + " data length:" + to_string(session_data.length()));

        auto data = PipelineRequest::generate(cmd, session.session_id, session_data);
        auto self = shared_from_this();
        auto data_copy = make_shared<string>(data);
        boost::asio::async_write(live_socket, boost::asio::buffer(*data_copy), [this, self, data_copy, sent_handler](const boost::system::error_code error, size_t) {
            if (error) {
                output_debug_info_ec(error);
                destroy();
                return;
            }

            sent_handler();
        });
    });

    if(!found){
        _log_with_endpoint(in_endpoint, "PipelineSession can't find the session " + to_string(session.session_id) + " to sent", Log::WARN);
        session.destroy(true);
    }
}

bool PipelineSession::find_and_process_session(uint32_t session_id, std::function<void(SessionsList::iterator&)> processor){

    auto it = sessions.begin();
    while(it != sessions.end()){
        if(it->get()->session_id == session_id){
            processor(it);
            return true;
        }
        ++it;
    }

    return false;
}

void PipelineSession::process_streaming_data(){

    while(!in_recv_streaming_data.empty()){
        PipelineRequest req;
        int ret = req.parse(in_recv_streaming_data);
        if(ret == -1){
            break;
        }

        if(ret == -2){
            _log_with_endpoint(in_endpoint, "PipelineSession error request format");
            destroy();
            return;
        }

        _log_with_endpoint(in_endpoint, "PipelineSession recv and process streaming data cmd: " + to_string(req.command) + " session:" + to_string(req.session_id) + " length:" + to_string(req.packet_data.length()));

        if(req.command == PipelineRequest::CONNECT){
            find_and_process_session(req.session_id, [this](SessionsList::iterator& it){
                it->get()->destroy(true);
                sessions.erase(it);
            });

            auto session = make_shared<ServerSession>(config, io_context, ssl_context, auth, plain_http_response);
            session->session_id = req.session_id;
            session->set_use_pipeline(shared_from_this());
            session->start();
            sessions.emplace_back(session);
            _log_with_endpoint(in_endpoint, "PipelineSession starts a session " + to_string(req.session_id) + ", now remain " + to_string(sessions.size()));
        }else if(req.command == PipelineRequest::DATA){
            auto found = find_and_process_session(req.session_id, [&,req](SessionsList::iterator& it){ 
                it->get()->in_recv(req.packet_data);
            });

            if(!found){
                _log_with_endpoint(in_endpoint, "PipelineSession cann't find a session " + to_string(req.session_id) + " to process" , Log::WARN);
            }
        }else if(req.command == PipelineRequest::CLOSE){
            auto found = find_and_process_session(req.session_id, [this, &req](SessionsList::iterator& it){ 
                _log_with_endpoint(in_endpoint, "PipelineSession recv client CLOSE cmd to destroy session:" + to_string(req.session_id));
                it->get()->destroy(true);   
                sessions.erase(it);                        
            });

            if(!found){
                _log_with_endpoint(in_endpoint, "PipelineSession cann't find a session " + to_string(req.session_id) + " to destroy" , Log::WARN);
            }
        }else if(req.command == PipelineRequest::ACK){
            auto found = find_and_process_session(req.session_id, [this, &req](SessionsList::iterator& it){ 
                _log_with_endpoint(in_endpoint, "PipelineSession recv client ACK cmd session:" + to_string(req.session_id));
                it->get()->out_async_read(true);
            });

            if(!found){
                _log_with_endpoint(in_endpoint, "PipelineSession cann't find a session " + to_string(req.session_id) + " to ACK" , Log::WARN);
            }
        }else{
            _log_with_endpoint(in_endpoint, "PipelineSession error command");
            destroy();
            return;
        }
    }    

    in_async_read();
}

void PipelineSession::session_write_ack(ServerSession& session,std::function<void()> sent_handler){
    in_send(PipelineRequest::ACK, session, "", sent_handler);
}

void PipelineSession::session_write_data(ServerSession& session, const std::string& session_data, std::function<void()> sent_handler){
    in_send(PipelineRequest::DATA, session, session_data, sent_handler);
}

void PipelineSession::timer_async_wait(){
    gc_timer.expires_after(chrono::seconds(3));
    auto self = shared_from_this();
    gc_timer.async_wait([this, self](const boost::system::error_code error) {
        if (!error) {
            _log_with_endpoint(in_endpoint, "PipelineSession wait for password timeout");
            destroy();
        }
    });
}

void PipelineSession::remove_session_after_destroy(ServerSession& session){
    if(status != DESTROY){
        find_and_process_session(session.session_id, [this, &session](SessionsList::iterator& it){
            in_send(PipelineRequest::CLOSE, session, "",[](){});
            sessions.erase(it);
            _log_with_endpoint(in_endpoint, "PipelineSession remove session " + to_string(session.session_id) + ", now remain " + to_string(sessions.size()));
        });
    }    
}

void PipelineSession::destroy(bool /*pipeline_call = false*/){
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;
    gc_timer.cancel();

    _log_with_endpoint(in_endpoint, "PipelineSession remove all sessions: " + to_string(sessions.size()));

    // clear all sessions which attached this PipelineSession
    for(auto it = sessions.begin(); it != sessions.end();it++){
        it->get()->destroy(true);
    }
    sessions.clear();    
    shutdown_ssl_socket(this, live_socket);
}




