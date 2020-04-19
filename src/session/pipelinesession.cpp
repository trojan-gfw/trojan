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
#include <boost/asio/ssl.hpp>

using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

PipelineSession::SessionsList PipelineSession::sessions;

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

    timer_async_wait();
}

tcp::socket& PipelineSession::accept_socket(){
    return (tcp::socket&)live_socket.next_layer();
}

void PipelineSession::start(){
    boost::system::error_code ec;
    start_time = time(NULL);
    in_endpoint = live_socket.next_layer().remote_endpoint(ec);
    if (ec) {
        destroy();
        return;
    }
    auto self = shared_from_this();
    live_socket.async_handshake(stream_base::server, [this, self](const boost::system::error_code error) {
        if (error) {
            Log::log_with_endpoint(in_endpoint, "SSL handshake failed: " + error.message(), Log::ERROR);
            if (error.message() == "http request" && plain_http_response != "") {
                recv_len += plain_http_response.length();
                boost::asio::async_write(accept_socket(), boost::asio::buffer(plain_http_response), [this, self](const boost::system::error_code, size_t) {
                    destroy();
                });
                return;
            }
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
            Log::log_with_endpoint(in_endpoint, "Pipeline error password");
            destroy();
            return;
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
    auto found = find_and_process_session(session, [&](SessionsList::iterator&){
        auto data = PipelineRequest::generate(cmd, session.session_id, session_data);
        auto self = shared_from_this();
        auto data_copy = make_shared<string>(data);
        boost::asio::async_write(live_socket, boost::asio::buffer(*data_copy), [this, self, data_copy, sent_handler](const boost::system::error_code error, size_t) {
            if (error) {
                destroy();
                return;
            }

            sent_handler();
        });
    });

    if(!found){
        session.destroy();
    }
}

bool PipelineSession::find_and_process_session(uint32_t session_id, std::function<void(SessionsList::iterator&)> processor){
    auto it = std::find_if(sessions.begin(), sessions.end(), [=](shared_ptr<ServerSession> s){
        return s.get()->session_id == session_id;
    });
    
    if(it != sessions.end()){
        processor(it);
        return true;
    }

    return false;
}

bool PipelineSession::find_and_process_session(ServerSession& session, std::function<void(SessionsList::iterator&)> processor){
    auto it = std::find_if(sessions.begin(), sessions.end(), [&](shared_ptr<ServerSession> s){
        return s.get() == (&session);
    });
    
    if(it != sessions.end()){
        processor(it);
        return true;
    }
    return false;
}

void PipelineSession::process_streaming_data(){
    PipelineRequest req;
    int ret = req.parse(in_recv_streaming_data);
    if(ret == -1){
        in_async_read();
        return;
    }

    if(ret == -2){
        Log::log_with_endpoint(in_endpoint, "Pipeline error request format");
        destroy();
        return;
    }

    if(req.command == PipelineRequest::CONNECT){
        find_and_process_session(req.session_id, [this](SessionsList::iterator& it){    
            sessions.erase(it); // must erase firstly then destroy
            it->get()->destroy();            
        });

        auto session = make_shared<ServerSession>(config, io_context, ssl_context, auth, plain_http_response);
        session->session_id = req.session_id;
        session->set_use_pipeline(shared_from_this());
        session->start();
        sessions.emplace_back(session);
        Log::log_with_endpoint(in_endpoint, "Pipeline start a session " + to_string(req.session_id) + ", now remain " + to_string(sessions.size()));
    }else if(req.command == PipelineRequest::DATA){
        find_and_process_session(req.session_id, [&,req](SessionsList::iterator& it){    
            it->get()->in_recv(req.packet_data);
        });
    }else if(req.command == PipelineRequest::CLOSE){
        find_and_process_session(req.session_id, [this](SessionsList::iterator& it){    
            sessions.erase(it); // must erase firstly then destroy
            it->get()->destroy();            
        });
    }else{
        Log::log_with_endpoint(in_endpoint, "Pipeline error command");
        destroy();
        return;
    }

    in_async_read();
}

void PipelineSession::session_write_data(ServerSession& session, const std::string& session_data, std::function<void()> sent_handler){
    in_send(PipelineRequest::DATA, session, session_data, sent_handler);
}

void PipelineSession::timer_async_wait(){
    gc_timer.expires_after(chrono::seconds(3));
    auto self = shared_from_this();
    gc_timer.async_wait([this, self](const boost::system::error_code error) {
        if (!error) {
            Log::log_with_endpoint(in_endpoint, "Pipeline wait for password timeout");
            destroy();
        }
    });
}

void PipelineSession::remove_session_after_destroy(ServerSession& session){
    if(status != DESTROY){
        find_and_process_session(session, [this, &session](SessionsList::iterator& it){
            sessions.erase(it);
            in_send(PipelineRequest::CLOSE, session, "",[](){});
            Log::log_with_endpoint(in_endpoint, "Pipeline remove session " + to_string(session.session_id) + ", now remain " + to_string(sessions.size()));
        });
    }    
}

void PipelineSession::destroy(){
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;
    
    Log::log_with_endpoint(in_endpoint, "Pipeline remove all sessions " + to_string(sessions.size()));

    // clear all sessions which attached this pipeline
    auto it = sessions.begin();
    while(it != sessions.end()){
        
        auto sess = it->get();
        auto pipe = sess->get_pipeline();

        if(!pipe.expired() && pipe.lock().get() == this){
            sess->destroy();
            it = sessions.erase(it);
        }else{
            ++it;
        }
    }

    // TODO
    gc_timer.cancel();
}




