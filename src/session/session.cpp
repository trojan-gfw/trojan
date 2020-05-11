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

#include "session.h"
using namespace std;

Session::SessionIdType Session::s_session_id_counter = 0;
set<Session::SessionIdType> Session::s_session_used_ids;

Session::Session(const Config &config, boost::asio::io_context &io_context) : recv_len(0),
                                                                              sent_len(0),
                                                                              resolver(io_context),
                                                                              udp_socket(io_context),
                                                                              pipeline_client_service(nullptr),
                                                                              pipeline_wait_for_ack(false),
                                                                              pipeline_first_call_ack(true),
                                                                              config(config),
                                                                              io_context(io_context),
                                                                              session_id(0) {
    pipeline_ack_counter = static_cast<int>(config.experimental.pipeline_ack_window);
}

Session::~Session() = default;

void Session::allocate_session_id(){
    if(s_session_used_ids.size() >= numeric_limits<SessionIdType>::max()){
        throw logic_error("session id is over !! pipeline reached the session id limits !!");
    }

    do{
        session_id = s_session_id_counter++;        
    }while(s_session_used_ids.find(session_id) != s_session_used_ids.end());

    s_session_used_ids.insert(session_id);
}

void Session::free_session_id(){
    s_session_used_ids.erase(session_id);
}


