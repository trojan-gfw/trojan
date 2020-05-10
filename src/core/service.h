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

#ifndef _SERVICE_H_
#define _SERVICE_H_

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ssl.hpp>
#include <functional>
#include <list>
#include <string>

#include "authenticator.h"
#include "core/icmpd.h"
#include "core/pipeline.h"
#include "session/session.h"
#include "session/udpforwardsession.h"

class Pipeline;
class icmpd;
class Service {
private:
    typedef std::list<std::weak_ptr<Pipeline>> PipelineList;
    
    const Config &config;
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor socket_acceptor;
    boost::asio::ssl::context ssl_context;
    Authenticator *auth;
    std::string plain_http_response;
    boost::asio::ip::udp::socket udp_socket;
    std::list<std::weak_ptr<UDPForwardSession> > udp_sessions;
    uint8_t udp_read_buf[Session::MAX_BUF_LENGTH]{};
    boost::asio::ip::udp::endpoint udp_recv_endpoint;
    void async_accept();
    void udp_async_read();

    PipelineList pipelines;
    size_t pipeline_select_idx;
    void prepare_pipelines();
    void start_session(std::shared_ptr<Session> session, bool is_udp_forward, Pipeline::SentHandler&& started_handler);
    std::shared_ptr<icmpd> icmp_processor;
    void prepare_icmpd(Config& config, bool is_ipv4);

public:
    explicit Service(Config &config, bool test = false);
    void run();
    void stop();
    boost::asio::io_context &service();
    void reload_cert();
    ~Service();

    void session_async_send_to_pipeline(Session& session, PipelineRequest::Command cmd, const std::string& data, Pipeline::SentHandler&& sent_handler);
    void session_async_send_to_pipeline_icmp(const std::string& data, Pipeline::SentHandler&& sent_handler);
    void session_destroy_in_pipeline(Session& session);

    Pipeline* search_default_pipeline();
};
#endif // _SERVICE_H_
