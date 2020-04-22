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

#include <list>
#include <string>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ip/udp.hpp>
#include <functional>
#include "session/session.h"
#include "pipeline.h"
#include "authenticator.h"
#include "session/udpforwardsession.h"

class Service {
private:
    typedef std::list<std::weak_ptr<Pipeline>> PipelineList;
    enum {
        MAX_LENGTH = 8192
    };
    const Config &config;
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor socket_acceptor;
    boost::asio::ssl::context ssl_context;
    Authenticator *auth;
    std::string plain_http_response;
    boost::asio::ip::udp::socket udp_socket;
    std::list<std::weak_ptr<UDPForwardSession> > udp_sessions;
    uint8_t udp_read_buf[MAX_LENGTH];
    boost::asio::ip::udp::endpoint udp_recv_endpoint;
    void async_accept();
    void udp_async_read();

    PipelineList pipelines;
    void prepare_pipelines();
    void start_session(std::shared_ptr<Session> session, bool is_udp_forward, std::function<void(boost::system::error_code ec)> started_handler);
public:
    Service(Config &config, bool test = false);
    void run();
    void stop();
    boost::asio::io_context &service();
    void reload_cert();
    ~Service();

    void session_async_send_to_pipeline(Session& session, const std::string& data, std::function<void(boost::system::error_code ec)> sent_handler);
    void session_destroy_in_pipeline(Session& session);
};

template<typename ThisT, typename EndPoint>
void connect_remote_server(const Config& config, boost::asio::ip::tcp::resolver& resolver, 
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& out_socket, ThisT this_ptr, EndPoint in_endpoint, std::function<void()> connected_handler){

    auto timeout_timer = std::shared_ptr<boost::asio::deadline_timer>(nullptr);
    if(config.tcp.connect_time_out > 0){
        // out_socket.next_layer().async_connect will be stuck forever
        // we must set a timeout timer
        timeout_timer = std::make_shared<boost::asio::deadline_timer>(out_socket.next_layer().get_io_context());
        timeout_timer->expires_from_now(boost::posix_time::milliseconds(config.tcp.connect_time_out));
        timeout_timer->async_wait([=, &out_socket](const boost::system::error_code error) {
            if(!error){
                Log::log_with_endpoint(in_endpoint, "cannot establish connection to remote server " + config.remote_addr + ':' + std::to_string(config.remote_port) + ": timeout", Log::ERROR);
                this_ptr->destroy();
            }
        });
    }

    auto self = this_ptr->shared_from_this();
    resolver.async_resolve(config.remote_addr, std::to_string(config.remote_port), [=, &config, &out_socket](const boost::system::error_code error, boost::asio::ip::tcp::resolver::results_type results) {
        if (error || results.size() == 0) {
            Log::log_with_endpoint(in_endpoint, "cannot resolve remote server hostname " + config.remote_addr + ": " + error.message(), Log::ERROR);
            this_ptr->destroy();
            return;
        }
        auto iterator = results.begin();
        Log::log_with_endpoint(in_endpoint, config.remote_addr + " is resolved to " + iterator->endpoint().address().to_string(), Log::ALL);
        boost::system::error_code ec;
        out_socket.next_layer().open(iterator->endpoint().protocol(), ec);
        if (ec) {
            this_ptr->destroy();
            return;
        }
        if (config.tcp.no_delay) {
            out_socket.next_layer().set_option(boost::asio::ip::tcp::no_delay(true));
        }
        if (config.tcp.keep_alive) {
            out_socket.next_layer().set_option(boost::asio::socket_base::keep_alive(true));
        }
#ifdef TCP_FASTOPEN_CONNECT
        if (config.tcp.fast_open) {
            using fastopen_connect = boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN_CONNECT>;
            boost::system::error_code ec;
            out_socket.next_layer().set_option(fastopen_connect(true), ec);
        }
#endif // TCP_FASTOPEN_CONNECT
        
        out_socket.next_layer().async_connect(*iterator, [=, &config, &out_socket](const boost::system::error_code error) {
            if (error) {
                Log::log_with_endpoint(in_endpoint, "cannot establish connection to remote server " + config.remote_addr + ':' + std::to_string(config.remote_port) + ": " + error.message(), Log::ERROR);
                this_ptr->destroy();
                return;
            }
            out_socket.async_handshake(boost::asio::ssl::stream_base::client, [=, &config, &out_socket](const boost::system::error_code error) {
                if(timeout_timer){
                    timeout_timer->cancel();
                }
                if (error) {
                    Log::log_with_endpoint(in_endpoint, "SSL handshake failed with " + config.remote_addr + ':' + std::to_string(config.remote_port) + ": " + error.message(), Log::ERROR);
                    this_ptr->destroy();
                    return;
                }
                Log::log_with_endpoint(in_endpoint, "tunnel established");
                if (config.ssl.reuse_session) {
                    auto ssl = out_socket.native_handle();
                    if (!SSL_session_reused(ssl)) {
                        Log::log_with_endpoint(in_endpoint, "SSL session not reused");
                    } else {
                        Log::log_with_endpoint(in_endpoint, "SSL session reused");
                    }
                }
                connected_handler();
            });
        });        
    });
}

template<typename ThisPtr>
void shutdown_ssl_socket(ThisPtr this_ptr, boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket){
    if (socket.next_layer().is_open()) {
        auto self = this_ptr->shared_from_this();
        auto ssl_shutdown_timer = std::make_shared<boost::asio::steady_timer>(socket.get_io_context());
        auto ssl_shutdown_cb = [=, &socket](const boost::system::error_code error) {
            if (error == boost::asio::error::operation_aborted) {
                return;
            }
            boost::system::error_code ec;
            ssl_shutdown_timer.get()->cancel();
            socket.next_layer().cancel(ec);
            socket.next_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            socket.next_layer().close(ec);
        };
        boost::system::error_code ec;
        socket.next_layer().cancel(ec);
        socket.async_shutdown(ssl_shutdown_cb);
        ssl_shutdown_timer.get()->expires_after(std::chrono::seconds(5));
        ssl_shutdown_timer.get()->async_wait(ssl_shutdown_cb);
    }    
}

#endif // _SERVICE_H_
