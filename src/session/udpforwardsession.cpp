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

#include "udpforwardsession.h"
#include <stdexcept>
#include "ssl/sslsession.h"
#include "proto/trojanrequest.h"
#include "proto/udppacket.h"
#include "core/service.h"

using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

UDPForwardSession::UDPForwardSession(const Config &config, boost::asio::io_context &io_context, context &ssl_context, 
    const udp::endpoint &endpoint,const std::pair<std::string, uint16_t>& targetdst, const UDPWrite &in_write) :
    Session(config, io_context),
    status(CONNECT),
    in_write(in_write),
    out_socket(io_context, ssl_context),
    gc_timer(io_context),
    udp_target(targetdst) {
    udp_recv_endpoint = endpoint;
    in_endpoint = tcp::endpoint(endpoint.address(), endpoint.port());
}

tcp::socket& UDPForwardSession::accept_socket() {
    throw logic_error("accept_socket does not exist in UDPForwardSession");
}

void UDPForwardSession::start() {
    timer_async_wait();
    start_time = time(NULL);

    if(!pipeline_service){
        auto ssl = out_socket.native_handle();
        if (config.ssl.sni != "") {
            SSL_set_tlsext_host_name(ssl, config.ssl.sni.c_str());
        }
        if (config.ssl.reuse_session) {
            SSL_SESSION *session = SSLSession::get_session();
            if (session) {
                SSL_set_session(ssl, session);
            }
        }
        out_write_buf = TrojanRequest::generate(config.password.cbegin()->first, udp_target.first, udp_target.second, false);
        Log::log_with_endpoint(udp_recv_endpoint, "forwarding UDP packets to " + udp_target.first + ':' + to_string(udp_target.second) + " via " + config.remote_addr + ':' + to_string(config.remote_port), Log::INFO);

        auto self = shared_from_this();
        connect_remote_server(config, resolver, out_socket, this, udp_recv_endpoint, [this, self](){
            status = FORWARDING;
            out_async_read();
            out_async_write(out_write_buf);
            out_write_buf.clear();
        });
    }    
}

bool UDPForwardSession::process(const udp::endpoint &endpoint, const string &data) {
    if (endpoint != udp_recv_endpoint) {
        return false;
    }
    in_recv(data);
    return true;
}

void UDPForwardSession::out_async_read() {
    if(!pipeline_service){
        auto self = shared_from_this();
        out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
            if (error) {
                destroy();
                return;
            }
            out_recv(string((const char*)out_read_buf, length));
        });
    }    
}

void UDPForwardSession::out_async_write(const string &data) {
    auto self = shared_from_this();
    if(pipeline_service){
        pipeline_service->session_async_send_to_pipeline(*this, data, [this, self](const boost::system::error_code error) {
            if (error) {
                destroy();
                return;
            }
            out_sent();
        });
    }else{        
        auto data_copy = make_shared<string>(data);
        boost::asio::async_write(out_socket, boost::asio::buffer(*data_copy), [this, self, data_copy](const boost::system::error_code error, size_t) {
            if (error) {
                destroy();
                return;
            }
            out_sent();
        });
    }
}

void UDPForwardSession::timer_async_wait(){
    gc_timer.expires_after(chrono::seconds(config.udp_timeout));
    auto self = shared_from_this();
    gc_timer.async_wait([this, self](const boost::system::error_code error) {
        if (!error) {
            Log::log_with_endpoint(udp_recv_endpoint, "UDP session timeout");
            destroy();
        }
    });
}

void UDPForwardSession::in_recv(const string &data) {
    if (status == DESTROY) {
        return;
    }
    gc_timer.cancel();
    timer_async_wait();
    string packet = UDPPacket::generate(udp_target.first, udp_target.second, data);
    size_t length = data.length();
    Log::log_with_endpoint(udp_recv_endpoint, "sent a UDP packet of length " + to_string(length) + " bytes to " + udp_target.first + ':' + to_string(udp_target.second));
    sent_len += length;
    if (status == FORWARD) {
        status = FORWARDING;
        out_async_write(packet);
    } else {
        out_write_buf += packet;
    }
}

void UDPForwardSession::out_recv(const string &data) {
    if (status == FORWARD || status == FORWARDING) {
        gc_timer.cancel();
        timer_async_wait();
        udp_data_buf += data;
        for (;;) {
            UDPPacket packet;
            size_t packet_len;
            bool is_packet_valid = packet.parse(udp_data_buf, packet_len);
            if (!is_packet_valid) {
                if (udp_data_buf.length() > MAX_LENGTH) {
                    Log::log_with_endpoint(udp_recv_endpoint, "UDP packet too long", Log::ERROR);
                    destroy();
                    return;
                }
                break;
            }
            Log::log_with_endpoint(udp_recv_endpoint, "received a UDP packet of length " + to_string(packet.length) + " bytes from " + packet.address.address + ':' + to_string(packet.address.port));
            udp_data_buf = udp_data_buf.substr(packet_len);
            recv_len += packet.length;
            in_write(udp_recv_endpoint, udp_target, packet.payload);
        }
        out_async_read();
    }
}

void UDPForwardSession::out_sent() {
    if (status == FORWARDING) {
        if (out_write_buf.length() == 0) {
            status = FORWARD;
        } else {
            out_async_write(out_write_buf);
            out_write_buf.clear();
        }
    }
}

void UDPForwardSession::destroy(bool pipeline_call /*= false*/) {
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;
    Log::log_with_endpoint(udp_recv_endpoint, "disconnected, " + to_string(recv_len) + " bytes received, " + to_string(sent_len) + " bytes sent, lasted for " + to_string(time(NULL) - start_time) + " seconds", Log::INFO);
    resolver.cancel();
    gc_timer.cancel();
    shutdown_ssl_socket(this, out_socket);
    
    if(!pipeline_call && pipeline_service){
        pipeline_service->session_destroy_in_pipeline(*this);
    }
}
