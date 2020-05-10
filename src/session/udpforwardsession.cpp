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
#include <utility>

#include "core/service.h"
#include "proto/trojanrequest.h"
#include "proto/udppacket.h"
#include "ssl/sslsession.h"
#include "core/utils.h"

using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

UDPForwardSession::UDPForwardSession(const Config &config, boost::asio::io_context &io_context, context &ssl_context, 
    const udp::endpoint &endpoint,const std::pair<std::string, uint16_t>& targetdst, UDPWrite in_write) :
    Session(config, io_context),
    status(CONNECT),
    in_write(move(in_write)),
    out_socket(io_context, ssl_context),
    gc_timer(io_context),
    udp_target(targetdst) ,
    udp_target_socket(io_context){

    udp_recv_endpoint = endpoint;
    udp_target_endpoint = udp::endpoint(boost::asio::ip::make_address(udp_target.first), udp_target.second);    
    in_endpoint = tcp::endpoint(endpoint.address(), endpoint.port());

    allocate_session_id();
}

UDPForwardSession::~UDPForwardSession(){
    free_session_id();
}

tcp::socket& UDPForwardSession::accept_socket() {
    throw logic_error("accept_socket does not exist in UDPForwardSession");
}
void UDPForwardSession::start(){
    throw logic_error("start does not exist in UDPForwardSession");
}

void UDPForwardSession::start_udp(const std::string& data) {
    timer_async_wait();
    start_time = time(nullptr);

    auto self = shared_from_this();
    auto cb = [this, self](){
        if(config.run_type == Config::NAT){
            udp_target_socket.open(udp_target_endpoint.protocol());
            bool is_ipv4 = udp_target_endpoint.protocol().family() == boost::asio::ip::tcp::v6().family();
            if (prepare_nat_udp_target_bind(udp_target_socket.native_handle(), is_ipv4, udp_target_endpoint)) {
                udp_target_socket.bind(udp_target_endpoint);
            } else {
                destroy();
                return;
            }
        }
        
        status = FORWARDING;
        out_async_read();
        out_async_write(out_write_buf);
        out_write_buf.clear();
    };

    out_write_buf = TrojanRequest::generate(config.password.cbegin()->first, udp_target.first, udp_target.second, false);
    process(udp_recv_endpoint, data);

    _log_with_endpoint(udp_recv_endpoint, "session_id: " + to_string(session_id) + " forwarding UDP packets to " + udp_target.first + ':' + to_string(udp_target.second) + " via " + config.remote_addr + ':' + to_string(config.remote_port), Log::INFO);

    if(pipeline_client_service){    
        cb();
    }else{
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
        connect_remote_server_ssl(this, config.remote_addr, to_string(config.remote_port), resolver, out_socket, udp_recv_endpoint, cb);
    }    
}

bool UDPForwardSession::process(const udp::endpoint &endpoint, const string &data) {
    if (endpoint != udp_recv_endpoint) {
        return false;
    }
    in_recv(data);
    return true;
}

void UDPForwardSession::pipeline_out_recv(string &&data) {
    if (!pipeline_client_service) {
        throw logic_error("cannot call pipeline_out_recv without pipeline!");
    }
    
    if (status != DESTROY) {
        pipeline_data_cache.push_data(std::move(data));
    }
}

void UDPForwardSession::out_async_read() {
    if (pipeline_client_service) {
        pipeline_data_cache.async_read([this](const string &data) {
            out_recv(data);
        });
    } else {
        auto self = shared_from_this();
        out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_BUF_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
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
    if(pipeline_client_service){
        pipeline_client_service->session_async_send_to_pipeline(*this, PipelineRequest::DATA, data, [this, self](const boost::system::error_code error) {
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
            _log_with_endpoint(udp_recv_endpoint, "session_id: " + to_string(session_id) + " UDP session timeout");
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
    _log_with_endpoint(udp_recv_endpoint, "session_id: " + to_string(session_id) + " sent a UDP packet of length " + to_string(length) + " bytes to " + udp_target.first + ':' + to_string(udp_target.second));
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
                if (udp_data_buf.length() > MAX_BUF_LENGTH) {
                    _log_with_endpoint(udp_recv_endpoint, "session_id: " + to_string(session_id) + " UDP packet too long", Log::ERROR);
                    destroy();
                    return;
                }
                break;
            }
            _log_with_endpoint(udp_recv_endpoint, "session_id: " + to_string(session_id) + " received a UDP packet of length " + to_string(packet.length) + " bytes from " + packet.address.address + ':' + to_string(packet.address.port));
            udp_data_buf = udp_data_buf.substr(packet_len);
            recv_len += packet.length;

            if(config.run_type == Config::NAT){
                boost::system::error_code ec;
                udp_target_socket.send_to(boost::asio::buffer(packet.payload), udp_recv_endpoint, 0 , ec);
                if (ec == boost::asio::error::no_permission) {
                    _log_with_endpoint(udp_recv_endpoint, "[udp] dropped a packet due to firewall policy or rate limit");
                } else if (ec) {
                    output_debug_info_ec(ec);
                    destroy();
                    return;
                } 
            }else{
                in_write(udp_recv_endpoint, packet.payload);
            }            
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
    _log_with_endpoint(udp_recv_endpoint, "session_id: " + to_string(session_id) + " disconnected, " + to_string(recv_len) + " bytes received, " + to_string(sent_len) + " bytes sent, lasted for " + to_string(time(nullptr) - start_time) + " seconds", Log::INFO);
    resolver.cancel();
    gc_timer.cancel();

    if(udp_target_socket.is_open()){
        udp_target_socket.cancel();
        udp_target_socket.close();
    }

    shutdown_ssl_socket(this, out_socket);
    
    if(!pipeline_call && pipeline_client_service){
        pipeline_client_service->session_destroy_in_pipeline(*this);
    }
}
