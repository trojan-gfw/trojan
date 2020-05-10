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

#include "service.h"
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <fstream>
#include <thread>
#include <chrono>
#include "session/serversession.h"
#include "session/clientsession.h"
#include "session/forwardsession.h"
#include "session/natsession.h"
#include "session/pipelinesession.h"

using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

#ifndef _WIN32  // nat mode does not support in windows platform
// copied from shadowsocks-libev udpreplay.c
static int get_dstaddr(struct msghdr *msg, struct sockaddr_storage *dstaddr)
{
    struct cmsghdr *cmsg;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR) {
            memcpy(dstaddr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
            dstaddr->ss_family = AF_INET;
            return 0;
        } else if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_RECVORIGDSTADDR) {
            memcpy(dstaddr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in6));
            dstaddr->ss_family = AF_INET6;
            return 0;
        }
    }

    return 1;
}

static int get_ttl(struct msghdr *msg) {
    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TTL) {
            return *(int *)CMSG_DATA(cmsg);
        } else if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT) {
            return *(int *)CMSG_DATA(cmsg);
        }
    }

    return -1;
}

static pair<string, uint16_t> get_addr(struct sockaddr_storage addr){
    
    const int buf_size = 256;
    char buf[256];

    if(addr.ss_family == AF_INET){
        sockaddr_in *sa = (sockaddr_in*) &addr;
        if(inet_ntop(AF_INET, &(sa->sin_addr), buf, buf_size)){
            return make_pair(buf, ntohs(sa->sin_port));
        }             
    }else{
        sockaddr_in6 *sa = (sockaddr_in6*) &addr;
        if(inet_ntop(AF_INET6, &(sa->sin6_addr), buf, buf_size)){
            return make_pair(buf, ntohs(sa->sin6_port));
        }                
    }

    return make_pair("", 0);
}

// copied from shadowsocks-libev udpreplay.c
// it works if in NAT mode
static pair<string, uint16_t> recv_tproxy_udp_msg(int fd, boost::asio::ip::udp::endpoint& recv_endpoint, char* buf, int& buf_len, int& ttl){
    struct sockaddr_storage src_addr;
    memset(&src_addr, 0, sizeof(struct sockaddr_storage));

    char control_buffer[64] = { 0 };
    struct msghdr msg;
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec iov[1];
    struct sockaddr_storage dst_addr;
    memset(&dst_addr, 0, sizeof(struct sockaddr_storage));

    msg.msg_name       = &src_addr;
    msg.msg_namelen    = sizeof(struct sockaddr_storage);;
    msg.msg_control    = control_buffer;
    msg.msg_controllen = sizeof(control_buffer);

    const int packet_size = DEFAULT_PACKET_SIZE;
    const int buf_size = DEFAULT_PACKET_SIZE * 2;

    iov[0].iov_base = buf;
    iov[0].iov_len  = buf_size;
    msg.msg_iov     = iov;
    msg.msg_iovlen  = 1;

    buf_len = recvmsg(fd, &msg, 0);
    if (buf_len == -1) {
        _log_with_date_time("[udp] server_recvmsg failed!", Log::FATAL);
    } else{
        if (buf_len > packet_size) {
            _log_with_date_time(string("[udp] UDP server_recv_recvmsg fragmentation, MTU at least be: ") + to_string(buf_len + PACKET_HEADER_SIZE), Log::INFO);
        }

        ttl = get_ttl(&msg);
        if (get_dstaddr(&msg, &dst_addr)) {
            _log_with_date_time("[udp] unable to get dest addr!", Log::FATAL);
        }
        else {
            auto target_dst = get_addr(dst_addr);       
            auto src_dst = get_addr(src_addr);
            recv_endpoint.address(boost::asio::ip::make_address(src_dst.first));
            recv_endpoint.port(src_dst.second); 
            return target_dst;
        }
    }    

    return make_pair("", 0);
}
#endif // _WIN32

Service::Service(Config &config, bool test) :
    config(config),
    socket_acceptor(io_context),
    ssl_context(context::sslv23),
    auth(nullptr),
    udp_socket(io_context),
    pipeline_select_idx(0) {

#ifndef ENABLE_NAT
    if (config.run_type == Config::NAT) {
        throw runtime_error("NAT is not supported");
    }
#endif // ENABLE_NAT

    if (!test) {
        tcp::resolver resolver(io_context);
        tcp::endpoint listen_endpoint = *resolver.resolve(config.local_addr, to_string(config.local_port)).begin();
        socket_acceptor.open(listen_endpoint.protocol());
        socket_acceptor.set_option(tcp::acceptor::reuse_address(true));

        if (config.tcp.reuse_port) {
#ifdef ENABLE_REUSE_PORT
            socket_acceptor.set_option(reuse_port(true));
#else  // ENABLE_REUSE_PORT
            _log_with_date_time("SO_REUSEPORT is not supported", Log::WARN);
#endif // ENABLE_REUSE_PORT
        }
        
        socket_acceptor.bind(listen_endpoint);
        socket_acceptor.listen();
        prepare_icmpd(config, listen_endpoint.address().is_v4());

        if (config.run_type == Config::FORWARD || config.run_type == Config::NAT) {
            auto udp_bind_endpoint = udp::endpoint(listen_endpoint.address(), listen_endpoint.port());
            auto udp_protocol = udp_bind_endpoint.protocol();
            udp_socket.open(udp_protocol);
            
            if(config.run_type == Config::NAT){
#ifdef _WIN32
                throw runtime_error("NAT is not supported in Windows");
#else
                // copy from shadowsocks-libev
                int opt = 1;
                int fd = udp_socket.native_handle();
                int sol;
                int ip_recv;
                bool ipv4 = udp_protocol.family() == boost::asio::ip::tcp::v4().family();
                bool ipv6 = udp_protocol.family() == boost::asio::ip::tcp::v6().family();

                if (ipv4) {
                    sol = SOL_IP;
                    ip_recv = IP_RECVORIGDSTADDR;
                } else if (ipv6) {
                    sol = SOL_IPV6;
                    ip_recv = IPV6_RECVORIGDSTADDR;
                } else {
                    _log_with_date_time("[udp] protocol can't be recognized", Log::FATAL);
                    stop();
                    return;
                }

                if (setsockopt(fd, sol, IP_TRANSPARENT, &opt, sizeof(opt))) {
                    _log_with_date_time("[udp] setsockopt IP_TRANSPARENT failed!", Log::FATAL);
                    stop();
                    return;
                }

                if (setsockopt(fd, sol, ip_recv, &opt, sizeof(opt))) {
                    _log_with_date_time("[udp] setsockopt IP_RECVORIGDSTADDR failed!", Log::FATAL);
                    stop();
                    return;
                }

                if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
                    _log_with_date_time( "[udp] setsockopt SO_REUSEADDR failed!", Log::FATAL);
                    stop();
                    return;
                }

                if (config.run_type == Config::NAT && config.experimental.pipeline_proxy_icmp) {
                    if (setsockopt(fd, sol, ipv4 ? IP_RECVTTL : IPV6_RECVHOPLIMIT, &opt, sizeof(opt))) {
                        _log_with_date_time("[udp] setsockopt IP_RECVOPTS/IPV6_RECVHOPLIMIT failed!", Log::ERROR);
                    }
                }
#endif // _WIN32

            }

            udp_socket.bind(udp_bind_endpoint);
        }
    }

    config.prepare_ssl_context(ssl_context, plain_http_response);

    if(config.run_type == Config::SERVER){
        if (config.mysql.enabled) {
#ifdef ENABLE_MYSQL
            auth = new Authenticator(config);
#else // ENABLE_MYSQL
            _log_with_date_time("MySQL is not supported", Log::WARN);
#endif // ENABLE_MYSQL
        }
    }

    if (!test) {
        if (config.tcp.no_delay) {
            socket_acceptor.set_option(tcp::no_delay(true));
        }
        if (config.tcp.keep_alive) {
            socket_acceptor.set_option(boost::asio::socket_base::keep_alive(true));
        }
        if (config.tcp.fast_open) {
#ifdef TCP_FASTOPEN
            using fastopen = boost::asio::detail::socket_option::integer<IPPROTO_TCP, TCP_FASTOPEN>;
            boost::system::error_code ec;
            socket_acceptor.set_option(fastopen(config.tcp.fast_open_qlen), ec);
#else // TCP_FASTOPEN
            _log_with_date_time("TCP_FASTOPEN is not supported", Log::WARN);
#endif // TCP_FASTOPEN
#ifndef TCP_FASTOPEN_CONNECT
            _log_with_date_time("TCP_FASTOPEN_CONNECT is not supported", Log::WARN);
#endif // TCP_FASTOPEN_CONNECT
        }
    }

    if(!config.experimental.pipeline_loadbalance_configs.empty()){
        if (config.experimental.pipeline_num != 0) {
            _log_with_date_time("Pipeline will use load balance config:", Log::WARN);
            string tmp;
            for (auto it = config.experimental.pipeline_loadbalance_configs.begin();
             it != config.experimental.pipeline_loadbalance_configs.end(); it++) {
                
                auto other = make_shared<Config>();
                other->load(*it);

                auto ssl = make_shared<boost::asio::ssl::context>(context::sslv23);
                other->prepare_ssl_context(*ssl, tmp);

                config.experimental._pipeline_loadbalance_configs.emplace_back(other);
                config.experimental._pipeline_loadbalance_context.emplace_back(ssl);
                _log_with_date_time("Loaded " + (*it) + " config.", Log::WARN);
            }
        }else{
            _log_with_date_time("Pipeline load balance need to enable pipeline (set pipeline_num as non zero)", Log::ERROR);
        }
    }
}

void Service::prepare_icmpd(Config& config, bool is_ipv4){

    if (config.experimental.pipeline_proxy_icmp) {

        // set this icmp false first
        config.experimental.pipeline_proxy_icmp = false;

        if (!is_ipv4) {
            _log_with_date_time("Pipeline proxy icmp can only run in ipv4", Log::ERROR);
            return;
        }

        if (config.experimental.pipeline_num == 0) {
            _log_with_date_time("Pipeline proxy ICMP message need to enable pipeline (set pipeline_num as non zero)", Log::ERROR);
            return;
        }

        if (config.run_type != Config::SERVER) {
            if (config.run_type != Config::NAT) {
                _log_with_date_time("Pipeline proxy icmp can only run in NAT & SERVER type", Log::ERROR);
                return;
            }

            if (!icmpd::get_icmpd_lock()) {
                _log_with_date_time("Pipeline proxy icmp disabled in this process, cannot get lock, it can only run in one process of host", Log::WARN);
                return;
            }
        }
        
        config.experimental.pipeline_proxy_icmp = true;

        _log_with_date_time("Pipeline will proxy ICMP message", Log::WARN);
        icmp_processor = make_shared<icmpd>(io_context);
        icmp_processor->set_service(this, config.run_type == Config::NAT);
        icmp_processor->start_recv();
    }
}

void Service::run() {
    
    async_accept();
    if (config.run_type == Config::FORWARD || config.run_type == Config::NAT) {
        udp_async_read();
    }
    tcp::endpoint local_endpoint = socket_acceptor.local_endpoint();
    string rt;
    if (config.run_type == Config::SERVER) {
        rt = "server";
    } else if (config.run_type == Config::FORWARD) {
        rt = "forward";
    } else if (config.run_type == Config::NAT) {
        rt = "nat";
    } else {
        rt = "client";
    }
    _log_with_date_time(string("trojan service (") + rt + ") started at " + local_endpoint.address().to_string() + ':' + to_string(local_endpoint.port()), Log::WARN);
    io_context.run();
    _log_with_date_time("trojan service stopped", Log::WARN);
}

void Service::stop() {
    boost::system::error_code ec;
    socket_acceptor.cancel(ec);
    if (udp_socket.is_open()) {
        udp_socket.cancel(ec);
        udp_socket.close(ec);
    }
    io_context.stop();
}

void Service::prepare_pipelines(){
    if(config.run_type != Config::SERVER && config.experimental.pipeline_num > 0){

        bool changed = false;

        auto it = pipelines.begin();
        while(it != pipelines.end()){
            if(it->expired()){
                it = pipelines.erase(it);
                changed = true;
            }else{
                ++it;
            }
        }
       
        size_t curr_num = 0;
        for (auto it = pipelines.begin(); it != pipelines.end(); it++) {
            if (&(it->lock().get()->config) == &config) {
                curr_num++;
            }
        }

        for (; curr_num < config.experimental.pipeline_num; curr_num++ ) {
            auto pipeline = make_shared<Pipeline>(config, io_context, ssl_context);
            pipeline->start();
            pipelines.emplace_back(pipeline);
            changed = true;

            if (icmp_processor) {
                pipeline->set_icmpd(icmp_processor);
            }
            _log_with_date_time("[pipeline] start new pipeline, total:" + to_string(pipelines.size()), Log::INFO);
        }
        

        if (!config.experimental.pipeline_loadbalance_configs.empty()) {
            for (size_t i = 0; i < config.experimental._pipeline_loadbalance_configs.size(); i++) {

                auto config_file = config.experimental.pipeline_loadbalance_configs[i];
                auto balance_config = config.experimental._pipeline_loadbalance_configs[i];
                auto balance_ssl = config.experimental._pipeline_loadbalance_context[i];

                size_t curr_num = 0;
                for (auto it = pipelines.begin(); it != pipelines.end();it++){
                    if (&(it->lock().get()->config) == balance_config.get()) {
                        curr_num++;
                    }
                }

                for (; curr_num < config.experimental.pipeline_num; curr_num++ ) {
                    auto pipeline = make_shared<Pipeline>(*balance_config, io_context, *balance_ssl);
                    pipeline->start();
                    pipelines.emplace_back(pipeline);
                    changed = true;

                    _log_with_date_time("[pipeline] start a balance pipeline: " + config_file + " total:" + to_string(pipelines.size()), Log::INFO);
                }
            }

            if (changed) {
                // for default polling balance algorithm,
                // need to arrage the pipeine from 00000011111122222333333... to 012301230123...
                size_t config_idx = 0;
                size_t all_configs = config.experimental._pipeline_loadbalance_configs.size() + 1;

                auto curr = pipelines.begin();
                while (curr != pipelines.end()) {
                    auto next = curr;
                    next++;

                    while (next != pipelines.end()) {
                        bool found = false;
                        auto config_ptr = &(next->lock()->config);
                        if (config_idx == 0) {
                            found = config_ptr == &config;
                        } else {
                            found = config_ptr == config.experimental._pipeline_loadbalance_configs[config_idx - 1].get();
                        }

                        if (found) {
                            std::iter_swap(curr, next);
                            if (++config_idx >= all_configs) {
                                config_idx = 0;
                            }
                            break;
                        }

                        next++;
                    }

                    curr++;
                }

                // auto it = pipelines.begin();
                // while (it != pipelines.end()) {
                //     _log_with_date_time("after arrage:" + to_string(it->lock()->config.remote_port));
                //     ++it;
                // }
            }
            
        }
    }
}

void Service::start_session(std::shared_ptr<Session> session, bool is_udp_forward, Pipeline::SentHandler&& started_handler) {
    if(config.experimental.pipeline_num > 0 && config.run_type != Config::SERVER){
        
        prepare_pipelines();

        if(pipelines.empty()){
            throw logic_error("pipeline is empty after preparing!");
        }
        
        auto it = pipelines.begin();
        auto pipeline = shared_ptr<Pipeline>(nullptr);

        if(pipeline_select_idx >= pipelines.size()){
            pipeline_select_idx = 0;
            pipeline = it->lock();
        }

        if (!pipeline || !pipeline->is_connected()) {
            pipeline = it->lock();
            size_t idx = 0;            
            while(it != pipelines.end()){
                auto sel_pp = it->lock();
                if (idx >= pipeline_select_idx) {
                    if (sel_pp->is_connected()) {
                        pipeline = sel_pp;
                        break;
                    } else {
                        pipeline_select_idx++;
                    }
                }
                ++it;
                ++idx;          
            }
            pipeline_select_idx++;
        }

        if(!pipeline){
            throw logic_error("pipeline fatal logic!");
        }

        _log_with_date_time("pipeline " + to_string(pipeline->get_pipeline_id()) + " start session_id:" + to_string(session->session_id), Log::INFO);
        session.get()->set_use_pipeline(this, is_udp_forward);
        pipeline->session_start(*(session.get()), move(started_handler));
    }else{
        started_handler(boost::system::error_code());
    }
}

void Service::session_async_send_to_pipeline(Session &session, PipelineRequest::Command cmd, const std::string &data, Pipeline::SentHandler&& sent_handler) {
    if(config.experimental.pipeline_num > 0 && config.run_type != Config::SERVER){
        
        Pipeline* pipeline = nullptr;
        auto it = pipelines.begin();
        while(it != pipelines.end()){
            if(it->expired()){
                it = pipelines.erase(it);
            }else{
                auto p = it->lock().get();
                if(p->is_in_pipeline(session)){
                    pipeline = p;
                    break;
                }
                ++it;
            }
        }

        if(!pipeline){
            _log_with_date_time("pipeline is broken, destory session", Log::WARN);
            sent_handler(boost::asio::error::broken_pipe);
        }else{
            pipeline->session_async_send_cmd(cmd, session, data, move(sent_handler));
        }
    }else{
        _log_with_date_time("can't send data via pipeline!", Log::FATAL);
    }
}

void Service::session_async_send_to_pipeline_icmp(const std::string& data, std::function<void(boost::system::error_code ec)>&& sent_handler){
    if (config.experimental.pipeline_num > 0 && config.run_type != Config::SERVER) {
        Pipeline *pipeline = search_default_pipeline();
        if (!pipeline) {
            _log_with_date_time("pipeline is broken, destory session", Log::WARN);
            sent_handler(boost::asio::error::broken_pipe);
        } else {
            pipeline->session_async_send_icmp(data, move(sent_handler));
        }
    } else {
        _log_with_date_time("can't send data via pipeline!", Log::FATAL);
    }
}

void Service::session_destroy_in_pipeline(Session& session){
    auto it = pipelines.begin();
    while(it != pipelines.end()){
        if(it->expired()){
            it = pipelines.erase(it);
        }else{
            auto p = it->lock().get();
            if(p->is_in_pipeline(session)){
                _log_with_date_time("pipeline " + to_string(p->get_pipeline_id()) + " destroy session_id:" + to_string(session.session_id));
                p->session_destroyed(session);
                break;
            }
            ++it;
        }
    }
}

Pipeline* Service::search_default_pipeline() {
    prepare_pipelines();

    if (pipelines.empty()) {
        throw logic_error("pipeline is empty after preparing!");
    }

    Pipeline *pipeline = nullptr;
    auto it = pipelines.begin();
    while (it != pipelines.end()) {
        if (it->expired()) {
            it = pipelines.erase(it);
        } else {
            auto p = it->lock().get();
            if (&(p->config) == (&config)) {  // find the default pipeline, cannot use load-balance server
                _log_with_date_time("->>>>>>> search default pipeline: " + p->config.remote_addr + "  p1 " + to_string(uint64_t(&config)) + " p2:" + to_string(uint64_t(&p->config)));
                pipeline = p;
                break;
            }
            ++it;
        }
    }

    return pipeline;
}
void Service::async_accept() {
    shared_ptr<Session>session(nullptr);
    if (config.run_type == Config::SERVER) {
        if(config.experimental.pipeline_num > 0){
            // start a pipeline mode in server run_type
            auto pipeline = make_shared<PipelineSession>(config, io_context, ssl_context, auth, plain_http_response);
            pipeline->set_icmpd(icmp_processor);

            session = pipeline;
        }else{
            session = make_shared<ServerSession>(config, io_context, ssl_context, auth, plain_http_response);
        }        
    } else {
        if (config.run_type == Config::FORWARD) {
            session = make_shared<ForwardSession>(config, io_context, ssl_context);
        } else if (config.run_type == Config::NAT) {
            session = make_shared<NATSession>(config, io_context, ssl_context);
        } else {
            session = make_shared<ClientSession>(config, io_context, ssl_context);
        }      
    }
    
    socket_acceptor.async_accept(session->accept_socket(), [this, session](const boost::system::error_code error) {    

        if (error == boost::asio::error::operation_aborted) {
            // got cancel signal, stop calling myself
            return;
        }

        if (!error) {
            boost::system::error_code ec;
            auto endpoint = session->accept_socket().remote_endpoint(ec);
            if (!ec) {
                _log_with_endpoint(endpoint, "incoming connection");
                start_session(session, false, [session](boost::system::error_code ec){
                    if(ec){
                        session->destroy();    
                    }else{
                        session->start(); 
                    }                    
                });                
            }
        }
        async_accept();
    });
}

void Service::udp_async_read() {
    auto cb = [this](const boost::system::error_code error, size_t length) {
        if (error == boost::asio::error::operation_aborted) {
            // got cancel signal, stop calling myself
            return;
        }
        if (error) {
            stop();
            throw runtime_error(error.message());
        }
        
        pair<string,uint16_t> targetdst;
        
        if(config.run_type == Config::NAT){
#ifdef _WIN32  // windows cannot support nat mode
            targetdst = make_pair("", 0);
#else
            int read_length = (int)length;
            int ttl = -1;
            targetdst = recv_tproxy_udp_msg(udp_socket.native_handle(), udp_recv_endpoint, (char *)udp_read_buf, read_length, ttl);
            length = read_length < 0 ? 0 : read_length;

            // in the first design, if we want to proxy icmp, we need to transfer TTL of udp to server and set TTL when server sends upd out
            // but now in most of traceroute programs just use icmp to trigger remote server back instead of udp, so we don't need pass TTL to server any more
            // we just keep this codes of retreiving TTL if it will be used for some future features.
            _log_with_date_time("[udp] get ttl:" + to_string(ttl));
#endif  //_WIN32
        }else{
            targetdst = make_pair(config.target_addr, config.target_port);
        }

        if(targetdst.second != 0){                
            string data((const char *)udp_read_buf, length);
            for (auto it = udp_sessions.begin(); it != udp_sessions.end();) {
                auto next = ++it;
                --it;
                if (it->expired()) {
                    udp_sessions.erase(it);
                } else if (it->lock()->process(udp_recv_endpoint, data)) {
                    udp_async_read();
                    return;
                }
                it = next;
            }
            
            _log_with_endpoint(udp_recv_endpoint, "new UDP session");
            auto session = make_shared<UDPForwardSession>(config, io_context, ssl_context, udp_recv_endpoint, targetdst, 
             [this](const udp::endpoint &endpoint, const string &data) {
                if(config.run_type == Config::NAT){
                    throw logic_error("[udp] logic fatal error, cannot call in_write function for NAT type!");
                }else{
                    boost::system::error_code ec;
                    udp_socket.send_to(boost::asio::buffer(data), endpoint, 0, ec);
                        
                    if (ec == boost::asio::error::no_permission) {
                        _log_with_endpoint(udp_recv_endpoint, "[udp] dropped a packet due to firewall policy or rate limit");
                    } else if (ec) {
                        throw runtime_error(ec.message());
                    }             
                }
            });

            start_session(session, true, [this, session, data](boost::system::error_code ec){
                if(!ec){
                    udp_sessions.emplace_back(session);
                    session->start_udp(data);
                }                
            });
              
        }else{
            _log_with_endpoint(udp_recv_endpoint, "cannot read original destination address!");
        }

        udp_async_read();        
    };

    if(config.run_type == Config::NAT){
        udp_socket.async_receive_from(boost::asio::null_buffers(), udp_recv_endpoint, cb);
    }else{
        udp_socket.async_receive_from(boost::asio::buffer(udp_read_buf, Session::MAX_BUF_LENGTH), udp_recv_endpoint, cb);
    }    
}

boost::asio::io_context &Service::service() {
    return io_context;
}

void Service::reload_cert() {
    if (config.run_type == Config::SERVER) {
        _log_with_date_time("reloading certificate and private key. . . ", Log::WARN);
        ssl_context.use_certificate_chain_file(config.ssl.cert);
        ssl_context.use_private_key_file(config.ssl.key, context::pem);
        boost::system::error_code ec;
        socket_acceptor.cancel(ec);
        async_accept();
        _log_with_date_time("certificate and private key reloaded", Log::WARN);
    } else {
        _log_with_date_time("cannot reload certificate and private key: wrong run_type", Log::ERROR);
    }
}

Service::~Service() {
    if (auth) {
        delete auth;
        auth = nullptr;
    }
}
