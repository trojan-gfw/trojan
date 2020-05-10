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

#ifndef ICMPD_HPP
#define ICMPD_HPP

#include <sys/file.h>

#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <list>
#include <memory>
#include <unordered_map>

#include "proto/icmp_header.h"
#include "proto/ipv4_header.h"
#include "session/session.h"

class Service;
class icmpd : public std::enable_shared_from_this<icmpd> {

    enum{
        ICMP_WAIT_TRANSFER_TIME = 5,
    };

    boost::asio::streambuf m_buffer;
    boost::asio::ip::icmp::socket m_socket;

    Service* m_service;
    bool m_client_or_server;

    class IcmpSentData{
    public:
        std::weak_ptr<Session> pipeline_session;
        boost::asio::ip::address_v4 source;
        boost::asio::ip::address_v4 destination;
        int sent_time;
        IcmpSentData(std::weak_ptr<Session> sess, boost::asio::ip::address_v4 src, boost::asio::ip::address_v4 dst) : 
            pipeline_session(sess), source(src), destination(dst) {
            sent_time = time(nullptr);
        }
    };

    class IcmpSendingCache{
    public:
        std::string sending_data;
        boost::asio::ip::address_v4 destination;
        IcmpSendingCache(const std::string& data, boost::asio::ip::address_v4 dst):sending_data(data),destination(dst){}
    };

    std::unordered_map<std::string, std::shared_ptr<IcmpSentData>> m_transfer_table;

    std::list<std::shared_ptr<IcmpSendingCache>> m_sending_data_cache;
    bool m_is_sending_cache;

    std::string generate_time_exceeded_icmp(ipv4_header& ipv4_hdr, icmp_header& icmp_hdr);
    void send_back_time_exceeded(ipv4_header& ipv4_hdr, icmp_header& icmp_hdr);

    void check_transfer_table_timeout();
    void add_transfer_table(std::string&& hash, std::shared_ptr<IcmpSentData>&& data);
    bool read_icmp(std::istream& is, size_t length, ipv4_header& ipv4_hdr, icmp_header& icmp_hdr, std::string& body);
    std::shared_ptr<icmpd::IcmpSentData> find_icmp_sent_data(const std::string& hash, bool erase);

    void send_data_to_socket(const std::string& data, boost::asio::ip::address_v4 addr);
    void async_out_send();

    static int s_icmpd_file_lock;

public : 
    icmpd(boost::asio::io_service& io_service);
    ~icmpd();
    void start_recv();

    void set_service(Service* service, bool client_or_server) {
        m_service = service;
        m_client_or_server = client_or_server;
    }

    void server_out_send(const std::string& data, std::weak_ptr<Session> pipeline_session);
    void client_out_send(const std::string& data);

    static bool get_icmpd_lock();
};

#endif //ICMPD_HPP