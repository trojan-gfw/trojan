#include "icmpd.h"

#include <iostream>
#include <stdexcept>

#include "core/service.h"
#include "session/pipelinesession.h"

using namespace std;
using namespace boost::asio::ip;

icmpd::icmpd(boost::asio::io_service& io_service)
    : m_socket(io_service, icmp::v4()),
      m_is_sending_cache(false) {
#ifdef _WIN32
    throw runtime_error("[icmp] cannot crate icmpd in windows!");
#else
    int fd = m_socket.native_handle();
    int opt = 1;
    if (setsockopt(fd, SOL_IP, IP_HDRINCL, &opt, sizeof(opt))) {
        throw runtime_error("[icmp] setsockopt IP_HDRINCL failed!");
    }
#endif //_WIN32
}

void icmpd::add_transfer_table(std::string&& hash, std::shared_ptr<IcmpSentData>&& data) {
    if(m_client_or_server){
        throw logic_error("[icmp] client don't need use add_transfer_table");
    }

    check_transfer_table_timeout();
    m_transfer_table.emplace(make_pair(hash, data));
}

void icmpd::check_transfer_table_timeout() {
    auto curr_time = time(nullptr);
    for(auto it = m_transfer_table.begin();it != m_transfer_table.end();){
        if (curr_time - it->second->sent_time > ICMP_WAIT_TRANSFER_TIME) {
            _log_with_date_time("[icmp] transfer table item timeout, remove " + it->second->source.to_string() + " -> " + it->second->destination.to_string());
            it = m_transfer_table.erase(it);
        }else{
            ++it;
        }
    }
}

std::shared_ptr<icmpd::IcmpSentData> icmpd::find_icmp_sent_data(const std::string& hash, bool erase) {    
    check_transfer_table_timeout();

    auto it = m_transfer_table.find(hash);
    if (it != m_transfer_table.end()) {
        auto session = it->second;
        if (!session->pipeline_session.expired()) {
            if (erase) {
                m_transfer_table.erase(it);
            }
            return session;
        }
    }

    return nullptr;
}

bool icmpd::read_icmp(std::istream& is, size_t length, ipv4_header& ipv4_hdr, icmp_header& icmp_hdr, std::string& body) {
    is >> ipv4_hdr >> icmp_hdr;

    if(is){
        int remain = length - ipv4_hdr.header_length() - icmp_header::HEADER_LENGTH;
        body.resize(remain, 0);
        if (remain > 0) {
            is.read(&body[0], remain);
        }

        return true;
    }

    _log_with_date_time("[icmp] read icmp error!");
    return false;
}

void icmpd::start_recv() {
    auto self = shared_from_this();
    m_buffer.consume(m_buffer.size());    
    m_socket.async_receive(m_buffer.prepare(65536), [this, self](boost::system::error_code ec, size_t length) {
        if (!ec) {
            m_buffer.commit(length);
            std::istream is(&m_buffer);

            ipv4_header ipv4_hdr;
            icmp_header icmp_hdr;
            string body;

            if (read_icmp(is, length, ipv4_hdr, icmp_hdr, body)) {
                
                _log_with_date_time("[icmp] recv " + ipv4_hdr.source_address().to_string() + " -> " + 
                    ipv4_hdr.destination_address().to_string() + " ttl " + to_string(ipv4_hdr.time_to_live()) +
                    " icmp type " + to_string(icmp_hdr.type()) + " length:" + to_string(length));

                if (m_client_or_server) {
                    if (icmp_hdr.type() == icmp_header::echo_request) { // only proxy echo_request for client
                        if(ipv4_hdr.time_to_live() == 1){
                            send_back_time_exceeded(ipv4_hdr, icmp_hdr);
                        }else{
                            ipv4_hdr.time_to_live(ipv4_hdr.time_to_live() - 1);
                            ipv4_hdr.assign_header_checksum();

                            std::ostringstream os;
                            os << ipv4_hdr << icmp_hdr << body;
                            
                            m_service->session_async_send_to_pipeline_icmp(os.str(), [this, self](const boost::system::error_code) {
                                // nothing to process...
                            });
                        }
                    }
                } else {
                    std::shared_ptr<IcmpSentData> icmp_sent_data(nullptr);
                    if (icmp_hdr.type() == icmp_header::echo_reply) {  // for ping
                        auto hash = ipv4_hdr.source_address().to_string() + to_string((int)icmp_header::echo_request) +
                                    to_string(icmp_hdr.identifier()) + to_string(icmp_hdr.sequence_number());

                        icmp_sent_data = find_icmp_sent_data(hash, true);
                    }
                    else if(icmp_hdr.type() == icmp_header::time_exceeded){ // for traceroute
                        ipv4_header orig_ipv4_hdr;
                        icmp_header orig_icmp_hdr;
                        string orig_body;
                        std::istringstream orig_is(body);
                        if (read_icmp(orig_is, body.length(), orig_ipv4_hdr, orig_icmp_hdr, orig_body)) {
                            auto hash = orig_ipv4_hdr.destination_address().to_string() + to_string((int)icmp_header::echo_request) +
                                        to_string(orig_icmp_hdr.identifier()) + to_string(orig_icmp_hdr.sequence_number());

                            icmp_sent_data = find_icmp_sent_data(hash, true);
                            if (icmp_sent_data) {
                                orig_ipv4_hdr.source_address(icmp_sent_data->source);
                                orig_ipv4_hdr.assign_header_checksum();

                                std::ostringstream os;
                                os << orig_ipv4_hdr << orig_icmp_hdr;

                                body = os.str();

                                icmp_hdr.assign_checksum(body);
                                ipv4_hdr.total_length(ipv4_hdr.header_length() + icmp_header::HEADER_LENGTH + body.length());
                            }                            
                        }
                    }

                    if (icmp_sent_data) {
                        ipv4_hdr.destination_address(icmp_sent_data->source);

                        std::ostringstream os;
                        os << ipv4_hdr << icmp_hdr << body;

                        static_cast<PipelineSession*>(icmp_sent_data->pipeline_session.lock().get())->session_write_icmp(os.str(), [this, self](const boost::system::error_code) {
                            // nothing to process...
                        });
                    }
                }
            }
        }else{
            output_debug_info_ec(ec);
        }

        start_recv();
    });
}

string icmpd::generate_time_exceeded_icmp(ipv4_header& ipv4_hdr, icmp_header& icmp_hdr) {
    std::ostringstream os;
    os << ipv4_hdr << icmp_hdr;

    auto send_back_body = os.str();

    os.str("");

    auto src = ipv4_hdr.source_address();

    ipv4_hdr.destination_address(src);
    ipv4_hdr.time_to_live(64);
    ipv4_hdr.source_address(address_v4());

    icmp_hdr.type(icmp_header::time_exceeded);
    icmp_hdr.code(0);
    icmp_hdr.assign_checksum(send_back_body);

    os << ipv4_hdr << icmp_hdr << send_back_body;

    return os.str();
}

void icmpd::send_data_to_socket(const std::string& data, boost::asio::ip::address_v4 addr){
    // cannot call the send_to function directly, it will throw "Operation not permitted" exception,
    // it must be wait for it has been sent successfully back
    m_sending_data_cache.emplace_back(make_shared<IcmpSendingCache>(data, addr));
    async_out_send();
}

void icmpd::async_out_send(){
    if(m_is_sending_cache || m_sending_data_cache.empty()){
        return;
    }

    m_is_sending_cache = true;

    auto send = m_sending_data_cache.front();
    auto self = shared_from_this();
    auto data = make_shared<string>(send->sending_data);
    m_socket.async_send_to(boost::asio::buffer(*data), icmp::endpoint(send->destination, 0), [this, self, data](const boost::system::error_code ec, size_t) {
        if (ec) {
            ipv4_header ipv4_hdr;
            icmp_header icmp_hdr;
            string body;

            std::istringstream is(*data);
            read_icmp(is, data->length(), ipv4_hdr, icmp_hdr, body);
            _log_with_date_time("[icmp] async_send_to error: " + ec.message() + " " + ipv4_hdr.source_address().to_string() + " -> " + ipv4_hdr.destination_address().to_string());
        }
        m_is_sending_cache = false;
        async_out_send();
    });

    m_sending_data_cache.pop_front();
}

void icmpd::send_back_time_exceeded(ipv4_header& ipv4_hdr, icmp_header& icmp_hdr) {
    auto data = generate_time_exceeded_icmp(ipv4_hdr, icmp_hdr);
    _log_with_date_time("[icmp] send_back_time_exceeded " + ipv4_hdr.source_address().to_string() + " -> " + ipv4_hdr.destination_address().to_string());
    send_data_to_socket(data, ipv4_hdr.destination_address());
}

void icmpd::server_out_send(const std::string& data, std::weak_ptr<Session> pipeline_session){
    if(m_client_or_server){
        throw logic_error("[icmp] client cannot call icmpd::server_out_send");
    }

    std::istringstream is(data);

    ipv4_header ipv4_hdr;
    icmp_header icmp_hdr;
    string body;

    if(read_icmp(is, data.length(), ipv4_hdr, icmp_hdr, body)){
        if (icmp_hdr.type() != icmp_header::echo_request) {
            throw logic_error("[icmp] can only proxy client ping message!");
        }

        if(ipv4_hdr.time_to_live() == 1){
            auto exceed_data = generate_time_exceeded_icmp(ipv4_hdr, icmp_hdr);
            auto self = shared_from_this();
            static_cast<PipelineSession*>(pipeline_session.lock().get())->session_write_icmp(exceed_data, [this, self](const boost::system::error_code) {
                // nothing to process...
            });
            return;
        }

        auto dst = ipv4_hdr.destination_address();
        auto src = ipv4_hdr.source_address();
        ipv4_hdr.source_address(address_v4()); // change the src as 0.0.0.0, kernel will fill it

        std::ostringstream os;
        os << ipv4_hdr << icmp_hdr << body;

        _log_with_date_time("[icmp] server send out " + ipv4_hdr.source_address().to_string() + " -> " + ipv4_hdr.destination_address().to_string() + " length:" + to_string(data.length()));

        send_data_to_socket(os.str(), dst);

        auto hash = dst.to_string() + to_string((int)icmp_header::echo_request) 
            + to_string(icmp_hdr.identifier()) + to_string(icmp_hdr.sequence_number());

        add_transfer_table(move(hash), make_shared<IcmpSentData>(pipeline_session, src, dst));
    }
}

void icmpd::client_out_send(const std::string& data){
    if (!m_client_or_server) {
        throw logic_error("[icmp] server cannot call icmpd::client_out_send");
    }

    std::istringstream is(data);

    ipv4_header ipv4_hdr;
    icmp_header icmp_hdr;
    string body;

    if (read_icmp(is, data.length(), ipv4_hdr, icmp_hdr, body)) {

        if (ipv4_hdr.source_address().is_unspecified()) {
            // time exceeded from trojan server (from generate_time_exceeded_icmp)
            auto pipeline = m_service->search_default_pipeline();
            if(pipeline){
                auto addr = pipeline->get_out_socket_endpoint().address();
                if(addr.is_v4()){
                    ipv4_hdr.source_address(addr.to_v4());
                    ipv4_hdr.identification((uint16_t)time(nullptr));  // don't let kernel fill the source address

                    std::ostringstream os;
                    os << ipv4_hdr << icmp_hdr << body;

                    auto dst = ipv4_hdr.destination_address();
                    _log_with_date_time("[icmp] client send out " + ipv4_hdr.source_address().to_string() + " -> " + dst.to_string() + " trojan server time exceeded.");

                    send_data_to_socket(os.str(), dst);
                }else{
                    _log_with_date_time("[icmp] client send out cannot support ipv6!");
                }                
            }            
        } else {
            auto dst = ipv4_hdr.destination_address();
            _log_with_date_time("[icmp] client send out " + ipv4_hdr.source_address().to_string() + " -> " + dst.to_string() + " length:" + to_string(data.length()));

            // cout << "ip header: " << ipv4_hdr.to_string() << endl;
            // cout << "icmp header: " << icmp_hdr.to_string() << endl;
            
            send_data_to_socket(data, dst);
        }
        
    }
}
