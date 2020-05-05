#include "icmpd.h"

#include <iostream>
#include <stdexcept>

#include "core/service.h"
#include "session/pipelinesession.h"

using namespace std;
using namespace boost::asio::ip;

icmpd::icmpd(boost::asio::io_service& io_service) : m_socket(io_service, icmp::v4()),
                                                    m_timer(io_service, boost::asio::chrono::seconds(ICMP_WAIT_TRANSFER_TIME)),
                                                    m_start_timer(false) {
    int fd = m_socket.native_handle();
    int opt = 1;
    if (setsockopt(fd, SOL_IP, IP_HDRINCL, &opt, sizeof(opt))) {
        throw runtime_error("[icmp] setsockopt IP_HDRINCL failed!");
    }
}

void icmpd::timer_async_wait(){
    auto curr_time = time(NULL);
    for(auto it = m_transfer_table.begin();it != m_transfer_table.end();){
        if (curr_time - it->second->sent_time > ICMP_WAIT_TRANSFER_TIME) {
            _log_with_date_time("[icmp] timeout, remove " + it->second->source.to_string() + " -> " + it->second->destination.to_string());
            it = m_transfer_table.erase(it);
        }else{
            ++it;
        }
    }

    auto self = shared_from_this();
    m_timer.async_wait([this, self](const boost::system::error_code error) {
        if (!error) {
            timer_async_wait();
        }        
    });
}

bool icmpd::read_icmp(std::istream& is, size_t length, ipv4_header& ipv4_hdr, icmp_header& icmp_hdr, std::string& body) {
    is >> ipv4_hdr >> icmp_hdr;

    if(is){
        size_t remain = length - ipv4_hdr.header_length() - icmp_header::HEADER_LENGTH;
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
    if (!m_start_timer) {
        m_start_timer = true;
        m_timer.async_wait([this, self](const boost::system::error_code) {
            timer_async_wait();
        });
    }
    m_buffer.consume(m_buffer.size());    
    m_socket.async_receive(m_buffer.prepare(65536), [this, self](boost::system::error_code ec, size_t length) {
        if (!ec) {
            m_buffer.commit(length);
            std::istream is(&m_buffer);

            ipv4_header ipv4_hdr;
            icmp_header icmp_hdr;
            string body;

            if (read_icmp(is, length, ipv4_hdr, icmp_hdr, body)) {
                
                _log_with_date_time("[icmp] recv " + ipv4_hdr.source_address().to_string() + " -> " + ipv4_hdr.destination_address().to_string());

                if (m_client_or_server) {
                    if (icmp_hdr.type() == icmp_header::echo_request) { // only proxy echo_request for client
                        if(ipv4_hdr.time_to_live() == 1){
                            send_back_time_exceeded(ipv4_hdr, icmp_hdr);
                        }else{
                            std::ostringstream os;
                            os << ipv4_hdr << icmp_hdr << body;
                            m_service->session_async_send_to_pipeline_icmp(os.str(), [this, self](const boost::system::error_code) {
                                // nothing to process...
                            });
                        }
                    }
                } else {
                    if (icmp_hdr.type() == icmp_header::echo_reply){ // for ping
                        auto hash = ipv4_hdr.source_address().to_string() + to_string((int)icmp_header::echo_request) + to_string(icmp_hdr.identifier());
                        auto it = m_transfer_table.find(hash);
                        if (it != m_transfer_table.end()) {
                            auto session = it->second;
                            if(!session->pipeline_session.expired()){
                                ipv4_hdr.destination_address(session->source);

                                std::ostringstream os;
                                os << ipv4_hdr << icmp_hdr << body;

                                static_cast<PipelineSession*>(session->pipeline_session.lock().get())->session_write_icmp(os.str(), [this, self](const boost::system::error_code) {
                                    // nothing to process...
                                });

                                m_transfer_table.erase(it);
                            }
                        }
                    } 
                    else if(icmp_hdr.type() == icmp_header::time_exceeded){ // for traceroute
                        // TODO
                    }
                    else if (icmp_hdr.type() == icmp_header::destination_unreachable) {  // for traceroute
                        // TODO
                    }                    
                }
            }
        }

        start_recv();
    });
}

void icmpd::send_back_time_exceeded(ipv4_header& ipv4_hdr, icmp_header& icmp_hdr) {
    std::ostringstream os;
    os << ipv4_hdr << icmp_hdr;

    auto send_back_body = os.str();
    
    os.clear();
    os.seekp(ios::beg);

    auto dst = ipv4_hdr.destination_address();
    auto src = ipv4_hdr.source_address();

    ipv4_hdr.destination_address(src);
    ipv4_hdr.source_address(address_v4());
    ipv4_hdr.identification(0);

    icmp_hdr.type(icmp_header::time_exceeded);
    icmp_hdr.code(0);
    icmp_hdr.assign_checksum(send_back_body);

    os << ipv4_hdr << icmp_hdr << send_back_body;

    _log_with_date_time("[icmp] send_back_time_exceeded " + ipv4_hdr.source_address().to_string() + " -> " + ipv4_hdr.destination_address().to_string());

    m_socket.send_to(boost::asio::buffer(os.str()), icmp::endpoint(dst, 0));
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

        auto dst = ipv4_hdr.destination_address();
        auto src = ipv4_hdr.source_address();
        ipv4_hdr.source_address(address_v4()); // change the src as 0.0.0.0, kernel will fill it
        ipv4_hdr.identification(0);

        std::ostringstream os;
        os << ipv4_hdr << icmp_hdr << body;

        _log_with_date_time("[icmp] server send out " + ipv4_hdr.source_address().to_string() + " -> " + ipv4_hdr.destination_address().to_string());

        m_socket.send_to(boost::asio::buffer(os.str()), icmp::endpoint(dst, 0));

        auto hash = dst.to_string() + to_string((int)icmp_header::echo_request) + to_string(icmp_hdr.identifier());
        m_transfer_table.emplace(make_pair(hash, make_shared<IcmpSentData>(pipeline_session, src, dst)));
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

        _log_with_date_time("[icmp] client send out " + ipv4_hdr.source_address().to_string() + " -> " + ipv4_hdr.destination_address().to_string());

        auto dst = ipv4_hdr.destination_address();
        m_socket.send_to(boost::asio::buffer(data), icmp::endpoint(dst, 0));
    }
}
