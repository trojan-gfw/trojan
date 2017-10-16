#ifndef _SERVERSESSION_H_
#define _SERVERSESSION_H_

#include "session.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

class ServerSession : public Session {
public:
    ServerSession(const Config &config, boost::asio::io_service &io_service, boost::asio::ssl::context &ssl_context);
    boost::asio::ip::tcp::socket& accept_socket();
    void start();
};

#endif // _SERVERSESSION_H_
