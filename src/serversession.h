#ifndef _SERVERSESSION_H_
#define _SERVERSESSION_H_

#include "session.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

class ServerSession : public Session {
private:
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>in_socket;
    boost::asio::ip::tcp::socket out_socket;
public:
    ServerSession(const Config &config, boost::asio::io_service &io_service, boost::asio::ssl::context &ssl_context);
    boost::asio::basic_socket<boost::asio::ip::tcp, boost::asio::stream_socket_service<boost::asio::ip::tcp> >& accept_socket();
    void start();
};

#endif // _SERVERSESSION_H_
