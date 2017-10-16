#ifndef _CLIENTSESSION_H_
#define _CLIENTSESSION_H_

#include "session.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

class ClientSession : public Session {
private:
    boost::asio::ip::tcp::socket in_socket;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>out_socket;
public:
    ClientSession(const Config &config, boost::asio::io_service &io_service, boost::asio::ssl::context &ssl_context);
    boost::asio::basic_socket<boost::asio::ip::tcp, boost::asio::stream_socket_service<boost::asio::ip::tcp> >& accept_socket();
    void start();
};

#endif // _CLIENTSESSION_H_
