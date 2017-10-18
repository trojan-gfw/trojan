#ifndef _CLIENTSESSION_H_
#define _CLIENTSESSION_H_

#include "session.h"
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

class ClientSession : public Session {
private:
    enum Status {
        HANDSHAKE,
        REQUEST,
        CONNECTING_REMOTE,
        FORWARD
    } status;
    boost::asio::ip::tcp::socket in_socket;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>out_socket;
    void destroy();
    void in_async_read();
    void in_async_write();
    void in_recv(const std::string &data);
    void in_send(const std::string &data);
    void out_async_read();
    void out_async_write();
    void out_recv(const std::string &data);
    void out_send(const std::string &data);
public:
    ClientSession(const Config &config, boost::asio::io_service &io_service, boost::asio::ssl::context &ssl_context);
    boost::asio::basic_socket<boost::asio::ip::tcp, boost::asio::stream_socket_service<boost::asio::ip::tcp> >& accept_socket();
    void start();
};

#endif // _CLIENTSESSION_H_
