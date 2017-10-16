#ifndef _SERVICE_H_
#define _SERVICE_H_

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

class Config;

class Service {
private:
    const Config &config;
    boost::asio::io_service io_service;
    boost::asio::ip::tcp::acceptor socket_acceptor;
    boost::asio::ssl::context ssl_context;
    void async_accept();
public:
    Service(const Config &config);
    int run();
};

#include "config.h"

#endif // _SERVICE_H_
