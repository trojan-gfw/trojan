#ifndef _SESSION_H_
#define _SESSION_H_

#include <boost/asio.hpp>

class Config;

class Session {
protected:
    enum {
        MAX_LENGTH = 8192
    };
    const Config &config;
    boost::asio::io_service &io_service;
public:
    Session(const Config &config, boost::asio::io_service &io_service);
    virtual boost::asio::basic_socket<boost::asio::ip::tcp, boost::asio::stream_socket_service<boost::asio::ip::tcp> >& accept_socket() = 0;
    virtual void start() = 0;
};

#include "config.h"

#endif // _SESSION_H_
