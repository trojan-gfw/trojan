#ifndef _SESSION_H_
#define _SESSION_H_

#include <cstdint>
#include <queue>
#include <boost/asio.hpp>

class Config;

class Session {
protected:
    enum {
        MAX_LENGTH = 8192
    };
    const Config &config;
    uint8_t in_read_buf[MAX_LENGTH];
    std::queue<std::string>in_write_queue;
    uint8_t out_read_buf[MAX_LENGTH];
    std::queue<std::string>out_write_queue;
    bool closing, destroying;
    boost::asio::ip::tcp::resolver resolver;
public:
    Session(const Config &config, boost::asio::io_service &io_service);
    virtual boost::asio::basic_socket<boost::asio::ip::tcp, boost::asio::stream_socket_service<boost::asio::ip::tcp> >& accept_socket() = 0;
    virtual void start() = 0;
};

#include "config.h"

#endif // _SESSION_H_
