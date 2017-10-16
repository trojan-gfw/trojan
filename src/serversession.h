#ifndef _SERVERSESSION_H_
#define _SERVERSESSION_H_

#include "session.h"
#include <boost/asio.hpp>

class ServerSession : public Session {
public:
    ServerSession(const Config &config, boost::asio::io_service &io_service);
    boost::asio::ip::tcp::socket& socket();
    void start();
};

#endif // _SERVERSESSION_H_
