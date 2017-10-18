#ifndef _LOG_H_
#define _LOG_H_

#include <string>
#include <boost/asio.hpp>

class Log {
public:
    static void log(const std::string &message);
    static void log_with_date_time(const std::string &message);
    static void log_with_endpoint(const boost::asio::ip::tcp::endpoint &endpoint, const std::string &message);
};

#endif // _LOG_H_
