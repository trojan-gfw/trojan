#ifndef _LOG_H_
#define _LOG_H_

#include <string>

class Log {
public:
    static void log(const std::string &message);
    static void log_with_date_time(const std::string &message);
};

#endif // _LOG_H_
