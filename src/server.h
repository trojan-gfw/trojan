#ifndef _SERVER_H_
#define _SERVER_H_

#include "service.h"

class Config;

class Server : public Service {
public:
    Server(const Config &config);
    int run();
};

#include "config.h"

#endif // _SERVER_H_
