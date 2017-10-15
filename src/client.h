#ifndef _CLIENT_H
#define _CLIENT_H

#include "service.h"

class Config;

class Client : public Service {
public:
    Client(const Config &config);
    int run();
};

#include "config.h"

#endif // _CLIENT_H
