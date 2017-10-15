#ifndef _SERVICE_H_
#define _SERVICE_H_

class Config;

class Service {
protected:
    Config const *config;
public:
    Service(const Config &config);
    virtual int run() = 0;
};

#include "config.h"

#endif // _SERVICE_H_
