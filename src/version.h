#ifndef _VERSION_H_
#define _VERSION_H_

#include <string>

class Version {
private:
    const static std::string version;
public:
    static std::string get_version();
};

#endif // _VERSION_H_
