#include "version.h"
#include <string>
using namespace std;

const string Version::version("0.1.0");

string Version::get_version() {
    return version;
}
