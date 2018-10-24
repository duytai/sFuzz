#include <iostream>
#include <vector>
#include <libdevcore/FixedHash.h>

using namespace std;
using namespace dev;

namespace fuzzer {
    bytes functionSelector(string name, vector<string> types);
    bytes encode(string name, vector<string> types);
    string tofullType(string type);
};
