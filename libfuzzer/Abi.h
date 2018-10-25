#include <iostream>
#include <vector>
#include <libdevcore/FixedHash.h>

using namespace std;
using namespace dev;

namespace fuzzer {
    bytes functionSelector(string name, vector<string> types);
    bytes encodeABI(string name, vector<string> types, vector<string> values);
    string tofullType(string type);
};
