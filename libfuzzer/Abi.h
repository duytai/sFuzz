#include <iostream>
#include <vector>
#include <libdevcore/FixedHash.h>

using namespace std;
using namespace dev;

namespace fuzzer {
    bytes functionSelector(string name, vector<string> types);
    bytes encodeABI(string name, vector<string> types, vector<bytes> values);
    bytes createEmptyTestcase(vector<string> types);
    vector<bytes> decodeTestcase(vector<string> types, bytes data);
    string tofullType(string type);
    string toExactType(string type);
    int getTypeSize(string type);
};
