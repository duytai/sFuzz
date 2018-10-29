#pragma once
#include <iostream>
#include <vector>
#include <libdevcore/FixedHash.h>

using namespace std;
using namespace dev;

namespace fuzzer {
    const int MAX_DYNAMIC_SIZE = 256;
    
    bytes functionSelector(string name, vector<string> types);
    bytes encodeABI(string name, vector<string> types, vector<bytes> values);
    bytes createElem(vector<string> types);
    vector<bytes> decodeElem(vector<string> types, bytes data);
    int getElemSize(vector<string> types);
    string tofullType(string type);
    string toExactType(string type);
    int getTypeSize(string type);
};
