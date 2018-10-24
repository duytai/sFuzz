#include "Abi.h"
#include <boost/algorithm/string.hpp>
#include <vector>
#include <libdevcore/SHA3.h>
#include <libdevcore/FixedHash.h>

using namespace std;
using namespace dev;

namespace fuzzer {
  string tofullType(string type) {
    string searchPatterns[4] = {"int[", "uint[", "fixed[", "ufixed["};
    string replaceCandidates[4] = {"int256", "uint256", "fixed128x128", "ufixed128x128"};
    for (int i = 0; i < 4; i += 1) {
      string pattern = searchPatterns[i];
      string candidate = replaceCandidates[i];
      if (boost::starts_with(type, pattern)) return candidate + type.substr(pattern.length() - 1);
      if (type == pattern.substr(0, pattern.length() - 1)) return candidate;
    }
    return type;
  }
  
  bytes functionSelector(string name, vector<string> types) {
    vector<string> fullTypes;
    transform(types.begin(), types.end(), back_inserter(fullTypes), ptr_fun(tofullType));
    bytes fullSelector = sha3(name + "(" + boost::algorithm::join(fullTypes, ",") + ")").ref().toBytes();
    return bytes(fullSelector.begin(), fullSelector.begin() + 4);
  }
  
  bytes encode(string name, vector<string> types) {
    auto isArray = [](string type){ return type.find_last_of("]") == type.length() - 1;};
    for (string type : types) {
      if (isArray(type) || type == "string" || type == "bytes")
        throw "Have not supported dynamic type yet !";
    }
    bytes base = functionSelector(name, types);
    bytes ext(types.size() * 32, 0);
    base.insert(base.end(), ext.begin(), ext.end());
    return base;
  }
}
