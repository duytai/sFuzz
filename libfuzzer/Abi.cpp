#include "Abi.h"
#include <boost/algorithm/string.hpp>
#include <vector>
#include <regex>
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
  
  string toExactType(string type) {
    string fullType = tofullType(type);
    if (fullType == "address") return "uint160";
    if (fullType == "bool") return "uint8";
    return fullType;
  }
  // TODO: handle dynamic case
  int getTypeSize(string type) {
    string exactType = toExactType(type);
    smatch sm;
    regex_match(exactType, sm, regex("[a-z]+(\\d+)"));
    return stoi(sm[1]) / 8;
  }
  
  bytes functionSelector(string name, vector<string> types) {
    vector<string> fullTypes;
    transform(types.begin(), types.end(), back_inserter(fullTypes), ptr_fun(tofullType));
    bytes fullSelector = sha3(name + "(" + boost::algorithm::join(fullTypes, ",") + ")").ref().toBytes();
    return bytes(fullSelector.begin(), fullSelector.begin() + 4);
  }
  // TODO: handle dynamic case
  bytes encodeABI(string name, vector<string> types, vector<bytes> values) {
    auto isArray = [](string type){ return type.find_last_of("]") == type.length() - 1;};
    auto paddingLeft = [](bytes d, int size) {
      if ((int) d.size() > size) throw "No need to pad";
      bytes temp(size - d.size(), 0);
      temp.insert(temp.end(), d.begin(), d.end());
      return temp;
    };
    bytes payload;
    for (string type : types) {
      if (isArray(type) || type == "string" || type == "bytes")
        throw "Have not supported dynamic type yet !";
    }
    bytes base = name == "" ? bytes{} : functionSelector(name, types);
    for (auto value: values) {
      bytes d = paddingLeft(value, 32);
      payload.insert(payload.end(), d.begin(), d.end());
    }
    base.insert(base.end(), payload.begin(), payload.end());
    return base;
  }
  // TODO: handle dynamic case
  bytes createElem(vector<string> types) {
    int totalSize = 0;
    for (auto type : types) totalSize += getTypeSize(type);
    return bytes(totalSize, 0);
  }
  // TODO: handle dynamic case
  vector<bytes> decodeElem(vector<string> types, bytes data) {
    vector<bytes> results;
    int startAt = 0;
    for (auto type : types) {
      bytes d;
      int size = getTypeSize(type);
      copy(data.begin() + startAt, data.begin() + startAt + size, back_inserter(d));
      results.push_back(d);
      startAt += size;
    }
    return results;
  }
  // TODO: handle dynamic case
  int getElemSize(vector<string> types) {
    int totalSize = 0;
    for (auto type : types) totalSize += getTypeSize(type);
    return totalSize;
  }
}
