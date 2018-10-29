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
      if (boost::starts_with(type, pattern))
        return candidate + type.substr(pattern.length() - 1);
      if (type == pattern.substr(0, pattern.length() - 1)) return candidate;
    }
    return type;
  }
  
  string toExactType(string type) {
    string fullType = tofullType(type);
    string searchPatterns[2] = {"address[", "bool["};
    string replaceCandidates[2] = {"uint160", "uint8"};
    for (int i = 0; i < 2; i += 1) {
      string pattern = searchPatterns[i];
      string candidate = replaceCandidates[i];
      if (boost::starts_with(fullType, pattern))
        return candidate + fullType.substr(pattern.length() - 1);
      if (fullType == pattern.substr(0, pattern.length() - 1)) return candidate;
    }
    return fullType;
  }
  
  int getTypeSize(string type) {
    string exactType = toExactType(type);
    if (exactType == "string" || exactType == "bytes")
      return MAX_DYNAMIC_SIZE;
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
  /*
   * Receive normalized data:
   * - Already padding left (int, uint) and right (bytes, string)
   */
  bytes encodeABI(string name, vector<string> types, vector<bytes> values) {
    auto isArray = [](string type){ return type.find_last_of("]") == type.length() - 1;};
    auto int4To32Bytes = [](u256 v) {
      bytes ret;
      for (int j = 0; j < 32; j++) {
        auto b = (byte)(v >> ((32 - j - 1) * 8)) & 0xFF;
        ret.push_back(b);
      }
      return ret;
    };
    /*
     * OFFSET: if type is dynamic
     * DATA: if type is static
     */
    u256 offset = types.size() * 32;
    auto encodeHead = [&](string type, bytes value) {
      if (type == "string" || type == "bytes") {
        bytes ret = int4To32Bytes(offset);
        offset += value.size() + 32;
        return ret;
      }
      return value;
    };
    auto encodeTail = [=](string type, bytes value) {
      bytes ret;
      /* Only dynamic has tail */
      if (type == "string" || type == "bytes") {
        bytes bb = int4To32Bytes(value.size());
        ret.insert(ret.end(), bb.begin(), bb.end());
        ret.insert(ret.end(), value.begin(), value.end());
      }
      return ret;
    };
    bytes payload;
    for (int i = 0; i < (int) values.size(); i += 1) {
      auto exactType = toExactType(types[i]);
      auto value = values[i];
      if (isArray(exactType)) {
        /* Dynamic or Both */
      } else {
        bytes bb;
        /* Dynamic: Add data offset from starting  */
        bytes head = encodeHead(exactType, value);
        payload.insert(payload.end(), head.begin(), head.end());
      }
    }
    /* Add dynamic data */
    for (int i = 0; i < (int) values.size(); i += 1) {
      auto exactType = toExactType(types[i]);
      auto value = values[i];
      if (isArray(exactType)) {
        /* Dynamic or Both */
      } else {
        bytes tail = encodeTail(exactType, value);
        payload.insert(payload.end(), tail.begin(), tail.end());
      }
    }
    bytes base = name == "" ? bytes{} : functionSelector(name, types);
    base.insert(base.end(), payload.begin(), payload.end());
    return base;
  }
  
  bytes createElem(vector<string> types) {
    int totalSize = 0;
    for (auto type : types) totalSize += getTypeSize(type);
    return bytes(totalSize, 0);
  }
  
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
  
  int getElemSize(vector<string> types) {
    int totalSize = 0;
    for (auto type : types) totalSize += getTypeSize(type);
    return totalSize;
  }
}
