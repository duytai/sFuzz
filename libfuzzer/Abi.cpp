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
  
  bytes encodeABI(string name, vector<string> types, vector<bytes> values) {
    auto isArray = [](string type){ return type.find_last_of("]") == type.length() - 1;};
    auto paddingLeft = [](bytes d, int size) {
      if ((int) d.size() > size) throw "No need to pad";
      bytes temp(size - d.size(), 0);
      temp.insert(temp.end(), d.begin(), d.end());
      return temp;
    };
    auto paddingRight = [](bytes d, int size) {
      if ((int) d.size() > size) throw "No need to pad";
      bytes temp;
      copy(d.begin(), d.end(), back_inserter(temp));
      while ((int)temp.size() < size) temp.push_back(0);
      return temp;
    };
    /*
     * Data size must be multiple of 32;
     */
    auto exactDataSize = [](int valueSize) {
      int exactSize = valueSize % 32 == 0 ? valueSize : (valueSize / 32 + 1) * 32;
      return exactSize;
    };
    bytes payload;
    u256 offset = types.size() * 32;
    for (int i = 0; i < (int) values.size(); i += 1) {
      auto exactType = toExactType(types[i]);
      auto value = values[i];
      if (isArray(exactType)) {
        /* Dynamic or Both */
      } else {
        if (exactType == "string" || exactType == "bytes") {
          /* Dynamic: Add data offset from starting  */
          for (int j = 0; j < 32; j++) {
            auto v = (byte)(offset >> ((32 - j - 1) * 8)) & 0xFF;
            payload.push_back(v);
          }
          /* 32: describe len and actual data size */
          offset += exactDataSize(value.size()) + 32;
        } else {
          /*
           * Static
           * bytes - padding right
           * int,uint - padding left
           */
          bytes d = boost::starts_with(exactType, "bytes")
            ? paddingRight(value, 32)
            : paddingLeft(value, 32);
          payload.insert(payload.end(), d.begin(), d.end());
        }
      }
    }
    /* Add dynamic data */
    for (int i = 0; i < (int) values.size(); i += 1) {
      auto exactType = toExactType(types[i]);
      auto value = values[i];
      if (isArray(exactType)) {
        /* Dynamic or Both */
      } else {
        if (exactType == "string" || exactType == "bytes") {
          /* len */
          u256 dataSize = value.size();
          for (int j = 0; j < 32; j++) {
            auto v = (byte)(dataSize >> ((32 - j - 1) * 8)) & 0xFF;
            payload.push_back(v);
          }
          /* data */
          bytes d = paddingRight(value, exactDataSize(value.size()));
          payload.insert(payload.end(), d.begin(), d.end());
        }
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
