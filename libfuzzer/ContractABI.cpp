#include <iostream>
#include <boost/algorithm/string.hpp>
#include <regex>
#include "ContractABI.h"

using namespace std;

namespace fuzzer {
  bytes ContractABI::encodeTuple(vector<TypeDef> tds) {
    bytes ret;
    /* Payload */
    bytes payload;
    vector<int> dataOffset = {0};
    for (auto td : tds) {
      if (td.isDynamic || td.isDynamicArray || td.isSubDynamicArray) {
        bytes data;
        switch (td.dimensions.size()) {
          case 0: {
            data = encodeSingle(td.dt);
            break;
          }
          case 1: {
            data = encodeArray(td.dts, td.isDynamicArray);
            break;
          }
          case 2: {
            data = encode2DArray(td.dtss, td.isDynamicArray, td.isSubDynamicArray);
            break;
          }
        }
        dataOffset.push_back(dataOffset.back() + data.size());
        payload.insert(payload.end(), data.begin(), data.end());
      }
    }
    /* Calculate offset */
    u256 headerOffset = 0;
    for (auto td : tds) {
      if (td.isDynamic || td.isDynamicArray || td.isSubDynamicArray) {
        headerOffset += 32;
      } else {
        switch (td.dimensions.size()) {
          case 0: {
            headerOffset += encodeSingle(td.dt).size();
            break;
          }
          case 1: {
            headerOffset += encodeArray(td.dts, td.isDynamicArray).size();
            break;
          }
          case 2: {
            headerOffset += encode2DArray(td.dtss, td.isDynamicArray, td.isSubDynamicArray).size();
            break;
          }
        }
      }
    }
    bytes header;
    int dynamicCount = 0;
    for (auto td : tds) {
      /* Dynamic in head */
      if (td.isDynamic || td.isDynamicArray || td.isSubDynamicArray) {
        u256 offset = headerOffset + dataOffset[dynamicCount];
        /* Convert to byte */
        for (int i = 0; i < 32; i += 1) {
          byte b = (byte) (offset >> ((32 - i - 1) * 8)) & 0xFF;
          header.push_back(b);
        }
        dynamicCount ++;
      } else {
        /* static in head */
        bytes data;
        switch (td.dimensions.size()) {
          case 0: {
            data = encodeSingle(td.dt);
            break;
          }
          case 1: {
            data = encodeArray(td.dts, td.isDynamicArray);
            break;
          }
          case 2: {
            data = encode2DArray(td.dtss, td.isDynamicArray, td.isSubDynamicArray);
            break;
          }
        }
        header.insert(header.end(), data.begin(), data.end());
      }
    }
    /* Head + Payload */
    ret.insert(ret.end(), header.begin(), header.end());
    ret.insert(ret.end(), payload.begin(), payload.end());
    return ret;
  }
  
  bytes ContractABI::encode2DArray(vector<vector<DataType>> dtss, bool isDynamicArray, bool isSubDynamic) {
    bytes ret;
    if (isDynamicArray) {
      bytes payload;
      bytes header;
      u256 numElem = dtss.size();
      if (isSubDynamic) {
        /* Need Offset*/
        vector<int> dataOffset = {0};
        for (auto dts : dtss) {
          bytes data = encodeArray(dts, isSubDynamic);
          dataOffset.push_back(dataOffset.back() + data.size());
          payload.insert(payload.end(), data.begin(), data.end());
        }
        /* Count */
        for (int i = 0; i < 32; i += 1) {
          byte b = (byte) (numElem >> ((32 - i - 1) * 8)) & 0xFF;
          header.push_back(b);
        }
        for (int i = 0; i < numElem; i += 1) {
          u256 headerOffset =  32 * numElem + dataOffset[i];
          for (int i = 0; i < 32; i += 1) {
            byte b = (byte) (headerOffset >> ((32 - i - 1) * 8)) & 0xFF;
            header.push_back(b);
          }
        }
      } else {
        /* Count */
        for (int i = 0; i < 32; i += 1) {
          byte b = (byte) (numElem >> ((32 - i - 1) * 8)) & 0xFF;
          header.push_back(b);
        }
        for (auto dts : dtss) {
          bytes data = encodeArray(dts, isSubDynamic);
          payload.insert(payload.end(), data.begin(), data.end());
        }
      }
      ret.insert(ret.end(), header.begin(), header.end());
      ret.insert(ret.end(), payload.begin(), payload.end());
      return ret;
    }
    for (auto dts : dtss) {
      bytes data = encodeArray(dts, isSubDynamic);
      ret.insert(ret.end(), data.begin(), data.end());
    }
    return ret;
  }
  
  bytes ContractABI::encodeArray(vector<DataType> dts, bool isDynamicArray) {
    bytes ret;
    /* T[] */
    if (isDynamicArray) {
      /* Calculate header and payload */
      bytes payload;
      bytes header;
      u256 numElem = dts.size();
      if (dts[0].isDynamic) {
        /* If element is dynamic then needs offset */
        vector<int> dataOffset = {0};
        for (auto dt : dts) {
          bytes data = encodeSingle(dt);
          dataOffset.push_back(dataOffset.back() + data.size());
          payload.insert(payload.end(), data.begin(), data.end());
        }
        /* Count */
        for (int i = 0; i < 32; i += 1) {
          byte b = (byte) (numElem >> ((32 - i - 1) * 8)) & 0xFF;
          header.push_back(b);
        }
        /* Offset */
        for (int i = 0; i < numElem; i += 1) {
          u256 headerOffset =  32 * numElem + dataOffset[i];
          for (int i = 0; i < 32; i += 1) {
            byte b = (byte) (headerOffset >> ((32 - i - 1) * 8)) & 0xFF;
            header.push_back(b);
          }
        }
      } else {
        /* Do not need offset, count them */
        for (int i = 0; i < 32; i += 1) {
          byte b = (byte) (numElem >> ((32 - i - 1) * 8)) & 0xFF;
          header.push_back(b);
        }
        for (auto dt : dts) {
          bytes data = encodeSingle(dt);
          payload.insert(payload.end(), data.begin(), data.end());
        }
      }
      ret.insert(ret.end(), header.begin(), header.end());
      ret.insert(ret.end(), payload.begin(), payload.end());
      return ret;
    }
    /* T[k] */
    for (auto dt : dts) {
      bytes data = encodeSingle(dt);
      ret.insert(ret.end(), data.begin(), data.end());
    }
    return ret;
  }
  
  bytes ContractABI::encodeSingle(DataType dt) {
    bytes ret;
    bytes payload = dt.payload();
    if (dt.isDynamic) {
      /* Concat len and data */
      bytes header = dt.header();
      ret.insert(ret.end(), header.begin(), header.end());
      ret.insert(ret.end(), payload.begin(), payload.end());
      return ret;
    }
    ret.insert(ret.end(), payload.begin(), payload.end());
    return ret;
  }
  
  DataType::DataType(bytes value, bool padLeft, bool isDynamic) {
    this->value = value;
    this->padLeft = padLeft;
    this->isDynamic = isDynamic;
  }
  
  bytes DataType::header() {
    u256 size = this->value.size();
    bytes ret;
    for (int i = 0; i < 32; i += 1) {
      byte b = (byte) (size >> ((32 - i - 1) * 8)) & 0xFF;
      ret.push_back(b);
    }
    return ret;
  }
  
  bytes DataType::payload() {
    auto paddingLeft = [this](double toLen) {
      bytes ret(toLen - this->value.size(), 0);
      ret.insert(ret.end(), this->value.begin(), this->value.end());
      return ret;
    };
    auto paddingRight = [this](double toLen) {
      bytes ret;
      ret.insert(ret.end(), this->value.begin(), this->value.end());
      while(ret.size() < toLen) ret.push_back(0);
      return ret;
    };
    if (this->value.size() > 32) {
      if (!this->isDynamic) throw "Size of static <= 32 bytes";
      int valueSize = this->value.size();
      int finalSize = valueSize % 32 == 0 ? valueSize : (valueSize / 32 + 1) * 32;
      if (this->padLeft) return paddingLeft(finalSize);
      return paddingRight(finalSize);
    }
    if (this->padLeft) return paddingLeft(32);
    return paddingRight(32);
  }
  
  string TypeDef::toRealname(string name) {
    string fullType = toFullname(name);
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
  
  string TypeDef::toFullname(string name) {
    string searchPatterns[4] = {"int[", "uint[", "fixed[", "ufixed["};
    string replaceCandidates[4] = {"int256", "uint256", "fixed128x128", "ufixed128x128"};
    for (int i = 0; i < 4; i += 1) {
      string pattern = searchPatterns[i];
      string candidate = replaceCandidates[i];
      if (boost::starts_with(name, pattern))
        return candidate + name.substr(pattern.length() - 1);
      if (name == pattern.substr(0, pattern.length() - 1)) return candidate;
    }
    return name;
  }
  
  vector<int> TypeDef::extractDimension(string name) {
    vector<int> ret;
    smatch sm;
    regex_match(name, sm, regex("[a-z]+[0-9]*\\[(\\d*)\\]\\[(\\d*)\\]"));
    if (sm.size() == 3) {
      /* Two dimension array */
      ret.push_back(sm[1] == "" ? 0 : stoi(sm[1]));
      ret.push_back(sm[2] == "" ? 0 : stoi(sm[2]));
      return ret;
    }
    regex_match(name, sm, regex("[a-z]+[0-9]*\\[(\\d*)\\]"));
    if (sm.size() == 2) {
      /* One dimension array */
      ret.push_back(sm[1] == "" ? 0 : stoi(sm[1]));
      return ret;
    }
    return ret;
  }
  
  void TypeDef::addValue(vector<vector<bytes>> vss) {
    if (this->dimensions.size() != 2) throw "Invalid dimension";;
    for (auto vs : vss) {
      vector<DataType> dts;
      for (auto v : vs) {
        dts.push_back(DataType(v, this->padLeft, this->isDynamic));
      }
      this->dtss.push_back(dts);
    }
  }
  
  void TypeDef::addValue(vector<bytes> vs) {
    if (this->dimensions.size() != 1) throw "Invalid dimension";
    for (auto v : vs) {
      this->dts.push_back(DataType(v, this->padLeft, this->isDynamic));
    }
  }
  
  void TypeDef::addValue(bytes v) {
    if (this->dimensions.size()) throw "Invalid dimension";
    this->dt = DataType(v, this->padLeft, this->isDynamic);
  }
  
  TypeDef::TypeDef(string name) {
    this->name = name;
    this->fullname = toFullname(name);
    this->realname = toRealname(name);
    this->dimensions = extractDimension(name);
    this->padLeft = !boost::starts_with(this->fullname, "bytes") && !boost::starts_with(this->fullname, "string");
    int numDimension = this->dimensions.size();
    if (!numDimension) {
      this->isDynamic = this->fullname == "string" || this->name == "bytes";
      this->isDynamicArray = false;
      this->isSubDynamicArray = false;
    } else if (numDimension == 1) {
      this->isDynamic = boost::starts_with(this->fullname, "string[")
      || boost::starts_with(this->fullname, "bytes[");
      this->isDynamicArray = this->dimensions[0] == 0;
      this->isSubDynamicArray = false;
    } else {
      this->isDynamic = boost::starts_with(this->fullname, "string[")
      || boost::starts_with(this->fullname, "bytes[");
      this->isDynamicArray = this->dimensions[0] == 0;
      this->isSubDynamicArray = this->dimensions[1] == 0;
    }
  }
}
