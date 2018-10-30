#include <iostream>
#include "ContractABI.h"

using namespace std;

namespace fuzzer {
  bytes ContractABI::encode2DArray(vector<vector<DataType>> dtss, bool isDynamic, bool isSubDynamic) {
    bytes ret;
    if (isDynamic) {
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
}
