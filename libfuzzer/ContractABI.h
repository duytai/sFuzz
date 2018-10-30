#pragma once
#include <iostream>
#include <vector>
#include <libdevcore/FixedHash.h>

using namespace dev;
using namespace std;

namespace fuzzer {
  struct DataType {
    bytes value;
    bool padLeft;
    bool isDynamic;
    public:
      DataType(bytes value, bool padLeft, bool isDynamic);
      bytes payload();
      bytes header();
  };
  
  class ContractABI {
    public:
      static bytes encode2DArray(vector<vector<DataType>> dtss, bool isDynamic, bool isSubDynamic);
      static bytes encodeArray(vector<DataType> dts, bool isDynamicArray);
      static bytes encodeSingle(DataType dt);
  };
}
