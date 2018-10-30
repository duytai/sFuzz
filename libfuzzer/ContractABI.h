#pragma once
#include <iostream>
#include <vector>
#include <boost/algorithm/string.hpp>
#include <libdevcore/FixedHash.h>

using namespace dev;
using namespace std;

namespace fuzzer {
  class DataType {
    public:
      bytes value;
      bool padLeft;
      bool isDynamic;
      DataType(bytes value, bool padLeft, bool isDynamic);
      bytes payload();
      bytes header();
  };
  
  struct TypeDef {
    string name;
    string fullname;
    string realname;
    int dimension;
    bool isDynamic;
    bool isDynamicArray;
    bool isSubDynamicArray;
    public:
      TypeDef(string name);
      static string toFullname(string name);
      static string toRealname(string name);
      vector<int> getDimension(string name);
  };
  
  class ContractABI {
    public:
      static bytes encode2DArray(vector<vector<DataType>> dtss, bool isDynamic, bool isSubDynamic);
      static bytes encodeArray(vector<DataType> dts, bool isDynamicArray);
      static bytes encodeSingle(DataType dt);
  };
}
