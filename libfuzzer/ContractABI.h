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
      DataType(){};
      DataType(bytes value, bool padLeft, bool isDynamic);
      bytes payload();
      bytes header();
  };
  
  struct TypeDef {
    string name;
    string fullname;
    string realname;
    bool padLeft;
    bool isDynamic;
    bool isDynamicArray;
    bool isSubDynamicArray;
    public:
      TypeDef(string name);
      void addValue(bytes v);
      void addValue(vector<bytes> vs);
      void addValue(vector<vector<bytes>> vss);
      static string toFullname(string name);
      static string toRealname(string name);
      vector<int> extractDimension(string name);
      vector<int> dimensions;
      DataType dt;
      vector<DataType> dts;
      vector<vector<DataType>> dtss;
  };
  
  class ContractABI {
    public:
      static bytes encodeTuple(vector<TypeDef> tds);
      static bytes encode2DArray(vector<vector<DataType>> dtss, bool isDynamic, bool isSubDynamic);
      static bytes encodeArray(vector<DataType> dts, bool isDynamicArray);
      static bytes encodeSingle(DataType dt);
  };
}
