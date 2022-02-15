#pragma once
#include <vector>
#include "Common.h"

using namespace dev;
using namespace std;

namespace fuzzer {
  using Accounts = vector<tuple<bytes, u160, u256, bool>>;
  using FakeBlock = tuple<bytes, int64_t, int64_t>;
  
  struct DataType {
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
  
  struct FuncDef {
    string name;
    bool payable;
    vector<TypeDef> tds;
    uint32_t selector;
    bytes selectorBytes;
    FuncDef(){};
    FuncDef(string name, vector<TypeDef> tds, bool payable);
  };
  
  class ContractABI {
    vector<bytes> accounts;
    bytes block;
    public:
      int constructorIdx = -1;
      int totalFuncsNum;
      vector<FuncDef> fds;
      unordered_map<uint32_t, size_t> funcIdxs;
      ContractABI(){};
      ContractABI(string abiJson);
      /* get Ith FuncDef except for constructor*/
      int ithFuncDefIndex(int i);
      /* encoded ABI of contract constructor */
      bytes encodeConstructor();
      /* encoded ABI of contract functions */
      vector<bytes> encodeFunctions();
      /* encoded contract functions with given data and order */
      vector<bytes> encodeFunctions(bytes data, vector<size_t> order);
      /* Create random testcase for fuzzer */
      bytes randomTestcase();
      /* Update then call encodeConstructor/encodeFunction to feed to evm */
      void updateTestData(bytes data);
      /* Standard Json */
      string toStandardJson();
      uint64_t totalFuncs();
      Accounts decodeAccounts();
      FakeBlock decodeBlock();
      bool isPayable(string name);
      Address getSender();
      static bytes encodeTuple(vector<TypeDef> tds);
      static bytes encode2DArray(vector<vector<DataType>> dtss, bool isDynamic, bool isSubDynamic);
      static bytes encodeArray(vector<DataType> dts, bool isDynamicArray);
      static bytes encodeSingle(DataType dt);
      static bytes postprocessTestData(bytes data);
  }; 
  static bytes functionSelector(string name, vector<TypeDef> tds);
      
}
