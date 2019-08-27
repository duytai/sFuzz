#include <regex>
#include "ContractABI.h"

using namespace std;
namespace pt = boost::property_tree;

namespace fuzzer {
  FuncDef::FuncDef(string name, vector<TypeDef> tds, bool payable) {
    this->name = name;
    this->tds = tds;
    this->payable = payable;
  }
  
  FakeBlock ContractABI::decodeBlock() {
    if (!block.size()) throw "Block is empty";
    auto numberInBytes = bytes(block.begin(), block.begin() + 8);
    auto timestampInBytes = bytes(block.begin() + 8, block.begin() + 16);
    auto number = u64("0x" + toHex(numberInBytes));
    auto timestamp = u64("0x" + toHex(timestampInBytes));
    return make_tuple(block, (int64_t)number, (int64_t)timestamp);
  }

  Address ContractABI::getSender() {
    auto accounts = decodeAccounts();
    for (auto account : accounts) {
      if (get<3>(account)) return get<1>(account);
    }
  }

  Accounts ContractABI::decodeAccounts() {
    unordered_set<string> accountSet;
    Accounts ret;
    auto isSender = true;
    for (auto account : accounts) {
      bytes balanceInBytes(account.begin(), account.begin() + 12);
      bytes addressInBytes(account.begin() + 12, account.end());
      u256 balance = u256("0x" + toHex(balanceInBytes));
      u160 address = u160("0x" + toHex(addressInBytes));
      auto pair = accountSet.insert(toHex(addressInBytes));
      if (pair.second) {
        ret.push_back(make_tuple(account, address, balance, isSender));
        isSender = false;
      }
    }
    return ret;
  }
  
  uint64_t ContractABI::totalFuncs() {
    return count_if(fds.begin(), fds.end(), [](FuncDef fd) {
      return fd.name != "";
    });
  }
  
  string ContractABI::toStandardJson() {
    stringstream os;
    pt::ptree funcs;
    pt::ptree root;
    for (auto fd : this->fds) {
      pt::ptree func;
      pt::ptree inputs;
      func.put("name", fd.name);
      for (auto td : fd.tds) {
        pt::ptree input;
        input.put("type", td.name);
        switch (td.dimensions.size()) {
          case 0: {
            input.put("value", "0x" + toHex(td.dt.value));
            break;
          }
          case 1: {
            pt::ptree values;
            for (auto dt : td.dts) {
              pt::ptree value;
              value.put_value("0x" + toHex(dt.value));
              values.push_back(make_pair("", value));
            }
            input.add_child("value", values);
            break;
          }
          case 2: {
            pt::ptree valuess;
            for (auto dts : td.dtss) {
              pt::ptree values;
              for (auto dt : dts) {
                pt::ptree value;
                value.put_value("0x" + toHex(dt.value));
                values.push_back(make_pair("", value));
              }
              valuess.push_back(make_pair("", values));
            }
            input.add_child("value", valuess);
            break;
          }
        }
        inputs.push_back(make_pair("", input));
      }
      func.add_child("inputs", inputs);
      funcs.push_back(make_pair("", func));
    }
    root.add_child("functions", funcs);
    /* Accounts */
    unordered_set<string> accountSet; // to check exists
    pt::ptree accs;
    auto accountInTuples = decodeAccounts();
    for (auto account : accountInTuples) {
      auto accountInBytes = get<0>(account);
      auto balance = get<2>(account);
      auto address = bytes(accountInBytes.begin() + 12, accountInBytes.end());
      pt::ptree acc;
      acc.put("address", "0x" + toHex(address));
      acc.put("balance", balance);
      accs.push_back(make_pair("", acc));
    }
    root.add_child("accounts", accs);
    pt::write_json(os, root);
    return os.str();
  }
  /*
   * Validate generated data before sending it to vm
   * msg.sender address can not be 0 (32 - 64)
   */
  bytes ContractABI::postprocessTestData(bytes data) {
    auto sender = u256("0x" + toHex(bytes(data.begin() + 44, data.begin() + 64)));
    auto balance = u256("0x" + toHex(bytes(data.begin() + 32, data.begin() + 44)));
    if (!balance) data[32] = 0xff;
    if (!sender) data[63] = 0xf0;
    return data;
  }
  
  void ContractABI::updateTestData(bytes data) {
    /* Detect dynamic len by consulting first 32 bytes */
    int lenOffset = 0;
    auto consultRealLen = [&]() {
      int len = data[lenOffset];
      lenOffset = (lenOffset + 1) % 32;
      return len;
    };
    /* Container of dynamic len */
    auto consultContainerLen = [](int realLen) {
      if (!(realLen % 32)) return realLen;
      return (realLen / 32 + 1) * 32;
    };
    /* Pad to enough data before decoding */
    int offset = 96;
    auto padLen = [&](int singleLen) {
      int fitLen = offset + singleLen;
      while ((int)data.size() < fitLen) data.push_back(0);
    };
    block.clear();
    accounts.clear();
    auto senderInBytes = bytes(data.begin() + 32, data.begin() + 64);
    block = bytes(data.begin() + 64, data.begin() + 96);
    accounts.push_back(senderInBytes);
    for (auto &fd : this->fds) {
      for (auto &td : fd.tds) {
        switch (td.dimensions.size()) {
          case 0: {
            int realLen = td.isDynamic ? consultRealLen() : 32;
            int containerLen = consultContainerLen(realLen);
            /* Pad to enough bytes to read */
            padLen(containerLen);
            /* Read from offset ... offset + realLen */
            bytes d(data.begin() + offset, data.begin() + offset + realLen);
            /* If address, extract account */
            if (boost::starts_with(td.name, "address")) {
              accounts.push_back(d);
            }
            td.addValue(d);
            /* Ignore (containerLen - realLen) bytes */
            offset += containerLen;
            break;
          }
          case 1: {
            vector<bytes> ds;
            int numElem = td.dimensions[0] ? td.dimensions[0] : consultRealLen();
            for (int i = 0; i < numElem; i += 1) {
              int realLen = td.isDynamic ? consultRealLen() : 32;
              int containerLen = consultContainerLen(realLen);
              padLen(containerLen);
              bytes d(data.begin() + offset, data.begin() + offset + realLen);
              ds.push_back(d);
              offset += containerLen;
            }
            /* If address, extract account */
            if (boost::starts_with(td.name, "address")) {
              accounts.insert(accounts.end(), ds.begin(), ds.end());
            }
            td.addValue(ds);
            break;
          }
          case 2: {
            vector<vector<bytes>> dss;
            int numElem = td.dimensions[0] ? td.dimensions[0] : consultRealLen();
            int numSubElem = td.dimensions[1] ? td.dimensions[1] : consultRealLen();
            for (int i = 0; i < numElem; i += 1) {
              vector<bytes> ds;
              for (int j = 0; j < numSubElem; j += 1) {
                int realLen = td.isDynamic ? consultRealLen() : 32;
                int containerLen = consultContainerLen(realLen);
                padLen(containerLen);
                bytes d(data.begin() + offset, data.begin() + offset + realLen);
                ds.push_back(d);
                offset += containerLen;
              }
              dss.push_back(ds);
              /* If address, extract account */
              if (boost::starts_with(td.name, "address")) {
                accounts.insert(accounts.end(), ds.begin(), ds.end());
              }
            }
            td.addValue(dss);
            break;
          }
        }
      }
    }
  }
  
  bytes ContractABI::randomTestcase() {
    /*
     * Random value for ABI
     * | --- dynamic len (32 bytes) -- | sender | blockNumber(8) + timestamp(8) | content |
     */
    bytes ret(32, 5);
    int lenOffset = 0;
    auto consultRealLen = [&]() {
      int len = ret[lenOffset];
      lenOffset = (lenOffset + 1) % 32;
      return len;
    };
    auto consultContainerLen = [](int realLen) {
      if (!(realLen % 32)) return realLen;
      return (realLen / 32 + 1) * 32;
    };
    /* sender env */
    bytes sender(32, 0);
    bytes block(32, 0);
    ret.insert(ret.end(), sender.begin(), sender.end());
    ret.insert(ret.end(), block.begin(), block.end());
    for (auto fd : this->fds) {
      for (auto td : fd.tds) {
        switch(td.dimensions.size()) {
          case 0: {
            int realLen = td.isDynamic ? consultRealLen() : 32;
            int containerLen = consultContainerLen(realLen);
            bytes data(containerLen, 0);
            ret.insert(ret.end(), data.begin(), data.end());
            break;
          }
          case 1: {
            int numElem = td.dimensions[0] ? td.dimensions[0] : consultRealLen();
            for (int i = 0; i < numElem; i += 1) {
              int realLen = td.isDynamic ? consultRealLen() : 32;
              int containerLen = consultContainerLen(realLen);
              bytes data = bytes(containerLen, 0);
              ret.insert(ret.end(), data.begin(), data.end());
            }
            break;
          }
          case 2: {
            int numElem = td.dimensions[0] ? td.dimensions[0] : consultRealLen();
            int numSubElem = td.dimensions[1] ? td.dimensions[1] : consultRealLen();
            for (int i = 0; i < numElem; i += 1) {
              for (int j = 0; j < numSubElem; j += 1) {
                int realLen = td.isDynamic ? consultRealLen() : 32;
                int containerLen = consultContainerLen(realLen);
                bytes data = bytes(containerLen, 0);
                ret.insert(ret.end(), data.begin(), data.end());
              }
            }
            break;
          }
        }
      }
    }
    return ret;
  }
  
  ContractABI::ContractABI(string abiJson) {
    stringstream ss;
    ss << abiJson;
    pt::ptree root;
    pt::read_json(ss, root);
    for (auto node : root) {
      vector<TypeDef> tds;
      string type = node.second.get<string>("type");
      string constant = "false";
      bool payable = false;
      if (node.second.get_child_optional("constant")) {
        constant = node.second.get<string>("constant");
      }
      if (type == "fallback") {
        if (node.second.get_child_optional("payable")) {
          payable = node.second.get<bool>("payable");
        }
        this->fds.push_back(FuncDef("fallback", tds, payable));
      }
      if ((type == "constructor" || type == "function") && constant == "false") {
        auto inputNodes = node.second.get_child("inputs");
        string name = type == "constructor" ? "" : node.second.get<string>("name");
        if (node.second.get_child_optional("payable")) {
          payable = node.second.get<bool>("payable");
        }
        for (auto inputNode : inputNodes) {
          string type = inputNode.second.get<string>("type");
          tds.push_back(TypeDef(type));
        }
        this->fds.push_back(FuncDef(name, tds, payable));
      }
    };
  }
  
  bytes ContractABI::encodeConstructor() {
    auto it = find_if(fds.begin(), fds.end(), [](FuncDef fd) { return fd.name == "";});
    if (it != fds.end()) return encodeTuple((*it).tds);
    return bytes(0, 0);
  }
  
  bool ContractABI::isPayable(string name) {
    for (auto fd : fds) {
      if (fd.name == name) return fd.payable;
    }
    return false;
  }
  
  vector<bytes> ContractABI::encodeFunctions() {
    vector<bytes> ret;
    for (auto fd : fds) {
      if (fd.name != "") {
        bytes selector = functionSelector(fd.name /* name */, fd.tds /* type defs */);
        bytes data = encodeTuple(fd.tds);
        selector.insert(selector.end(), data.begin(), data.end());
        ret.push_back(selector);
      }
    }
    return ret;
  }
  
  bytes ContractABI::functionSelector(string name, vector<TypeDef> tds) {
    vector<string> argTypes;
    transform(tds.begin(), tds.end(), back_inserter(argTypes), [](TypeDef td) {
      return td.fullname;
    });
    string signature = name + "(" + boost::algorithm::join(argTypes, ",") + ")";
    bytes fullSelector = sha3(signature).ref().toBytes();
    return bytes(fullSelector.begin(), fullSelector.begin() + 4);
  }
  
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
