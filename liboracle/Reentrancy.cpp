#include "Reentrancy.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool reentrancy(CallLog callLog) {
    u256 numReentrancies = 0;
    unordered_map<string, u256> signatures;
    vector<u256> sentWeis;
    u256 sentWei = 0;
    for (auto callLogItem : callLog) {
      auto type = callLogItem.type;
      auto level = callLogItem.level;
      auto data = callLogItem.payload.data;
      auto wei = callLogItem.payload.wei;
      sentWei += wei;
      if (data.size() && type == CALL_OPCODE) {
        auto sig = bytes(data.begin(), data.begin() + 4);
        auto sigStr = toHex(sig);
        if (!level) {
          signatures[sigStr] = 1;
        } else if (signatures.count(sigStr)) {
          signatures[sigStr] ++;
          if (!!sentWei) sentWeis.push_back(sentWei);
          sentWei = 0;
        }
      }
    }
    if (!!sentWei) sentWeis.push_back(sentWei);
    for (auto it : signatures) {
      if (it.second > 1) numReentrancies ++;
    }
    return !!numReentrancies && sentWeis.size() >= 2;
  }
}
