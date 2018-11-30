#include "Reentrancy.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool reentrancy(CallLog) {
//    for (auto callLogItem : callLog) {
//      cout << "TYPE: " << callLogItem.type << endl;
//      cout << "LEVEL: " << callLogItem.level << endl;
//    }
//    exit(1);
    return false;
  }
}
