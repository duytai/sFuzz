#include "StaticFactory.h"
#include "DangerDelegateCall.h"
#include "BlockNumDependency.h"
#include "TimestampDependency.h"
#include "FreezingEther.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  OracleResult StaticFactory::analyze(bytes code) {
    OracleResult result;
    bytes opcodes;
    int pc = 0, codeSize = code.size();
    while (pc < codeSize) {
      auto ist = (Instruction) code[pc];
      opcodes.push_back(code[pc]);
      switch (ist) {
        case Instruction::PUSH1 ... Instruction::PUSH32: {
          int jumpNum = code[pc] - 0x5f;
          pc += jumpNum;
          break;
        }
        default: { break; }
      }
      pc += 1;
    }
    result.dangerDelegateCall = dangerDelegateCall(opcodes, code);
    result.blockNumDependency = blockNumDependency(opcodes);
    result.timestampDependency = timestampDependency(opcodes);
    result.freezingEther = freezingEther(opcodes);
    return result;
  }
}
