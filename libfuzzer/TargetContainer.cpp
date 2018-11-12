#include <libevm/LegacyVM.h>
#include "TargetContainer.h"
#include "Util.h"
#include "ContractABI.h"
#include <math.h>

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;

namespace fuzzer {
  TargetContainer::TargetContainer(bytes code, ContractABI ca): code(code), ca(ca){
    program.deploy(code);
  }
  
  TargetContainerResult TargetContainer::exec(bytes data) {
    /* Save all hit branches to trace_bits */
    Instruction prevInst;
    double lastCompValue = 0;
    u64 prevLocation = 0;
    u64 jumpDest1 = 0;
    u64 jumpDest2 = 0;
    bytes tracebits(MAP_SIZE, 0);
    unordered_map<uint64_t, double> predicates;
    OnOpFunc onOp = [&](u64, u64 pc, Instruction inst, bigint, bigint, bigint, VMFace const* _vm, ExtVMFace const*) {
      auto vm = dynamic_cast<LegacyVM const*>(_vm);
      switch (inst) {
        case Instruction::GT:
        case Instruction::SGT:
        case Instruction::LT:
        case Instruction::SLT:
        case Instruction::EQ: {
          vector<u256>::size_type stackSize = vm->stack().size();
          if (stackSize >= 2) {
            u256 left = vm->stack()[stackSize - 1];
            u256 right = vm->stack()[stackSize - 2];
            u256 temp = left > right ? left - right : right - left;
            lastCompValue = abs((double)(uint64_t)temp) + 1;
          }
          break;
        }
        default: {
          break;
        }
      }
      if (inst == Instruction::JUMPCI) {
        jumpDest1 = (u64) vm->stack().back();
        jumpDest2 = pc + 1;
      }
      if (prevInst == Instruction::JUMPCI) {
        tracebits[pc ^ prevLocation]++;
        prevLocation = pc >> 1;
        /* Calculate branch distance */
        if (lastCompValue != 0) {
          double distance = 1 - pow(1.001, -lastCompValue);
          /* Save predicate for uncovered branches */
          u64 jumpDest = pc == jumpDest1 ? jumpDest2 : jumpDest1;
          predicates[jumpDest ^ prevLocation] = distance;
        }
      }
      prevInst = inst;
    };
    /* Decode and call functions */
    Timer timer;
    ca.updateTestData(data);
    vector<bytes> funcs = ca.encodeFunctions();
    program.setupAccounts(ca.accounts);
    program.invoke(CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), onOp);
    for (auto func: funcs) {
      program.invoke(CONTRACT_FUNCTION, func, onOp);
    }
    /*
     Reset program and deploy again becuase
     it changed after invoke constructor
     */
    program.reset();
    program.deploy(code);
    /*
     Calculate checksum and return response
     */
    return TargetContainerResult(tracebits, sha3(tracebits), timer.elapsed(), predicates);
  }
}
