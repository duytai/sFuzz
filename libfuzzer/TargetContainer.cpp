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
  TargetContainer::TargetContainer(bytes code, ContractABI ca): code(code), ca(ca), state(State(0)), program(TargetProgram(state)){}
  
  TargetContainerResult TargetContainer::exec(bytes data) {
    /* Save all hit branches to trace_bits */
    Instruction prevInst;
    double lastCompValue = 0;
    u64 prevLocation = 0;
    u64 jumpDest1 = 0;
    u64 jumpDest2 = 0;
    u64 lastpc = 0;
    unordered_map<string, unordered_set<uint64_t>> uniqExceptions;
    unordered_set<uint64_t> tracebits;
    unordered_map<uint64_t, double> predicates;
    Address addr(100);
    OnOpFunc onOp = [&](u64, u64 pc, Instruction inst, bigint, bigint, bigint, VMFace const* _vm, ExtVMFace const*) {
      lastpc = pc;
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
        tracebits.insert(pc ^ prevLocation);
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
    ca.updateTestData(data);
    vector<bytes> funcs = ca.encodeFunctions();
    program.deploy(addr, code);
    program.updateEnv(ca.env);
    auto res = program.invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), onOp);
    if (res.excepted != TransactionException::None) {
      ostringstream os;
      os << res.excepted;
      unordered_set<uint64_t> exps;
      if (!uniqExceptions.count(os.str())) uniqExceptions[os.str()] = exps;
      uniqExceptions[os.str()].insert(lastpc ^ prevLocation);
    }
    for (auto func: funcs) {
      res = program.invoke(addr, CONTRACT_FUNCTION, func, onOp);
      if (res.excepted != TransactionException::None) {
        ostringstream os;
        os << res.excepted;
        unordered_set<uint64_t> exps;
        if (!uniqExceptions.count(os.str())) uniqExceptions[os.str()] = exps;
        uniqExceptions[os.str()].insert(lastpc ^ prevLocation);
      }
    }
    double cksum = 0;
    for (auto t : tracebits) cksum = cksum + (double)(t + cksum)/3;
    return TargetContainerResult(tracebits, cksum, predicates, uniqExceptions);
  }
}
