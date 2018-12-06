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
  TargetContainer::TargetContainer() {
    program = new TargetProgram();
    oracleFactory = new OracleFactory();
    baseAddress = ATTACKER_ADDRESS;
  }
  
  TargetContainer::~TargetContainer() {
    delete program;
    delete oracleFactory;
  }
  
  TargetExecutive TargetContainer::loadContract(bytes code, ContractABI ca) {
    if (baseAddress > CONTRACT_ADDRESS) {
      cout << "> Currently does not allow to load more than 1 asset contract" << endl;
      exit(0);
    }
    Address addr(baseAddress);
    TargetExecutive te(oracleFactory, program, addr, ca, code);
    baseAddress ++;
    return te;
  }
  
  void TargetExecutive::deploy(bytes data) {
    OnOpFunc onOp = [](u64, u64, Instruction, bigint, bigint, bigint, VMFace const*, ExtVMFace const*) {};
    ca.updateTestData(data);
    program->deploy(addr, bytes{code});
    program->setBalance(addr, DEFAULT_BALANCE);
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), onOp);
  }
  
  TargetContainerResult TargetExecutive::exec(bytes data) {
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
    OnOpFunc onOp = [&](u64, u64 pc, Instruction inst, bigint, bigint, bigint, VMFace const* _vm, ExtVMFace const* ext) {
      /* TODO: Improve it later */
      if (!ext->depth) {
        auto addressHex = ext->myAddress.hex();
        if (addressHex == ATTACKER_ADDRESS_HEX) return;
      }
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
        case Instruction::CALL:
        case Instruction::CALLCODE:
        case Instruction::DELEGATECALL:
        case Instruction::STATICCALL: {
          vector<u256>::size_type stackSize = vm->stack().size();
          u256 wei = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ? vm->stack()[stackSize - 3] : 0;
          auto sizeOffset = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ? (stackSize - 4) : (stackSize - 3);
          auto inOff = (uint64_t) vm->stack()[sizeOffset];
          auto inSize = (uint64_t) vm->stack()[sizeOffset - 1];
          auto first = vm->memory().begin();
          CallLogItemPayload payload;
          payload.gas = vm->stack()[stackSize - 1];
          payload.wei = wei;
          payload.inst = inst;
          payload.data = bytes(first + inOff, first + inOff + inSize);
          oracleFactory->save(CallLogItem(CALL_OPCODE, ext->depth + 1, payload));
          break;
        }
        case Instruction::TIMESTAMP: {
          oracleFactory->save(CallLogItem(TIMESTAMP_OPCODE, ext->depth + 1));
          break;
        }
        case Instruction::SUICIDE: {
          oracleFactory->save(CallLogItem(SUICIDE_OPCODE, ext->depth + 1));
          break;
        }
        case Instruction::NUMBER: {
          oracleFactory->save(CallLogItem(NUMBER_OPCODE, ext->depth + 1));
          break;
        }
        case Instruction::REVERT: {
          if (!pc) oracleFactory->save(CallLogItem(CALL_EXCEPTION, ext->depth + 1));
          break;
        }
        default: { break; }
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
    program->deploy(addr, code);
    program->setBalance(addr, DEFAULT_BALANCE);
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    oracleFactory->initialize();
    CallLogItemPayload payload;
    payload.gas = MAX_GAS;
    payload.wei = 0;
    payload.inst = Instruction::CALL;
    payload.data = ca.encodeConstructor();
    oracleFactory->save(CallLogItem(CALL_OPCODE, 0, payload));
    auto res = program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), onOp);
    if (res.excepted != TransactionException::None) {
      ostringstream os;
      os << res.excepted;
      unordered_set<uint64_t> exps;
      if (!uniqExceptions.count(os.str())) uniqExceptions[os.str()] = exps;
      uniqExceptions[os.str()].insert(lastpc ^ prevLocation);
      /* Save Call Log */
      oracleFactory->save(CallLogItem(CALL_EXCEPTION, 0));
    }
    for (auto func: funcs) {
      if (!oracleFactory->oracleResult.reentrancy) {
        program->invoke(ATTACKER_ADDRESS, CONTRACT_FUNCTION, setVictimData(func), EMPTY_ONOP);
      }
      /* Update payload */
      payload.data = func;
      payload.wei = 0;
      oracleFactory->save(CallLogItem(CALL_OPCODE, 0, payload));
      /* Call function */
      res = program->invoke(addr, CONTRACT_FUNCTION, func, onOp);
      if (res.excepted != TransactionException::None) {
        ostringstream os;
        os << res.excepted;
        unordered_set<uint64_t> exps;
        if (!uniqExceptions.count(os.str())) uniqExceptions[os.str()] = exps;
        uniqExceptions[os.str()].insert(lastpc ^ prevLocation);
        /* Save Call Log */
        oracleFactory->save(CallLogItem(CALL_EXCEPTION, 0));
      }
    }
    oracleFactory->finalize();
    double cksum = 0;
    for (auto t : tracebits) cksum = cksum + (double)(t + cksum)/3;
    return TargetContainerResult(tracebits, cksum, predicates, uniqExceptions);
  }
}
