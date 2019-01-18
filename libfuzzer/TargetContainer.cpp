#include <math.h>
#include "TargetContainer.h"
#include "Util.h"
#include "ContractABI.h"
#include <boost/multiprecision/cpp_dec_float.hpp>

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;
using namespace boost::multiprecision;

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
  
  void TargetExecutive::deploy(bytes data, OnOpFunc onOp) {
    ca.updateTestData(data);
    program->deploy(addr, bytes{code});
    program->setBalance(addr, DEFAULT_BALANCE);
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), onOp);
  }
  
  TargetContainerResult TargetExecutive::exec(bytes data, vector<uint64_t> orders, Logger* logger) {
    /* Save all hit branches to trace_bits */
    Instruction prevInst;
    u256 lastCompValue = 0;
    u64 prevLocation = 0;
    u64 jumpDest1 = 0;
    u64 jumpDest2 = 0;
    u64 lastpc = 0;
    u64 branchId = 0;
    u64 functionSig = 0;
    u64 recordJumpiFrom = 0;
    unordered_map<string, unordered_set<uint64_t>> uniqExceptions;
    unordered_set<uint64_t> branches;
    unordered_set<uint64_t> tracebits;
    unordered_map<uint64_t, double> predicates;
    OnOpFunc onOp = [&](u64, u64 pc, Instruction inst, bigint, bigint, bigint, VMFace const* _vm, ExtVMFace const* ext) {
      lastpc = pc;
      auto vm = dynamic_cast<LegacyVM const*>(_vm);
      /* Oracle analyze data */
      switch (inst) {
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
          payload.pc = pc;
          payload.gas = vm->stack()[stackSize - 1];
          payload.wei = wei;
          payload.inst = inst;
          payload.data = bytes(first + inOff, first + inOff + inSize);
          payload.testData = data;
          oracleFactory->save(CallLogItem(ext->depth + 1, payload));
          break;
        }
        default: {
          CallLogItemPayload payload;
          payload.pc = pc;
          payload.inst = inst;
          payload.testData = data;
          if (
            inst == Instruction::SUICIDE ||
            inst == Instruction::NUMBER ||
            inst == Instruction::TIMESTAMP ||
            inst == Instruction::INVALID ||
            inst == Instruction::ADD ||
            inst == Instruction::SUB
          ) {
            vector<u256>::size_type stackSize = vm->stack().size();
            auto left = vm->stack()[stackSize - 1];
            auto right = vm->stack()[stackSize - 2];
            if (inst == Instruction::ADD) {
              auto total256 = left + right;
              auto total512 = (u512) left + (u512) right;
              payload.isOverflow = total512 != total256;
            }
            if (inst == Instruction::SUB) {
              payload.isUnderflow = left < right;
            }
            oracleFactory->save(CallLogItem(ext->depth + 1, payload));
          }
          break;
        }
      }
      /* Mutation analyzes data */
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
            /* EQ call == function signature */
            if (left == functionSig && right == functionSig) recordJumpiFrom = pc + 4;
            /* calculate if command inside a function */
            if (pc > recordJumpiFrom) {
              u256 temp = left > right ? left - right : right - left;
              lastCompValue = temp + 1;
            }
          }
          break;
        }
        default: { break; }
      }
      /* calculate if command inside a function */
      if (pc > recordJumpiFrom) {
        if (inst == Instruction::JUMPCI) {
          jumpDest1 = (u64) vm->stack().back();
          jumpDest2 = pc + 1;
          branchId = pow(pc, 2);
        }
        if (prevInst == Instruction::JUMPCI) {
          tracebits.insert(pc ^ prevLocation);
          branchId = abs(pow(pc, 2) - branchId);
          branches.insert(branchId);
          /* Calculate branch distance */
          if (lastCompValue != 0) {
            /* Save predicate for uncovered branches */
            u64 jumpDest = pc == jumpDest1 ? jumpDest2 : jumpDest1;
            predicates[jumpDest ^ prevLocation] = (double)(cpp_dec_float_100(lastCompValue) / cpp_dec_float_100(lastCompValue + 1));
            //cout << ">> cover: " << (pc ^ prevLocation) << endl;
            //cout << ">> uncover: " << (jumpDest ^ prevLocation) << endl;
            //cout << ">> comp: " << lastCompValue << endl;
            lastCompValue = 0;
          }
          prevLocation = pc >> 1;
        }
        prevInst = inst;
      }
      /* log to file */
      if (logger->isEnabled()) {
        stringstream data;
        vector<u256>::size_type stackSize = vm->stack().size();
        data << pc << "|";
        data << instructionInfo(inst).name << "|";
        for (int64_t i = 0; i < (int64_t) stackSize; i ++) {
          data << toHex(u256ToBytes(vm->stack()[i])) << "|";
        }
        data << endl;
        logger->log(data.str());
      }
    };
    /* Decode and call functions */
    ca.updateTestData(data);
    vector<bytes> funcs = ca.encodeFunctions();
    program->deploy(addr, code);
    program->setBalance(addr, DEFAULT_BALANCE);
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    oracleFactory->initialize();
    CallLogItemPayload payload;
    payload.inst = Instruction::CALL;
    payload.data = ca.encodeConstructor();
    payload.testData = data;
    oracleFactory->save(CallLogItem(0, payload));
    /* Record all jumpis in constructor */
    recordJumpiFrom = 0;
    prevLocation = 0;
    auto res = program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), onOp);
    if (res.excepted != TransactionException::None) {
      ostringstream os;
      os << res.excepted;
      unordered_set<uint64_t> exps;
      if (!uniqExceptions.count(os.str())) uniqExceptions[os.str()] = exps;
      uniqExceptions[os.str()].insert(lastpc ^ prevLocation);
      /* Save Call Log */
      CallLogItemPayload payload;
      payload.inst = Instruction::INVALID;
      payload.testData = data;
      oracleFactory->save(CallLogItem(0, payload));
    }
    for (auto funcIdx : orders) {
      /* Update payload */
      CallLogItemPayload payload;
      auto func = funcs[funcIdx];
      payload.data = func;
      payload.inst = Instruction::CALL;
      payload.testData = data;
      oracleFactory->save(CallLogItem(0, payload));
      /* Ignore JUMPI untill program reaches inside function */
      recordJumpiFrom = 1000000000;
      functionSig = (u64) u256("0x" + toHex(bytes(func.begin(), func.begin() + 4)));
      prevLocation = functionSig;
      res = program->invoke(addr, CONTRACT_FUNCTION, func, onOp);
      if (res.excepted != TransactionException::None) {
        ostringstream os;
        os << res.excepted;
        unordered_set<uint64_t> exps;
        if (!uniqExceptions.count(os.str())) uniqExceptions[os.str()] = exps;
        uniqExceptions[os.str()].insert(lastpc ^ prevLocation);
        /* Save Call Log */
        CallLogItemPayload payload;
        payload.inst = Instruction::INVALID;
        payload.testData = data;
        oracleFactory->save(CallLogItem(0, payload));
      }
    }
    oracleFactory->finalize();
    double cksum = 0;
    for (auto t : tracebits) cksum = cksum + (double)(t + cksum)/3;
    return TargetContainerResult(tracebits, branches, cksum, predicates, uniqExceptions);
  }
}
