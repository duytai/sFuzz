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
    program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), ca.isPayable(""), onOp);
  }

  bool TargetExecutive::storageIsChanged(map<h256, pair<u256, u256>> st1, map<h256, pair<u256, u256>> st2) {
    vector<string> hashs;
    vector<map<h256, pair<u256, u256>>> storages = {st1, st2};
    for (auto storage : storages) {
      stringstream data;
      data << "::";
      for (auto it : storage) {
        data << it.first << ":";
        data << get<0>(it.second) << ":";
        data << get<1>(it.second);
      }
      hashs.push_back(data.str());
    }
    return hashs[0] != hashs[1];
  }

  TargetContainerResult TargetExecutive::exec(bytes data, vector<uint64_t> orders, Logger* logger) {
    /* Save all hit branches to trace_bits */
    Instruction prevInst;
    Instruction prevInstrBr;
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
    unordered_map<uint64_t, u256> predicates;
    vector<bytes> outputs;
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
          payload.caller = ext->myAddress;
          payload.callee = Address((u160)vm->stack()[stackSize - 2]);
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
            inst == Instruction::SUB ||
            inst == Instruction::MUL
          ) {
            vector<u256>::size_type stackSize = vm->stack().size();
            if (inst == Instruction::ADD || inst == Instruction::SUB || inst == Instruction::MUL) {
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
              if (inst == Instruction::MUL && left) {
                u256 total = left * right;
                payload.isOverflow = (total / left != right);
              }
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
      /* calculate number of branches */
      if (inst == Instruction::JUMPCI) {
        branchId = pow(pc, 2);
      }
      if (prevInstrBr == Instruction::JUMPCI) {
        branchId = abs(pow(pc, 2) - branchId);
        branches.insert(branchId);
      }
      prevInstrBr = inst;
      /* calulate predicates */
      if (pc > recordJumpiFrom) {
        if (inst == Instruction::JUMPCI) {
          jumpDest1 = (u64) vm->stack().back();
          jumpDest2 = pc + 1;
          logger->log("-- JUMPI  : " + to_string(pc) + "\n");
        }
        /* INVALID opcode is not recoreded in callback */
        auto newPc = pc;
        auto hasInvalid = false;
        if (inst == Instruction::JUMPCI && (Instruction)ext->code[pc + 1] == Instruction::INVALID) {
          vector<u256>::size_type stackSize = vm->stack().size();
          if (!vm->stack()[stackSize - 2]) {
            hasInvalid = true;
            newPc = pc + 1;
          }
        }
        if (prevInst == Instruction::JUMPCI || hasInvalid) {
          tracebits.insert(newPc ^ prevLocation);
          /* Calculate branch distance */
          if (lastCompValue != 0) {
            /* Save predicate for uncovered branches */
            u64 jumpDest = newPc == jumpDest1 ? jumpDest2 : jumpDest1;
            predicates[jumpDest ^ prevLocation] = lastCompValue;
            stringstream data;
            data << ">> DEST    : " << newPc << endl;
            data << ">> COVER   : " << (newPc ^ prevLocation) << endl;
            data << "++ UNCOVER : " << (jumpDest ^ prevLocation) << endl;
            data << "** COMP    : " << lastCompValue << endl;
            logger->log(data.str());
            lastCompValue = 0;
          }
          prevLocation = newPc >> 1;
        }
        prevInst = inst;
      }
    };
    /* Decode and call functions */
    ca.updateTestData(data);
    vector<bytes> funcs = ca.encodeFunctions();
    program->deploy(addr, code);
    program->setBalance(addr, DEFAULT_BALANCE);
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    oracleFactory->initialize();
    /* Record all jumpis in constructor */
    recordJumpiFrom = 0;
    prevLocation = 0;
    /* Who is sender */
    auto sender = ca.getSender();
    /* record stograge */
    auto storage = program->storage(addr);
    CallLogItemPayload payload;
    payload.inst = Instruction::CALL;
    payload.data = ca.encodeConstructor();
    payload.testData = data;
    payload.wei = ca.isPayable("") ? program->getBalance(sender) / 2 : 0;
    payload.caller = sender;
    payload.callee = addr;
    oracleFactory->save(CallLogItem(0, payload));
    auto res = program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), ca.isPayable(""), onOp);
    auto storageChanged = storageIsChanged(storage, program->storage(addr));
    storage = program->storage(addr);
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
    oracleFactory->finalize(storageChanged);

    for (auto funcIdx : orders) {
      /* Update payload */
      auto func = funcs[funcIdx];
      auto fd = ca.fds[funcIdx];
      /* Ignore JUMPI untill program reaches inside function */
      recordJumpiFrom = 1000000000;
      functionSig = (u64) u256("0x" + toHex(bytes(func.begin(), func.begin() + 4)));
      prevLocation = functionSig;
      CallLogItemPayload payload;
      payload.data = func;
      payload.inst = Instruction::CALL;
      payload.testData = data;
      payload.wei = ca.isPayable(fd.name) ? program->getBalance(sender) / 2 : 0;
      payload.caller = sender;
      payload.callee = addr;
      oracleFactory->save(CallLogItem(0, payload));
      res = program->invoke(addr, CONTRACT_FUNCTION, func, ca.isPayable(fd.name), onOp);
      auto storageChanged = storageIsChanged(storage, program->storage(addr));
      storage = program->storage(addr);
      outputs.push_back(res.output);
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
      oracleFactory->finalize(storageChanged);
    }
    auto addresses = program->addresses();
    /* Reset data before running new contract */
    program->rollback();
    double cksum = 0;
    for (auto t : tracebits) cksum = cksum + (double)(t + cksum)/3;
    return TargetContainerResult(tracebits, branches, cksum, predicates, uniqExceptions, storage, addresses, outputs);
  }
}
