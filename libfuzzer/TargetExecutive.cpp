#include "TargetExecutive.h"
#include "Logger.h"

namespace fuzzer {
  void TargetExecutive::deploy(bytes data, OnOpFunc onOp) {
    ca.updateTestData(data);
    program->deploy(addr, bytes{code});
    program->setBalance(addr, DEFAULT_BALANCE);
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), ca.isPayable(""), onOp);
  }

  TargetContainerResult TargetExecutive::exec(bytes data) {
    /* Save all hit branches to trace_bits */
    Instruction prevInst;
    RecordParam recordParam;
    u256 lastCompValue = 0;
    u64 jumpDest1 = 0;
    u64 jumpDest2 = 0;
    unordered_set<uint64_t> uniqExceptions;
    unordered_set<uint64_t> tracebits;
    unordered_map<uint64_t, u256> predicates;
    vector<bytes> outputs;
    size_t savepoint = program->savepoint();
    OnOpFunc onOp = [&](u64, u64 pc, Instruction inst, bigint, bigint, bigint, VMFace const* _vm, ExtVMFace const* ext) {
      auto vm = dynamic_cast<LegacyVM const*>(_vm);
      recordParam.lastpc = pc;
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
          OpcodePayload payload;
          payload.caller = ext->myAddress;
          payload.callee = Address((u160)vm->stack()[stackSize - 2]);
          payload.pc = pc;
          payload.gas = vm->stack()[stackSize - 1];
          payload.wei = wei;
          payload.inst = inst;
          payload.data = bytes(first + inOff, first + inOff + inSize);
          oracleFactory->save(OpcodeContext(ext->depth + 1, payload));
          break;
        }
        default: {
          OpcodePayload payload;
          payload.pc = pc;
          payload.inst = inst;
          if (
              inst == Instruction::SUICIDE ||
              inst == Instruction::NUMBER ||
              inst == Instruction::TIMESTAMP ||
              inst == Instruction::INVALID ||
              inst == Instruction::ADD ||
              inst == Instruction::SUB
              ) {
            vector<u256>::size_type stackSize = vm->stack().size();
            if (inst == Instruction::ADD || inst == Instruction::SUB) {
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
            }
            oracleFactory->save(OpcodeContext(ext->depth + 1, payload));
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
            /* calculate if command inside a function */
            if (recordParam.recording) {
              u256 temp = left > right ? left - right : right - left;
              lastCompValue = temp + 1;
            }
            /* EQ call == function signature */
            recordParam.recording = recordParam.recording
                || (left == right && right == recordParam.functionSignature);
          }
          break;
        }
        default: { break; }
      }
      /* Calculate predicates */
      if (recordParam.recording) {
        if (inst == Instruction::JUMPCI) {
          jumpDest1 = (u64) vm->stack().back();
          jumpDest2 = pc + 1;
        }
        if (prevInst == Instruction::JUMPCI) {
          tracebits.insert(pc ^ recordParam.prevLocation);
          /* Calculate branch distance */
          if (lastCompValue != 0) {
            /* Save predicate for uncovered branches */
            u64 jumpDest = pc == jumpDest1 ? jumpDest2 : jumpDest1;
            predicates[jumpDest ^ recordParam.prevLocation] = lastCompValue;
            lastCompValue = 0;
          }
          recordParam.prevLocation = pc >> 1;
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
    /* Record all JUMPI in constructor */
    recordParam.recording = true;
    recordParam.prevLocation = 0;
    /* Who is sender */
    auto sender = ca.getSender();
    /* record storage */
    OpcodePayload payload;
    payload.inst = Instruction::CALL;
    payload.data = ca.encodeConstructor();
    payload.wei = ca.isPayable("") ? program->getBalance(sender) / 2 : 0;
    payload.caller = sender;
    payload.callee = addr;
    oracleFactory->save(OpcodeContext(0, payload));
    auto res = program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), ca.isPayable(""), onOp);
    if (res.excepted != TransactionException::None) {
      uniqExceptions.insert(recordParam.lastpc ^ recordParam.prevLocation);
      /* Save Call Log */
      OpcodePayload payload;
      payload.inst = Instruction::INVALID;
      oracleFactory->save(OpcodeContext(0, payload));
    }
    oracleFactory->finalize();
    for (uint32_t funcIdx = 0; funcIdx < funcs.size(); funcIdx ++ ) {
      /* Update payload */
      auto func = funcs[funcIdx];
      auto fd = ca.fds[funcIdx];
      /* Ignore JUMPI until program reaches inside function */
      recordParam.recording = false;
      recordParam.functionSignature = (u64) u256("0x" + toHex(bytes(func.begin(), func.begin() + 4)));
      recordParam.prevLocation = recordParam.functionSignature;
      OpcodePayload payload;
      payload.data = func;
      payload.inst = Instruction::CALL;
      payload.wei = ca.isPayable(fd.name) ? program->getBalance(sender) / 2 : 0;
      payload.caller = sender;
      payload.callee = addr;
      oracleFactory->save(OpcodeContext(0, payload));
      res = program->invoke(addr, CONTRACT_FUNCTION, func, ca.isPayable(fd.name), onOp);
      outputs.push_back(res.output);
      if (res.excepted != TransactionException::None) {
        uniqExceptions.insert(recordParam.lastpc ^ recordParam.prevLocation);
        /* Save Call Log */
        OpcodePayload payload;
        payload.inst = Instruction::INVALID;
        oracleFactory->save(OpcodeContext(0, payload));
      }
      oracleFactory->finalize();
    }
    /* Reset data before running new contract */
    program->rollback(savepoint);
    double cksum = 0;
    for (auto t : tracebits) cksum = cksum + (double)(t + cksum)/3;
    return TargetContainerResult(tracebits, predicates, uniqExceptions, cksum);
  }
}
