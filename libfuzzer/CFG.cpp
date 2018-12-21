#include "CFG.h"

using namespace std;
using namespace dev;
using namespace eth;

namespace fuzzer {
  CFGStat CFG::toCFGStat(OpStat opStat) {
    CFGStat cfgStat;
    for (auto pc : opStat.pcs) cfgStat.pcs[pc] = 0;
    for (auto pc : opStat.jumpdests) cfgStat.jumpdests[pc] = 0;
    return cfgStat;
  }
  
  OpStat CFG::staticAnalyze(bytes code) {
    OpStat opStat;
    uint64_t pc = 0;
    while (pc < code.size()) {
      auto inst = (Instruction) code[pc];
      opStat.pcs.push_back(pc);
      if (inst == Instruction::JUMPDEST) {
        opStat.jumpdests.push_back(pc);
      }
      if (inst >= Instruction::PUSH1 && inst <= Instruction::PUSH32) {
        auto jumpNum = code[pc] - (uint64_t) Instruction::PUSH1 + 1;
        pc += jumpNum;
      }
      pc ++;
    }
    return opStat;
  }
  
  void CFG::simulate(bytes code, vector<u256> stack, uint64_t pc, CFGStat& cfgStat) {
    auto codeSize = code.size();
    while (pc < codeSize) {
      auto inst = (Instruction) code[pc];
      cfgStat.pcs[pc] ++;
      if (stack.size() > 1024 || cfgStat.pcs[pc] > 1024) return;
      switch (inst) {
        case Instruction::PUSH1 ... Instruction::PUSH32: {
          auto jumpNum = code[pc] - (uint64_t) Instruction::PUSH1 + 1;
          auto data = bytes(code.begin() + pc + 1, code.begin() + pc + 1 + jumpNum);
          stack.push_back(u256("0x" + toHex(data)));
          pc += jumpNum;
          break;
        }
        case Instruction::DUP1 ... Instruction::DUP16: {
          uint64_t stackSize = stack.size();
          uint64_t stackPos = code[pc] - (uint64_t) Instruction::DUP1 + 1;
          int64_t dupIndex = stackSize - stackPos;
          if (dupIndex < 0) return;
          auto data = stack[dupIndex];
          stack.push_back(data);
          break;
        }
        case Instruction::SWAP1 ... Instruction::SWAP16: {
          uint64_t stackSize = stack.size();
          uint64_t stackPos = code[pc] - (uint64_t) Instruction::SWAP1 + 1;
          int64_t swapIndex = stackSize - stackPos - 1;
          int64_t topIndex = stackSize - 1;
          if (swapIndex < 0) return;
          auto tmp = stack[topIndex];
          stack[topIndex] = stack[swapIndex];
          stack[swapIndex] = tmp;
          break;
        }
        case Instruction::JUMPI: {
          if (stack.size() < 2) return;
          auto jumpTo = (uint64_t) stack.back();
          stack.pop_back();
          stack.pop_back();
          if ((Instruction) code[jumpTo] == Instruction::JUMPDEST) {
            simulate(code, stack, jumpTo, cfgStat);
          }
          simulate(code, stack, pc + 1, cfgStat);
          return;
        }
        case Instruction::JUMP: {
          if (stack.size() < 1) return;
          auto jumpTo = (uint64_t) stack.back();
          stack.pop_back();
          if ((Instruction) code[jumpTo] == Instruction::JUMPDEST) {
            simulate(code, stack, jumpTo, cfgStat);
          }
          return;
        }
        case Instruction::STOP:
        case Instruction::RETURN:
        case Instruction::REVERT:
        case Instruction::SUICIDE:
        case Instruction::INVALID: {
          return;
        }
        case Instruction::JUMPDEST: {
          cfgStat.jumpdests[pc]++;
          break;
        }
        default: {
          auto info = instructionInfo(inst);
          uint64_t outOp = info.args;
          uint64_t inOp = info.ret;
          if (stack.size() < outOp) return;
          stack.erase(stack.end() - info.args, stack.end());
          u256s stackItems = u256s(inOp, 0);
          stack.insert(stack.end(), stackItems.begin(), stackItems.end());
          break;
        }
      }
      pc ++;
    }
  }
  
  CFG::CFG(bytes code) {
    uint64_t pos = 0;
    for (uint64_t i = 0; i < code.size() - 1; i ++) {
      auto isReturn = (Instruction) code[i] == Instruction::RETURN;
      auto isStop = (Instruction) code[i + 1] == Instruction::STOP;
      if (isReturn && isStop) {
        pos = i + 2;
        break;
      }
    }
    vector<bytes> stageCodes = {
      bytes(code.begin(), code.begin() + pos),
      bytes(code.begin() + pos, code.end()),
    };
    for (auto stageCode : stageCodes) {
      vector<u256> stack;
      auto opStat = staticAnalyze(stageCode);
      auto cfgStat = toCFGStat(opStat);
      simulate(stageCode, stack, 0, cfgStat);
      for (auto it : cfgStat.pcs) {
        if (!it.second) cout << "PC: " << it.first << endl;
      }
      for (auto it : cfgStat.jumpdests) {
        if (!it.second) cout << "JD: " << it.first << endl;
      }
      cout << "jumpdest: " << cfgStat.jumpdests.size() << endl;
    }
  }
}
