#include "CFG.h"
#include <libdevcore/Common.h>
#include <libevm/Instruction.h>
#include <libdevcore/CommonIO.h>

using namespace std;
using namespace dev;
using namespace eth;

namespace fuzzer {
  void CFG::simulate(const bytes& code, u256s stack, int pc, int prevLocation, unordered_set<int>& prevLocations) {
    int codeSize = code.size();
    while (pc < codeSize) {
      auto ist = (Instruction) code[pc];
      switch (ist) {
        case Instruction::PUSH1 ... Instruction::PUSH32: {
          int jumpNum = code[pc] - 0x5f;
          bytes value = bytes(code.begin() + pc + 1, code.begin() + pc + 1 + jumpNum);
          u256 stackItem = u256("0x" + toHex(value));
          stack.push_back(stackItem);
          pc += jumpNum;
          break;
        }
        case Instruction::DUP1 ... Instruction::DUP16: {
          int stackPos = code[pc] - 0x7f;
          int stackSize = stack.size();
          auto stackItem = stack[stackSize - stackPos];
          stack.push_back(stackItem);
          break;
        }
        case Instruction::SWAP1 ... Instruction::SWAP16: {
          int stackPos = code[pc] - 0x8f;
          int stackSize = stack.size();
          int swapIndex = stackSize - stackPos - 1;
          int topIndex = stackSize - 1;
          auto tmp = stack[topIndex];
          stack[topIndex] = stack[swapIndex];
          stack[swapIndex] = tmp;
          break;
        }
        case Instruction::JUMP: {
          auto jumpTo = (int) stack.back();
          stack.pop_back();
          if (jumpdests.count(jumpTo)) {
            simulate(code, stack, jumpTo, prevLocation, prevLocations);
          }
          return;
        }
        case Instruction::JUMPI: {
          auto jumpTo = (int) stack.back();
          stack.pop_back();
          stack.pop_back();
          jumpis.insert(pc);
          if (jumpdests.count(jumpTo)) {
            /* Bit is not set */
            if (tracebits[jumpTo ^ prevLocation] < 10000) {
              tracebits[jumpTo ^ prevLocation] += 1;
              int newPrevLocation = jumpTo >> 1;
              prevLocations.insert(newPrevLocation);
              simulate(code, stack, jumpTo, newPrevLocation, prevLocations);
            }
          }
          jumpTo = pc + 1;
          if (tracebits[jumpTo ^ prevLocation] < 10000) {
            tracebits[jumpTo ^ prevLocation] += 1;
            int newPrevLocation = jumpTo >> 1;
            prevLocations.insert(newPrevLocation);
            simulate(code, stack, jumpTo, newPrevLocation, prevLocations);
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
        default: {
          auto info = instructionInfo(ist);
          if ((int)stack.size() >= (int)info.args) {
            stack.erase(stack.end() - info.args, stack.end());
            u256s stackItems = u256s(info.ret, 0);
            stack.insert(stack.end(), stackItems.begin(), stackItems.end());
            break;
          } else return;
        }
      }
      pc += 1;
    }
  }

  int CFG::totalCount() {
    return tracebits.size() + extraEstimation;
  }
  
  unordered_set<int> CFG::findops(const bytes& code, Instruction op) {
    int pc = 0;
    int size = code.size();
    unordered_set<int> ret;
    jumpdests.clear();
    while (pc < size) {
      if ((Instruction) code[pc] == op) ret.insert(pc);
      if (code[pc] > 0x5f && code[pc] < 0x80) {
        /* PUSH instruction */
        int jumpNum = code[pc] - 0x5f;
        pc += jumpNum;
      }
      pc += 1;
    }
    return ret;
  }
  
  CFG::CFG(string code, string codeRuntime) {
    extraEstimation = 0;
    u256s stack;
    unordered_set<int> prevLocations;
    int pc = 0;
    if (!code.empty() && !codeRuntime.empty()) {
      int allJumpi = findops(fromHex(code), Instruction::JUMPI).size();
      jumpdests = findops(fromHex(code), Instruction::JUMPDEST);
      simulate(fromHex(code), stack, pc, 0, prevLocations);
      for (auto it : prevLocations) {
        unordered_set<int> temp;
        simulate(fromHex(codeRuntime), stack, pc, it, temp);
      }
      int numJumpi = jumpis.size();
      extraEstimation = 2 * (allJumpi - numJumpi);
    }
  }
}
