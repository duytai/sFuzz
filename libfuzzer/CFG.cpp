#include "CFG.h"
#include <libdevcore/Common.h>
#include <libevm/Instruction.h>
#include <libdevcore/CommonIO.h>

using namespace std;
using namespace dev;
using namespace eth;

namespace fuzzer {
  void CFG::simulate(const bytes& code, u256s stack, int pc, int prevLocation, unordered_map<int, int>& prevLocations) {
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
          if (stackPos > stackSize) return;
          auto stackItem = stack[stackSize - stackPos];
          stack.push_back(stackItem);
          break;
        }
        case Instruction::SWAP1 ... Instruction::SWAP16: {
          int stackPos = code[pc] - 0x8f;
          int stackSize = stack.size();
          int swapIndex = stackSize - stackPos - 1;
          if (swapIndex < 0) return;
          int topIndex = stackSize - 1;
          auto tmp = stack[topIndex];
          stack[topIndex] = stack[swapIndex];
          stack[swapIndex] = tmp;
          break;
        }
        case Instruction::JUMP: {
          int stackSize = stack.size();
          if (stackSize > 1) {
            auto jumpTo = (int) stack.back();
            stack.pop_back();
            if ((Instruction) code[jumpTo] == Instruction::JUMPDEST) {
              simulate(code, stack, jumpTo, prevLocation, prevLocations);
            }
          }
          return;
        }
        case Instruction::JUMPI: {
          int stackSize = stack.size();
          if (stackSize > 1) {
            auto jumpTo = (int) stack.back();
            stack.pop_back();
            if ((Instruction) code[jumpTo] == Instruction::JUMPDEST) {
              /* Bit is not set */
              if (!tracebits[jumpTo ^ prevLocation]) {
                tracebits[jumpTo ^ prevLocation] = 1;
                int newPrevLocation = jumpTo >> 1;
                prevLocations[newPrevLocation] = 1;
                simulate(code, stack, jumpTo, newPrevLocation, prevLocations);
              }
            }
            jumpTo = pc + 1;
            if (!tracebits[jumpTo ^ prevLocation]) {
              tracebits[jumpTo ^ prevLocation] = 1;
              int newPrevLocation = jumpTo >> 1;
              prevLocations[newPrevLocation] = 1;
              simulate(code, stack, jumpTo, newPrevLocation, prevLocations);
            }
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
          stack.erase(stack.end() - info.args, stack.end());
          u256s stackItems = u256s(info.ret, 0);
          stack.insert(stack.end(), stackItems.begin(), stackItems.end());
          break;
        }
      }
      pc += 1;
    }
  }

  int CFG::totalCount() {
    return tracebits.size();
  }
  
  CFG::CFG(string code, string codeRuntime) {
    u256s stack;
    int pc = 0;
    unordered_map<int, int> prevLocations;
    simulate(fromHex(code), stack, pc, 0, prevLocations);
    for (auto it : prevLocations) {
      unordered_map<int, int> temp;
      simulate(fromHex(codeRuntime), stack, pc, it.first, temp);
    }
  }
}
