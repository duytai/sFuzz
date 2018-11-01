#include <iostream>
#include <set>
#include <libevm/Instruction.h>
#include "Dictionary.h"

using namespace std;
using namespace eth;

namespace fuzzer {
  Dictionary::Dictionary(bytes code) {
    int pc = 0;
    int size = code.size();
    struct bytesComparation {
      bool operator ()(const bytes a, const bytes b) {
        return toHex(a) < toHex(b);
      }
    };
    set<bytes, bytesComparation> values;
    auto paddingLeft = [this](bytes data) {
      bytes ret(32 - data.size(), 0);
      ret.insert(ret.end(), data.begin(), data.end());
      return ret;
    };
    auto paddingRight = [this](bytes data) {
      bytes ret;
      ret.insert(ret.end(), data.begin(), data.end());
      while(ret.size() < 32) ret.push_back(0);
      return ret;
    };
    while (pc < size) {
      if (code[pc] > 0x5f && code[pc] < 0x80) {
        /* PUSH instruction */
        int jumpNum = code[pc] - 0x5f;
        bytes value = bytes(code.begin() + pc + 1, code.begin() + pc + 1 + jumpNum);
        values.insert(value);
        pc += jumpNum;
      }
      pc += 1;
    }
    for (auto value : values) {
      bytes leftValue = paddingLeft(value);
      bytes rightValue = paddingRight(value);
      ExtraData l;
      l.data = leftValue;
      l.hitCount = 0;
      extras.push_back(l);
      if (toHex(leftValue) != toHex(rightValue)) {
        ExtraData r;
        r.data = rightValue;
        r.hitCount = 0;
        extras.push_back(r);
      }
    }
  }
}
