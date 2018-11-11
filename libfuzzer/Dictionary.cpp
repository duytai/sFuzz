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
        if (a.size() == b.size()) return memcmp(b.data(), a.data(), a.size()) > 0;
        return b.size() > a.size();
      }
    };
    set<bytes, bytesComparation> values;
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
      ExtraData d;
      d.data = value;
      d.hitCount = 0;
      extras.push_back(d);
    }
  }
}
