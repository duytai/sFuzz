#include "BytecodeBranch.h"
#include "Logger.h"

namespace fuzzer {

  BytecodeBranch::BytecodeBranch(const ContractInfo &contractInfo) {
    auto deploymentBin = contractInfo.bin.substr(0, contractInfo.bin.size() - contractInfo.binRuntime.size());
    auto progInfo = {
        make_tuple(fromHex(deploymentBin), contractInfo.srcmap, false),
        make_tuple(fromHex(contractInfo.binRuntime), contractInfo.srcmapRuntime, true),
    };
    for (auto progIt : progInfo) {
      auto opcodes = decodeBytecode(get<0>(progIt));
      auto isRuntime = get<2>(progIt);
      auto decompressedSourcemap = decompressSourcemap(get<1>(progIt));
      // offset - len - pc
      vector<tuple<uint64_t, uint64_t, uint64_t>> candidates;
      // Find: if (x > 0 && x < 1000)
      for (uint64_t i = 0; i < opcodes.size(); i ++) {
        if (get<1>(opcodes[i]) == Instruction::JUMPI) {
          auto offset = decompressedSourcemap[i][0];
          auto len = decompressedSourcemap[i][1];
          auto snippet = contractInfo.source.substr(offset, len);
          if (boost::starts_with(snippet, "if")
            || boost::starts_with(snippet, "while")
            || boost::starts_with(snippet, "require")
            || boost::starts_with(snippet, "assert")
          ) {
            Logger::info("----");
            for (auto candidate : candidates) {
              if (get<0>(candidate) > offset && get<0>(candidate) + get<1>(candidate) < offset + len) {
                Logger::info(contractInfo.source.substr(get<0>(candidate), get<1>(candidate)));
                if (isRuntime) {
                  runtimeJumpis.insert(get<2>(candidate));
                  Logger::info("pc: " + to_string(get<2>(candidate)));
                } else {
                  deploymentJumpis.insert(get<2>(candidate));
                  Logger::info("pc: " + to_string(get<2>(candidate)));
                }
              }
            }
            Logger::info(contractInfo.source.substr(offset, len));
            if (isRuntime) {
              runtimeJumpis.insert(get<0>(opcodes[i]));
              Logger::info("pc: " + to_string(get<0>(opcodes[i])));
            } else {
              deploymentJumpis.insert(get<0>(opcodes[i]));
              Logger::info("pc: " + to_string(get<0>(opcodes[i])));
            }
            candidates.clear();
          } else {
            candidates.push_back(make_tuple(offset, len, get<0>(opcodes[i])));
          }
        }
      }
    }
  }

  vector<string> BytecodeBranch::split(string str, char separator) {
    vector<string> elements;
    uint64_t sepIdx = 0;
    if (!str.size()) return {};
    for (uint64_t i = 0; i < str.length(); i ++) {
      if (str[i] == separator) {
        elements.push_back(str.substr(sepIdx, i - sepIdx));
        sepIdx = i + 1;
      }
    }
    elements.push_back(str.substr(sepIdx, str.length() - sepIdx));
    return elements;
  }

  vector<pair<uint64_t, Instruction>> BytecodeBranch::decodeBytecode(bytes bytecode) {
    uint64_t pc = 0;
    vector<pair<uint64_t, Instruction>> instructions;
    while (pc < bytecode.size()) {
      auto inst = (Instruction) bytecode[pc];
      if (inst >= Instruction::PUSH1 && inst <= Instruction::PUSH32) {
        auto jumpNum = bytecode[pc] - (uint64_t) Instruction::PUSH1 + 1;
        auto payload = bytes(bytecode.begin() + pc + 1, bytecode.begin() + pc + 1 + jumpNum);
        pc += jumpNum;
      }
      instructions.push_back(make_pair(pc, inst));
      pc ++;
    }
    return instructions;
  }

  pair<unordered_set<uint64_t>, unordered_set<uint64_t>> BytecodeBranch::findValidJumpis() {
    return make_pair(deploymentJumpis, runtimeJumpis);
  }

  vector<vector<uint64_t>> BytecodeBranch::decompressSourcemap(string srcmap) {
    vector<vector<uint64_t>> components;
    for (auto it : BytecodeBranch::split(srcmap, ';')) {
      auto sl = BytecodeBranch::split(it, ':');
      auto s = sl.size() >= 1 && sl[0] != "" ? stoi(sl[0]) : components[components.size() - 1][0];
      auto l = sl.size() >= 2 && sl[1] != "" ? stoi(sl[1]) : components[components.size() - 1][1];
      components.push_back({ s, l });
    }
    return components;
  }
}
