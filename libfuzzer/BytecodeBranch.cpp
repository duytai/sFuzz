#include "BytecodeBranch.h"
#include "Logger.h"

namespace fuzzer
{
BytecodeBranch::BytecodeBranch(const ContractInfo& contractInfo)
{
    auto deploymentBin = contractInfo.bin.substr(0,
        contractInfo.bin.size() - contractInfo.binRuntime.size());  // bin = deployBin + runTimeBin
    auto progInfo = {
        make_tuple(fromHex(deploymentBin), contractInfo.srcmap, false),
        make_tuple(fromHex(contractInfo.binRuntime), contractInfo.srcmapRuntime, true),
    };
    // JUMPI inside constant function
    vector<pair<uint64_t, uint64_t>> constantJumpis;
    for (auto it : contractInfo.constantFunctionSrcmap)
    {  //"offset:len:0,"
        auto elements = splitString(it, ':');
        constantJumpis.push_back(make_pair(stoi(elements[0]), stoi(elements[1])));
    }
    for (auto progIt : progInfo)
    {  // progit: <bin, srcMap, isRuntime:bool>

        // opcodes: [<programCounter: Inst>,...,...]
        auto opcodes = decodeBytecode(get<0>(progIt));
        auto isRuntime = get<2>(progIt);
        auto decompressedSourcemap = decompressSourcemap(
            get<1>(progIt));  // vector<vector<int>>, 例x1:x2:x3;a1:a2:a3 => {{x1,x2},{a1,a2}}
        // offset - len - pc
        vector<tuple<uint64_t, uint64_t, uint64_t>> candidates;
        // Find: if (x > 0 && x < 1000)
        for (uint64_t i = 0; i < decompressedSourcemap.size(); i++)
        {
            if (get<1>(opcodes[i]) == Instruction::JUMPI)
            {
                auto offset = decompressedSourcemap[i][0];
                auto len = decompressedSourcemap[i][1];
                auto snippet = contractInfo.source.substr(offset, len);
                if (boost::starts_with(snippet, "if") || boost::starts_with(snippet, "while") ||
                    boost::starts_with(snippet, "require") || boost::starts_with(snippet, "assert"))
                {
                    Logger::info("----");
                    for (auto candidate : candidates)
                    {  
                        if (get<0>(candidate) > offset &&
                            get<0>(candidate) + get<1>(candidate) < offset + len)
                        {
                            auto candidateSnippet = contractInfo.source.substr(
                                get<0>(candidate), get<1>(candidate)); 
                            auto numConstant = count_if(constantJumpis.begin(),
                                constantJumpis.end(), [&](const pair<uint64_t, uint64_t>& j) {
                                    return get<0>(candidate) >= get<0>(j) &&
                                           get<0>(candidate) + get<1>(candidate) <=
                                               get<0>(j) +
                                                   get<1>(
                                                       j);  //处理嵌套结构，计算candidate包含在当前的代码片段里面的数量
                                });
                            if (!numConstant)
                            {
                                Logger::info(candidateSnippet);
                                if (isRuntime)
                                {
                                    runtimeJumpis.insert(get<2>(candidate));
                                    Logger::info("pc: " + std::to_string(get<2>(candidate)));
                                    snippets.insert(make_pair(get<2>(candidate), candidateSnippet));
                                }
                                else
                                {
                                    deploymentJumpis.insert(get<2>(candidate));
                                    Logger::info("pc: " + std::to_string(get<2>(candidate)));
                                    snippets.insert(make_pair(get<2>(candidate), candidateSnippet));
                                }
                            }
                        }
                    }
                    //在constant裡面進行
                    auto numConstant = count_if(constantJumpis.begin(), constantJumpis.end(),
                        [&](const pair<uint64_t, uint64_t>& j) {
                            return offset >= get<0>(j) && offset + len <= get<0>(j) + get<1>(j);
                        });
                    if (!numConstant)
                    {
                        Logger::info(contractInfo.source.substr(offset, len));
                        if (isRuntime)
                        {
                            runtimeJumpis.insert(get<0>(opcodes[i]));
                            Logger::info("pc: " + std::to_string(get<0>(opcodes[i])));
                            snippets.insert(make_pair(get<0>(opcodes[i]), snippet));
                        }
                        else
                        {
                            deploymentJumpis.insert(get<0>(opcodes[i]));
                            Logger::info("pc: " + std::to_string(get<0>(opcodes[i])));
                            snippets.insert(make_pair(get<0>(opcodes[i]), snippet));
                        }
                    }
                    candidates.clear();
                }
                else
                {
                    candidates.push_back(make_tuple(offset, len, get<0>(opcodes[i])));
                }
            }
        }
    }
}

vector<pair<uint64_t, Instruction>> BytecodeBranch::decodeBytecode(bytes bytecode)
{
    uint64_t pc = 0;  // programCounter
    vector<pair<uint64_t, Instruction>> instructions;
    while (pc < bytecode.size())
    {
        auto inst = (Instruction)bytecode[pc];
        if (inst >= Instruction::PUSH1 && inst <= Instruction::PUSH32)
        {
            auto jumpNum =
                bytecode[pc] - (uint64_t)Instruction::PUSH1 + 1;  
            auto payload = bytes(bytecode.begin() + pc + 1, bytecode.begin() + pc + 1 + jumpNum);
            pc += jumpNum; 
        }
        instructions.push_back(make_pair(pc, inst));
        pc++;
    }
    return instructions;
}

pair<unordered_set<uint64_t>, unordered_set<uint64_t>> BytecodeBranch::findValidJumpis()
{
    return make_pair(deploymentJumpis, runtimeJumpis);
}

vector<vector<uint64_t>> BytecodeBranch::decompressSourcemap(string srcmap)
{
    vector<vector<uint64_t>> components;
    for (auto it : splitString(srcmap, ';'))
    {
        auto sl = splitString(it, ':');
        auto s = sl.size() >= 1 && sl[0] != "" ? stoi(sl[0]) : components[components.size() - 1][0];
        auto l = sl.size() >= 2 && sl[1] != "" ? stoi(sl[1]) : components[components.size() - 1][1];
        components.push_back({s, l});
    }
    return components;
}
}  // namespace fuzzer
