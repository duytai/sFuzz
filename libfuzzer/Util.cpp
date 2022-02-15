#include "Util.h"
#include "Logger.h"

namespace fuzzer
{
u32 UR(u32 limit)
{
    return random() % limit;
}

int effAPos(int p)
{
    return p >> EFF_MAP_SCALE2;
}

int effRem(int x)
{
    return (x) & ((1 << EFF_MAP_SCALE2) - 1);
}

int effALen(int l)
{
    return effAPos(l) + !!effRem(l);
}

int effSpanALen(int p, int l)
{
    return (effAPos(p + l - 1) - effAPos(p) + 1);
}
/* Helper function to see if a particular change (xor_val = old ^ new) could
 be a product of deterministic bit flips with the lengths and stepovers
 attempted by afl-fuzz. This is used to avoid dupes in some of the
 deterministic fuzzing operations that follow bit flips. We also
 return 1 if xor_val is zero, which implies that the old and attempted new
 values are identical and the exec would be a waste of time. */
bool couldBeBitflip(u32 xorValue)
{
    u32 sh = 0;
    if (!xorValue)
        return true;
    /* Shift left until first bit set. */
    while (!(xorValue & 1))
    {
        sh++;
        xorValue >>= 1;
    }
    /* 1-, 2-, and 4-bit patterns are OK anywhere. */
    if (xorValue == 1 || xorValue == 3 || xorValue == 15)
        return 1;
    /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */
    if (sh & 7)
        return false;
    if (xorValue == 0xff || xorValue == 0xffff || xorValue == 0xffffffff)
        return true;
    return false;
}
/* Helper function to see if a particular value is reachable through
 arithmetic operations. Used for similar purposes. */
bool couldBeArith(u32 old_val, u32 new_val, u8 blen)
{
    u32 i, ov = 0, nv = 0, diffs = 0;
    if (old_val == new_val)
        return true;
    /* See if one-byte adjustments to any byte could produce this result. */
    for (i = 0; i < blen; i++)
    {
        u8 a = old_val >> (8 * i), b = new_val >> (8 * i);
        if (a != b)
        {
            diffs++;
            ov = a;
            nv = b;
        }
    }
    /* If only one byte differs and the values are within range, return 1. */
    if (diffs == 1)
    {
        if ((u8)(ov - nv) <= ARITH_MAX || (u8)(nv - ov) <= ARITH_MAX)
            return true;
    }
    if (blen == 1)
        return false;
    /* See if two-byte adjustments to any byte would produce this result. */
    diffs = 0;
    for (i = 0; i < blen / 2; i++)
    {
        u16 a = old_val >> (16 * i), b = new_val >> (16 * i);
        if (a != b)
        {
            diffs++;
            ov = a;
            nv = b;
        }
    }
    /* If only one word differs and the values are within range, return 1. */
    if (diffs == 1)
    {
        if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX)
            return true;
        ov = swap16(ov);
        nv = swap16(nv);
        if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX)
            return true;
    }
    /* Finally, let's do the same thing for dwords. */
    if (blen == 4)
    {
        if ((u32)(old_val - new_val) <= (u32)ARITH_MAX ||
            (u32)(new_val - old_val) <= (u32)ARITH_MAX)
            return true;
        new_val = swap32(new_val);
        old_val = swap32(old_val);
        if ((u32)(old_val - new_val) <= (u32)ARITH_MAX ||
            (u32)(new_val - old_val) <= (u32)ARITH_MAX)
            return true;
    }
    return false;
}
/* Last but not least, a similar helper to see if insertion of an
 interesting integer is redundant given the insertions done for
 shorter blen. The last param (check_le) is set if the caller
 already executed LE insertion for current blen and wants to see
 if BE variant passed in new_val is unique. */
bool couldBeInterest(u32 old_val, u32 new_val, u8 blen, u8 check_le)
{
    u32 i, j;
    if (old_val == new_val)
        return true;
    /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */
    for (i = 0; i < blen; i++)
    {
        for (j = 0; j < sizeof(INTERESTING_8); j++)
        {
            u32 tval = (old_val & ~(0xff << (i * 8))) | (((u8)INTERESTING_8[j]) << (i * 8));
            if (new_val == tval)
                return true;
        }
    }
    /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts. */
    if (blen == 2 && !check_le)
        return false;
    /* See if two-byte insertions over old_val could give us new_val. */
    for (i = 0; i < blen - 1; i++)
    {
        for (j = 0; j < sizeof(INTERESTING_16) / 2; j++)
        {
            u32 tval = (old_val & ~(0xffff << (i * 8))) | (((u16)INTERESTING_16[j]) << (i * 8));
            if (new_val == tval)
                return true;
            /* Continue here only if blen > 2. */
            if (blen > 2)
            {
                tval = (old_val & ~(0xffff << (i * 8))) | (swap16(INTERESTING_16[j]) << (i * 8));
                if (new_val == tval)
                    return true;
            }
        }
    }
    if (blen == 4 && check_le)
    {
        /* See if four-byte insertions could produce the same result
         (LE only). */
        for (j = 0; j < sizeof(INTERESTING_32) / 4; j++)
            if (new_val == (u32)INTERESTING_32[j])
                return true;
    }
    return false;
}

u16 swap16(u16 x)
{
    return x << 8 | x >> 8;
}

u32 swap32(u32 x)
{
    return x << 24 | x >> 24 | ((x << 8) & 0x00FF0000) | ((x >> 8) & 0x0000FF00);
}

u32 chooseBlockLen(u32 limit)
{
    /* Delete at most: 1/4 */
    int maxFactor = limit / (4 * 32);
    if (!maxFactor)
        return 0;
    return (UR(maxFactor) + 1) * 32;
}

void locateDiffs(byte* ptr1, byte* ptr2, u32 len, s32* first, s32* last)
{
    s32 f_loc = -1;
    s32 l_loc = -1;
    u32 pos;
    for (pos = 0; pos < len; pos++)
    {
        if (*(ptr1++) != *(ptr2++))
        {
            if (f_loc == -1)
                f_loc = pos;
            l_loc = pos;
        }
    }
    *first = f_loc;
    *last = l_loc;
    return;
}

string formatDuration(int duration)
{
    stringstream ret;
    int days = duration / (60 * 60 * 24);
    int hours = duration / (60 * 60) % 24;
    int minutes = duration / 60 % 60;
    int seconds = duration % 60;
    ret << days << " days, " << hours << " hrs, " << minutes << " min, " << seconds << " sec";
    return padStr(ret.str(), 48);
}

string padStr(string str, int len)
{
    while ((int)str.size() < len)
        str += " ";
    return str;
}

vector<string> splitString(string str, char separator)
{
    vector<string> elements;
    uint64_t sepIdx = 0;
    if (!str.size())
        return {};
    for (uint64_t i = 0; i < str.length(); i++)
    {
        if (str[i] == separator)
        {
            elements.push_back(str.substr(sepIdx, i - sepIdx));
            sepIdx = i + 1;
        }
    }
    elements.push_back(str.substr(sepIdx, str.length() - sepIdx));
    return elements;
}

// PatternType getPatternType(string str)
// {
//     if (str == "RW")
//         return RW;
//     if (str == "WR")
//         return WR;
//     if (str == "WW")
//         return WW;
//     if (str == "RWR")
//         return RWR;
//     if (str == "WWR")
//         return WWR;
//     if (str == "WRW")
//         return WRW;
//     if (str == "RWW")
//         return RWW;
//     if (str == "WWW")
//         return WWW;
//     if (str == "W1XW2XW2YW1Y")
//         return W1XW2XW2YW1Y;
//     if (str == "W1XW2YW2XW1Y")
//         return W1XW2YW2XW1Y;
//     if (str == "W1XW2YW1YW2X")
//         return W1XW2YW1YW2X;
//     if (str == "W1XR2XR2YW1Y")
//         return W1XR2XR2YW1Y;
//     if (str == "W1XR2YR2XW1Y")
//         return W1XR2YR2XW1Y;
//     if (str == "R1XW2XW2YR1Y")
//         return R1XW2XW2YR1Y;
//     if (str == "R1XW2YW2XR1Y")
//         return R1XW2YW2XR1Y;
//     if (str == "R1XW2YR1YW2X")
//         return R1XW2YR1YW2X;
//     if (str == "W1XR2YW1YR2X")
//         return W1XR2YW1YR2X;
//     return ILLEGAL;
// }

vector<Pattern*> getAllPatterns(vector<ReadWriteNode> nodes)
{
    vector<Pattern*> patterns = getPatternsFromNodes(nodes, 0);
    vector<Pattern*> falconPatterns = getPatternsFromLengthTwoPattern(patterns);
    patterns.insert(patterns.end(), falconPatterns.begin(), falconPatterns.end());
    return patterns;
}

vector<Pattern*> getPatternsFromNodes(vector<ReadWriteNode> nodes, int window)
{
    vector<Pattern*> patterns;
    unordered_map<string, vector<ReadWriteNode>> nodesByAddr;

    for (auto node : nodes)
    {
        nodesByAddr[node.var].push_back(node);
    }

    for (auto it = nodesByAddr.begin(); it != nodesByAddr.end(); ++it)
    {
        auto var = it->first;
        auto nodes = it->second;
        for (size_t i = 0; i < nodes.size(); ++i)
        {
            ReadWriteNode node = nodes[i];
            if (window == 0)
            {
                vector<Pattern*> p = getPatterns(nodes, node, i + 1, nodes.size());
                patterns.insert(patterns.end(), p.begin(), p.end());
            }
            else
            {
                int end = i + window > nodes.size() ? nodes.size() : i + window;
                vector<Pattern*> p = getPatterns(nodes, node, i + 1, end);
                patterns.insert(patterns.end(), p.begin(), p.end());
            }
        }
    }
    return patterns;
}


vector<Pattern*> getUnicornPatternsFromLengthTwoPattern(Pattern* curPattern, vector<Pattern*> patterns)
{
    Pattern* nextPattern = nullptr;
    Pattern* generatedPattern = nullptr;
    vector<Pattern*> res;
    for (size_t i = 0; i < patterns.size(); ++i)
    {
        nextPattern = patterns[i];
        if (nextPattern->nodes.size() != 2)
        {
            continue;
        } 
        generatedPattern = tryConstructUnicornPattern(curPattern, nextPattern);
        if (generatedPattern != nullptr)
        {
            res.push_back(generatedPattern);
        }
    }
    return res;
}

vector<Pattern*> getPatternsFromLengthTwoPattern(vector<Pattern*> patterns)
{
    Pattern *curPattern = nullptr, *nextPattern = nullptr;
    Pattern* generatedPattern = nullptr;
    vector<Pattern*> res;
    for (size_t i = 0; i < patterns.size(); ++i)
    {
        curPattern = patterns[i];
        if (curPattern->nodes.size() != 2)
        {
            continue;
        }
        for (size_t j = i + 1; j < patterns.size(); ++j)
        {
            nextPattern = patterns[j];
            if (nextPattern->nodes.size() != 2)
            {
                continue;
            }

            generatedPattern = tryConstructFalconPattern(curPattern, nextPattern);
            if (generatedPattern != nullptr)
            {
                res.push_back(generatedPattern);
            }

            generatedPattern = tryConstructUnicornPattern(curPattern, nextPattern);
            if (generatedPattern != nullptr)
            {
                res.push_back(generatedPattern);
            }
        }
    }
    return res;
}

vector<Pattern*> getPatterns(vector<ReadWriteNode> nodes, ReadWriteNode curNode, int start, int end)
{
    vector<Pattern*> tmpPattern;
    if (curNode.type == READ)
    {
        for (size_t i = start; i < end; ++i)
        {
            auto node = nodes[i];

            if (node.type == READ && node.selector == curNode.selector)
            {
                break;
            }  //最后一个读

            if (node.type == WRITE && node.selector != curNode.selector)
            {
                tmpPattern.push_back(new Pattern({curNode, node}));
                break;
            }  // 第一个写

            if (node.type == WRITE)
            {
                break;
            }
        }
    }
    else
    {
        for (size_t i = start; i < end; ++i)
        {
            auto node = nodes[i];
            if (node.type == READ && node.selector != curNode.selector)
            {
                tmpPattern.push_back(new Pattern({curNode, node}));
                continue;
            }  //所有的读

            if (node.type == WRITE && node.selector != curNode.selector)
            {
                tmpPattern.push_back(new Pattern({curNode, node}));
                break;
            }  // 第一个写

            if (node.type == WRITE)
            {
                break;
            }
        }
    }
    return tmpPattern;
}

Pattern* tryConstructFalconPattern(Pattern* p1, Pattern* p2)
{
    auto nodes1 = p1->nodes;
    auto nodes2 = p2->nodes;

    if (nodes1.size() != 2 || nodes2.size() != 2)
    {
        return nullptr;
    }
    else
    {
        auto node1 = nodes1[0];
        auto node2 = nodes1[1];
        auto node3 = nodes2[0];
        auto node4 = nodes2[1];

        if (node2.GID == node3.GID)
        {
            return new Pattern({node1, node2, node4});
        }
        return nullptr;
    }
}

Pattern* tryConstructUnicornPattern(Pattern* p1, Pattern* p2)
{
    auto nodes1 = p1->nodes;
    auto nodes2 = p2->nodes;

    if (nodes1.size() != 2 || nodes2.size() != 2)
    {
        return nullptr;
    }
    else
    {
        auto node1 = nodes1[0];
        auto node2 = nodes1[1];
        auto node3 = nodes2[0];
        auto node4 = nodes2[1];

        if (node1.var == node3.var)
        {
            return nullptr;
        }

        if (node1.type == WRITE && node2.type == WRITE && node3.type == WRITE &&
            node4.type == WRITE)
        {
            if (node1.GID < node2.GID && node2.GID < node3.GID && node3.GID < node4.GID)
            {
                Pattern* tmp = new Pattern({node1, node2, node3, node4});
                tmp->patternType = "WXWXWYWY";
                return tmp;
            }
            if (node1.GID < node3.GID && node3.GID < node2.GID && node2.GID < node4.GID)
            {
                Pattern* tmp = new Pattern({node1, node3, node2, node4});
                tmp->patternType = "WXWYWXWY";
                return tmp;
            }
            if (node1.GID < node3.GID && node3.GID < node4.GID && node4.GID < node2.GID)
            {
                Pattern* tmp = new Pattern({node1, node3, node4, node2});
                tmp->patternType = "WXWYWYWX";
                return tmp;
            }
        }


        if (node1.type == WRITE && node2.type == READ && node3.type == READ && node4.type == WRITE)
        {
            if (node1.GID < node2.GID && node2.GID < node3.GID && node3.GID < node4.GID)
            {
                Pattern* tmp = new Pattern({node1, node2, node3, node4});
                tmp->patternType = "WXRXRYWY";
                return tmp;
            }
            if (node1.GID < node3.GID && node3.GID < node2.GID && node2.GID < node4.GID)
            {
                Pattern* tmp = new Pattern({node1, node3, node2, node4});
                tmp->patternType = "WXRYRXWY";
                return tmp;
            }
            if (node1.GID < node3.GID && node3.GID < node4.GID && node4.GID < node2.GID)
            {
                Pattern* tmp = new Pattern({node1, node3, node4, node2});
                tmp->patternType = "WXRYWYRX";
                return tmp;
            }
        }


        if (node1.type == READ && node2.type == WRITE && node3.type == WRITE && node4.type == READ)
        {
            if (node1.GID < node2.GID && node2.GID < node3.GID && node3.GID < node4.GID)
            {
                Pattern* tmp = new Pattern({node1, node2, node3, node4});
                tmp->patternType = "RXWXWYRY";
                return tmp;
            }
            if (node1.GID < node3.GID && node3.GID < node2.GID && node2.GID < node4.GID)
            {
                Pattern* tmp = new Pattern({node1, node3, node2, node4});
                tmp->patternType = "RXWYWXRY";
                return tmp;
            }
            if (node1.GID < node3.GID && node3.GID < node4.GID && node4.GID < node2.GID)
            {
                Pattern* tmp = new Pattern({node1, node3, node4, node2});
                tmp->patternType = "RXWYRYWX";
                return tmp;
            }
        }
        return nullptr;
    }
}

bool isTheSamePattern(const Pattern* p1, const Pattern* p2)
{
    if (p1->nodes.size() != p2->nodes.size() || p1->patternType != p2->patternType)
    {
        return false;
    }
    auto nodes1 = p1->nodes;
    auto nodes2 = p2->nodes;
    for (int i = 0; i < nodes1.size(); ++i)
    {
        if (nodes1[i].var != nodes2[i].var || nodes1[i].selector != nodes2[i].selector)
        {
            return false;
        }
    }
    return true;
}

string getString(Pattern* p)
{
    string str;
    str += "Pattern {\n";
    for (auto node : p->nodes)
    {
        str += "   " + node.type + "Node: [ selector: " + std::to_string(node.selector) +
               ", var: " + node.var + " ]\n";
    }
    str += "}\n";
    return str;
}

bool isRead(vector<ReadWriteNode> trace, string var)
{  //看第一个对var的操作是READ
    if (trace.size() == 0)
    {
        return false;
    }
    for (auto node : trace)
    {
        if (node.var == var)
        {
            return node.type == READ;
        }
    }
    return false;
}

bool isWrite(vector<ReadWriteNode> trace, string var)
{  //看是否存在对var的写
    if (trace.size() == 0)
    {
        return false;
    }
    for (auto node : trace)
    {
        if (node.var == var && node.type == WRITE)
        {
            return true;
        }
    }
    return false;
}

//以这个func的Type操作为第一个Node，去匹配所有可能的Pattern, 最终返回函数调用的前缀
vector<vector<size_t>> getNewPatternPrefixes(EventType type, uint32_t func,
    unordered_set<uint32_t> readCandidates, unordered_set<uint32_t> writeCandidates,
    unordered_map<uint32_t, size_t> funcIdxs)
{
    vector<vector<size_t>> res;
    if (type == READ)
    {
        for (auto writeCandidate : writeCandidates)
        {
            // RW
            auto p1 = {funcIdxs[func], funcIdxs[writeCandidate]};
            res.push_back(p1);
            // RWR、RWW
            auto p2 = {funcIdxs[func], funcIdxs[writeCandidate], funcIdxs[func]};
            res.push_back(p2);
        }
    }
    if (type == WRITE)
    {
        for (auto readCandidate : readCandidates)
        {
            // WR
            auto p1 = {funcIdxs[func], funcIdxs[readCandidate]};
            res.push_back(p1);
            // WRW
            auto p2 = {funcIdxs[func], funcIdxs[readCandidate], funcIdxs[func]};
            res.push_back(p2);
        }
        for (auto writeCandidate : writeCandidates)
        {
            // WW
            auto p1 = {funcIdxs[func], funcIdxs[writeCandidate]};
            res.push_back(p1);
            // WWW WWR
            auto p2 = {funcIdxs[func], funcIdxs[writeCandidate], funcIdxs[func]};
            res.push_back(p2);
        }
    }

    return res;
}


vector<Pattern*> getPossiblePatterns(string var, EventType type, uint32_t func,
    unordered_map<uint32_t, bytes> readCandidates, unordered_map<uint32_t, bytes> writeCandidates)
{
    vector<Pattern*> res;
    if (type == READ) {
        for (auto it = writeCandidates.begin(); it != writeCandidates.end(); ++it)
        {
            auto writeCandidate = it->first;
            // R(WriteCandidate) 
            res.push_back(new Pattern(
                {ReadWriteNode(func, READ, var), ReadWriteNode(writeCandidate, WRITE, var)}));
            // (WriteCandidate)R
            res.push_back(new Pattern(
                {ReadWriteNode(writeCandidate, WRITE, var), ReadWriteNode(func, READ, var)}));
            // R(WriteCandidate)R
            res.push_back(new Pattern({ReadWriteNode(func, READ, var),
                ReadWriteNode(writeCandidate, WRITE, var), ReadWriteNode(func, READ, var)}));
            // (WriteCandidate)R(WriteCandidate)
            res.push_back(new Pattern({ReadWriteNode(writeCandidate, WRITE, var), 
                ReadWriteNode(func, READ, var), ReadWriteNode(writeCandidate, WRITE, var)}));
            // RWW
            if (writeCandidates.find(func) != writeCandidates.end())
            {
                res.push_back(new Pattern({ReadWriteNode(func, READ, var),
                    ReadWriteNode(writeCandidate, WRITE, var), ReadWriteNode(func, WRITE, var)}));
            }
        }
    }
    if (type == WRITE)
    {
        for (auto it = writeCandidates.begin(); it != writeCandidates.end(); ++it)
        {
            auto writeCandidate = it->first;
            // W(WriteCandidate)
            res.push_back(new Pattern(
                {ReadWriteNode(func, WRITE, var), ReadWriteNode(writeCandidate, WRITE, var)}));
            // (WriteCandidate)W
            res.push_back(new Pattern(
                {ReadWriteNode(writeCandidate, WRITE, var), ReadWriteNode(func, WRITE, var)}));
            // W(WriteCandidate)W
            res.push_back(new Pattern({ReadWriteNode(func, WRITE, var),
                ReadWriteNode(writeCandidate, WRITE, var), ReadWriteNode(func, WRITE, var)}));
            // (WriteCandidate)W(WriteCandidate)
            res.push_back(new Pattern({ReadWriteNode(writeCandidate, WRITE, var),ReadWriteNode(func, WRITE, var),
                ReadWriteNode(writeCandidate, WRITE, var) }));
            // WWR
            if (readCandidates.find(func) != readCandidates.end())
            {
                res.push_back(new Pattern({ReadWriteNode(func, WRITE, var),
                    ReadWriteNode(writeCandidate, WRITE, var), ReadWriteNode(func, READ, var)}));
            }
        }
        for (auto it = readCandidates.begin(); it != readCandidates.end(); ++it)
        {
            auto readCandidate = it->first;
            // W(ReadCandidate)
            res.push_back(new Pattern(
                {ReadWriteNode(func, WRITE, var), ReadWriteNode(readCandidate, READ, var)}));
            // W(ReadCandidate)
            res.push_back(new Pattern(
                {ReadWriteNode(readCandidate, READ, var),ReadWriteNode(func, WRITE, var) }));
            // W(ReadCandidate)W
            res.push_back(new Pattern({ReadWriteNode(func, WRITE, var),
                ReadWriteNode(readCandidate, READ, var), ReadWriteNode(func, WRITE, var)}));
            // (ReadCandidate)W(ReadCandidate)
            res.push_back(new Pattern({ReadWriteNode(readCandidate, READ, var),ReadWriteNode(func, WRITE, var),
                ReadWriteNode(readCandidate, READ, var) }));
        }
    }
    return res;
}

bytes formatFuzzData(bytes header, bytes constructor, vector<pair<uint32_t, bytes>>& funcs)
{
    header.insert(header.end(), constructor.begin(), constructor.end());
    for (auto func : funcs)
    {
        header.insert(header.end(), func.second.begin() + 4, func.second.end());
    }
    return header;
}

bytes formatFuzzData(bytes header, bytes constructor, vector<bytes>& funcs)
{
    header.insert(header.end(), constructor.begin(), constructor.end());
    for (auto func : funcs)
    {
        header.insert(header.end(), func.begin() + 4, func.end());
    }
    return header;
}

vector<int> generateNDiffNum(int min, int max, int n)
{
    srand((unsigned)time(0));
    int rnd;
    vector<int> diff;
    vector<int> tmp(max - min + 1);
    for (int i = 0; i < n; i++)
    {
        do
        {
            rnd = min + rand() % (max - min);
        } while (tmp[rnd] < 0);
        tmp[rnd] = -1;
        diff.push_back(rnd);
    }
    return diff;
}


}  // namespace fuzzer
