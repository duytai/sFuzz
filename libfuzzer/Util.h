#pragma once
#include "Common.h"
#include "Pattern.h" 
#include <fstream>
#include <unordered_map>
#include <vector>

#define unlikely(_x) __builtin_expect(!!(_x), 0)
#define likely(_x) __builtin_expect(!!(_x), 1)

#define bV "━"
#define bV2 bV bV
#define bV5 bV2 bV2
#define bV10 bV5 bV5
#define bV20 bV10 bV10
#define bV30 bV20 bV10
#define bV50 bV30 bV20

#define bH "┃"
#define bBL "┗"
#define bBR "┛"
#define bTL "┏"
#define bTR "┓"
#define bLTR "┣"
#define bRTR "┫"
#define bBTR "┻"
#define bTTR "┳"
#define bCR "╋"

#define cGRN "\x1b[0;32m"
#define cRED "\x1b[0;31m"
#define cRST "\x1b[0m"
#define Bold "\e[1m"
#define CURSOR_HIDE "\x1b[?25l"
#define FF(_b) (0xff << ((_b) << 3))


using namespace std;
using namespace dev;
using namespace eth;

namespace fuzzer
{
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

static u256 MAX_GAS = 100000000000;
static u160 ATTACKER_ADDRESS = 0xf0;
static u160 CONTRACT_ADDRESS = 0xf2;
static u256 DEFAULT_BALANCE = 0xffffffffff;
static OnOpFunc EMPTY_ONOP = [](u64, u64, Instruction, bigint, bigint, bigint, VMFace const*,
                                 ExtVMFace const*) {};

static u32 SPLICE_CYCLES = 15;
static u32 MAX_DET_EXTRAS = 200;
static int STAGE_FLIP1 = 0;
static int STAGE_FLIP2 = 1;
static int STAGE_FLIP4 = 2;
static int STAGE_FLIP8 = 3;
static int STAGE_FLIP16 = 4;
static int STAGE_FLIP32 = 5;
static int STAGE_ARITH8 = 6;
static int STAGE_ARITH16 = 7;
static int STAGE_ARITH32 = 8;
static int STAGE_INTEREST8 = 9;
static int STAGE_INTEREST16 = 10;
static int STAGE_INTEREST32 = 11;
static int STAGE_EXTRAS_UO = 12;
static int STAGE_EXTRAS_AO = 14;
static int STAGE_HAVOC = 15;
static int STAGE_RANDOM = 16;
static int STAGE_ADD = 17;
static int STAGE_REMOVE = 18;
static int STAGE_SWAP = 19;
static int STAGE_PASSIVE = 20;
static int HAVOC_STACK_POW2 = 7;
static int HAVOC_MIN = 16;
static int EFF_MAP_SCALE2 = 4;  // 32 bytes block
static int ARITH_MAX = 35;
static int EFF_MAX_PERC = 90;
static int DYNAMIC_PATTERN_SAMPLING_MAX = 100;
static s8 INTERESTING_8[] = {-128, -1, 0, 1, 16, 32, 64, 100, 127};
static s16 INTERESTING_16[] = {-128, -1, 0, 1, 16, 32, 64, 100, 127, -32768, -129, 128, 255, 256,
    512, 1000, 1024, 4096, 32767};
static s32 INTERESTING_32[] = {-128, -1, 0, 1, 16, 32, 64, 100, 127, -32768, -129, 128, 255, 256,
    512, 1000, 1024, 4096, 32767, -2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045,
    2147483647};

/* Scale position: 1 efficient block contains 8 bytes */
int effAPos(int p);
/* Divide with remainder */
int effRem(int x);
/* Count number of efficient block*/
int effALen(int l);
/* Len in effector map from position p to p + l */
int effSpanALen(int p, int l);
bool couldBeBitflip(u32 xorVal);
bool couldBeArith(u32 oldVal, u32 newVal, u8 len);
bool couldBeInterest(u32 oldVal, u32 newVal, u8 blen, u8 checkLe);
u32 chooseBlockLen(u32 limit);
u32 UR(u32 limit);
/* Swap 2 bytes */
u16 swap16(u16 x);
/* Swap 4 bytes */
u32 swap32(u32 x);
/* Locate differents */
void locateDiffs(byte* ptr1, byte* ptr2, u32 len, s32* first, s32* last);
string formatDuration(int duration);
string padStr(string str, int len);
/* Data struct */
struct ExtraData
{
    bytes data;
};
vector<string> splitString(string str, char separator);
// PatternType getPatternType(string str);
vector<Pattern*> getAllPatterns(vector<ReadWriteNode> nodes);
vector<Pattern*> getPatternsFromNodes(vector<ReadWriteNode> nodes, int window);
vector<Pattern*> getUnicornPatternsFromLengthTwoPattern(Pattern* p,vector<Pattern*> patterns);
vector<Pattern*> getPatternsFromLengthTwoPattern(vector<Pattern*> patterns);
vector<Pattern*> getPatterns(
    vector<ReadWriteNode> nodes, ReadWriteNode curNode, int start, int end);
Pattern* tryConstructFalconPattern(Pattern* p1, Pattern* p2);
Pattern* tryConstructUnicornPattern(Pattern* p1, Pattern* p2);

bool isTheSamePattern(const Pattern* p1, const Pattern* p2);
string getString(Pattern* p);

bool isRead(vector<ReadWriteNode> trace, string var);
bool isWrite(vector<ReadWriteNode> trace, string var);

vector<vector<size_t>> getNewPatternPrefixes(EventType type, uint32_t func,
    unordered_set<uint32_t> readCandidates, unordered_set<uint32_t> writeCandidates,
    unordered_map<uint32_t, size_t> funcIdxs);

vector<Pattern*> getPossiblePatterns(string var, EventType type, uint32_t func, unordered_map<uint32_t, bytes> readCandidates, unordered_map<uint32_t, bytes> writeCandidates);

bytes formatFuzzData(bytes header, bytes constrcutor, vector<pair<uint32_t, bytes>>& funcs);
bytes formatFuzzData(bytes header, bytes constrcutor, vector<bytes>& funcs);

vector<int> generateNDiffNum(int min, int max, int n);

}  // namespace fuzzer
