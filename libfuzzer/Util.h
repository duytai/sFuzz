#pragma once
#include <iostream>
#include <vector>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

using namespace std;
namespace fuzzer {
  static int EFF_MIN_LEN = 1;
  static int EFF_MAP_SCALE2 = 3;
  static int MAP_SIZE_POW2 = 16;
  static int MAP_SIZE = (1 << MAP_SIZE_POW2);
  static int HASH_CONST = 0xa5b35705;
  static int ARITH_MAX = 35;
  static int EFF_MAX_PERC = 90;
  static vector<int8_t> INTERESTING_8 = { -128, -1, 0, 1, 16, 32, 64, 100, 127};
  static vector<int16_t> INTERESTING_16 = {-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767};
  static vector<int32_t> INTERESTING_32 = {-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647};
  /* Scale position: 1 efficient block contains 8 bytes */
  int effAPos(int p);
  /* Divide with remainder */
  int effRem(int x);
  /* Count number of efficient block*/
  int effALen(int l);
  bool couldBeBitflip(uint32_t xorVal);
  bool couldBeArith(uint32_t oldVal, uint32_t newVal, uint8_t len);
  /* Swap 2 bytes */
  uint16_t swap16(uint16_t x);
  /* Swap 4 bytes */
  uint32_t swap32(uint32_t x);
}
