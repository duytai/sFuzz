#pragma once
#include <iostream>

namespace fuzzer {
  static int EFF_MIN_LEN = 1;
  static int EFF_MAP_SCALE2 = 3;
  static int MAP_SIZE_POW2 = 16;
  static int MAP_SIZE = (1 << MAP_SIZE_POW2);
  static int HASH_CONST = 0xa5b35705;
  static int ARITH_MAX = 35;
  static int EFF_MAX_PERC = 90;
  /* Scale position: 1 efficient block contains 8 bytes */
  int effAPos(int p);
  /* Divide with remainder */
  int effRem(int x);
  /* Count number of efficient block*/
  int effALen(int l);
  bool couldBeBitflip(uint32_t xorVal);
  /* Swap 2 bytes */
  uint16_t swap16(uint16_t x);
  /* Swap 4 bytes */
  uint32_t swap32(uint32_t x);
}
