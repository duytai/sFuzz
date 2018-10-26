#include <iostream>

namespace fuzzer {
  static int EFF_MIN_LEN = 1;
  static int EFF_MAP_SCALE2 = 3;
  static int MAP_SIZE_POW2 = 16;
  static int MAP_SIZE = (1 << MAP_SIZE_POW2);
  static int HASH_CONST = 0xa5b35705;
  static int ARITH_MAX = 35;
  
  int effAPos(int p);
  int effRem(int x);
  int effALen(int l);
}
