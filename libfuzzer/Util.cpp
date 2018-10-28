#include "Util.h"

namespace fuzzer {
  int effAPos(int p) {
    return p >> EFF_MAP_SCALE2;
  }
  
  int effRem(int x) {
    return (x) & ((1 << EFF_MAP_SCALE2) - 1);
  }
  
  int effALen(int l) {
    return effAPos(l) + !!effRem(l);
  }
  /* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by afl-fuzz. This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. */
  bool couldBeBitflip(uint32_t xorValue) {
    uint32_t sh = 0;
    if (!xorValue) return true;
    /* Shift left until first bit set. */
    while (!(xorValue & 1)) { sh++ ; xorValue >>= 1; }
    /* 1-, 2-, and 4-bit patterns are OK anywhere. */
    if (xorValue == 1 || xorValue == 3 || xorValue == 15) return 1;
    /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */
    if (sh & 7) return false;
    if (xorValue == 0xff || xorValue == 0xffff || xorValue == 0xffffffff)
      return true;
    return false;
  }
  
  uint16_t swap16(uint16_t x) {
    return x << 8 | x >> 8;
  }
  
  uint32_t swap32(uint32_t x) {
    return x << 24 | x >> 24 | ((x << 8) & 0x00FF0000) | ((x >> 8) & 0x0000FF00);
  }
}

