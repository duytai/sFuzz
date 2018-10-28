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
  /* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */
  bool couldBeArith(uint32_t old_val, uint32_t new_val, uint8_t blen) {
    uint32_t i, ov = 0, nv = 0, diffs = 0;
    if (old_val == new_val) return true;
    /* See if one-byte adjustments to any byte could produce this result. */
    for (i = 0; i < blen; i++) {
      uint8_t a = old_val >> (8 * i),
      b = new_val >> (8 * i);
      if (a != b) { diffs++; ov = a; nv = b; }
    }
    /* If only one byte differs and the values are within range, return 1. */
    if (diffs == 1) {
      if ((uint8_t)(ov - nv) <= ARITH_MAX ||
          (uint8_t)(nv - ov) <= ARITH_MAX) return true;
    }
    if (blen == 1) return false;
    /* See if two-byte adjustments to any byte would produce this result. */
    diffs = 0;
    for (i = 0; i < blen / 2; i++) {
      uint16_t a = old_val >> (16 * i),
      b = new_val >> (16 * i);
      if (a != b) { diffs++; ov = a; nv = b; }
    }
    /* If only one word differs and the values are within range, return 1. */
    if (diffs == 1) {
      if ((uint16_t)(ov - nv) <= ARITH_MAX || (uint16_t)(nv - ov) <= ARITH_MAX)
        return  true;
      ov = swap16(ov); nv = swap16(nv);
      if ((uint16_t)(ov - nv) <= ARITH_MAX || (uint16_t)(nv - ov) <= ARITH_MAX)
        return true;
    }
    /* Finally, let's do the same thing for dwords. */
    if (blen == 4) {
      if ((uint32_t)(old_val - new_val) <= (uint32_t) ARITH_MAX || (uint32_t)(new_val - old_val) <= (uint32_t) ARITH_MAX)
        return true;
      new_val = swap32(new_val);
      old_val = swap32(old_val);
      if ((uint32_t)(old_val - new_val) <= (uint32_t) ARITH_MAX || (uint32_t)(new_val - old_val) <= (uint32_t) ARITH_MAX)
        return true;
    }
    return false;
  }
  
  uint16_t swap16(uint16_t x) {
    return x << 8 | x >> 8;
  }
  
  uint32_t swap32(uint32_t x) {
    return x << 24 | x >> 24 | ((x << 8) & 0x00FF0000) | ((x >> 8) & 0x0000FF00);
  }
}

