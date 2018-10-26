#include "Util.h"

int fuzzer::effAPos(int p) {
  return p >> fuzzer::EFF_MAP_SCALE2;
}

int fuzzer::effRem(int x) {
  return (x) & ((1 << fuzzer::EFF_MAP_SCALE2) - 1);
}

int fuzzer::effALen(int l) {
  return fuzzer::effAPos(l) + !!fuzzer::effRem(l);
}
