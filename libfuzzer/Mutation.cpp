#include "Mutation.h"
#include "Util.h"

using namespace std;
using namespace fuzzer;

int Mutation::havocDiv = 1;
Mutation::Mutation(FuzzItem item): curFuzzItem(item), dataSize(item.data.size()) {
  aCollect = vector<u8>(MAX_AUTO_EXTRA, 0);
  effCount = 0;
  spliceCycle = 0;
  doingDet = 1;
  perfScore = 100;
  prevCksum = curFuzzItem.res.cksum;
  eff = bytes(effALen(dataSize), 0);
  eff[0] = 1;
  if (effAPos(dataSize - 1) != 0) {
    eff[effAPos(dataSize - 1)] = 1;
    effCount ++;
  }
}

void Mutation::flipbit(int pos) {
  curFuzzItem.data[pos >> 3] ^= (128 >> (pos & 7));
}

void Mutation::singleWalkingBit(OnMutateFunc cb) {
  int maxStage = dataSize << 3;
  u32 aLen = 0;
  u8 *out_buf = &curFuzzItem.data[0];
  for (int i = 0; i < maxStage ; i += 1) {
    flipbit(i);
    FuzzItem item = cb(curFuzzItem.data);
    flipbit(i);
    /* Add auto extras */
    if ((i & 7) == 7) {
      h256 cksum = item.res.cksum;
      if (i == maxStage - 1 && cksum == prevCksum) {
        if (aLen < MAX_AUTO_EXTRA) aCollect[aLen] = out_buf[i >> 3];
        aLen ++;
        if (aLen >= MIN_AUTO_EXTRA && aLen <= MAX_AUTO_EXTRA) {
          //maybe_add_auto(a_collect, a_len);
        }
      } else if (cksum != prevCksum) {
        if (aLen >= MIN_AUTO_EXTRA && aLen <= MAX_AUTO_EXTRA) {
          //maybe_add_auto(a_collect, a_len);
        }
        aLen = 0;
        prevCksum = cksum;
      }
      if (cksum != curFuzzItem.res.cksum) {
        if (aLen < MAX_AUTO_EXTRA) aCollect[aLen] = out_buf[i >> 3];
        aLen ++;
      }
    } 
  }
}

void Mutation::twoWalkingBit(OnMutateFunc cb) {
  int maxStage = (dataSize << 3) - 1;
  for (int i = 0; i < maxStage; i += 1) {
    flipbit(i);
    flipbit(i + 1);
    cb(curFuzzItem.data);
    flipbit(i);
    flipbit(i + 1);
  }
}

void Mutation::fourWalkingBit(OnMutateFunc cb) {
  int maxStage = (dataSize << 3) - 3;
  for (int i = 0; i < maxStage; i += 1) {
    flipbit(i);
    flipbit(i + 1);
    flipbit(i + 2);
    flipbit(i + 3);
    cb(curFuzzItem.data);
    flipbit(i);
    flipbit(i + 1);
    flipbit(i + 2);
    flipbit(i + 3);
  }
}

void Mutation::singleWalkingByte(OnMutateFunc cb) {
  for (int i = 0; i < dataSize; i += 1) {
    curFuzzItem.data[i] ^= 0xFF;
    FuzzItem item = cb(curFuzzItem.data);
    /* We also use this stage to pull off a simple trick: we identify
     bytes that seem to have no effect on the current execution path
     even when fully flipped - and we skip them during more expensive
     deterministic stages, such as arithmetics or known ints. */
    if (!eff[effAPos(i)]) {
      if (item.res.cksum != curFuzzItem.res.cksum) {
        eff[effAPos(i)] = 1;
        effCount += 1;
      }
    }
    curFuzzItem.data[i] ^= 0xFF;
  }
  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
   whole thing as worth fuzzing, since we wouldn't be saving much time
   anyway. */
  if (effCount != effALen(dataSize) && effCount * 100 / effALen(dataSize) > EFF_MAX_PERC) {
    eff = bytes(effALen(dataSize), 1);
  }
}

void Mutation::twoWalkingByte(OnMutateFunc cb) {
  int maxStage = dataSize - 1;
  u8 *buf = &curFuzzItem.data[0];
  for (int i = 0; i < maxStage; i += 1) {
    /* Let's consult the effector map... */
    if (!eff[effAPos(i)] && !eff[effAPos(i + 1)]) {
      continue;
    }
    *(u16*)(buf + i) ^= 0xFFFF;
    cb(curFuzzItem.data);
    *(u16*)(buf + i) ^= 0xFFFF;
  }
}

void Mutation::fourWalkingByte(OnMutateFunc cb) {
  int maxStage = dataSize - 3;
  u8 *buf = &curFuzzItem.data[0];
  for (int i = 0; i < maxStage; i += 1) {
    /* Let's consult the effector map... */
    if (!eff[effAPos(i)] && !eff[effAPos(i + 1)] &&
        !eff[effAPos(i + 2)] && !eff[effAPos(i + 3)]) {
      continue;
    }
    *(u32*)(buf + i) ^= 0xFFFFFFFF;
    cb(curFuzzItem.data);
    *(u32*)(buf + i) ^= 0xFFFFFFFF;
  }
}

void Mutation::singleArith(OnMutateFunc cb) {
  for (int i = 0; i < dataSize; i += 1) {
    /* Let's consult the effector map... */
    if (!eff[effAPos(i)]) {
      continue;
    }
    byte orig = curFuzzItem.data[i];
    for (int j = 1; j <= ARITH_MAX; j += 1) {
      byte r = orig ^ (orig + j);
      if (!couldBeBitflip(r)) {
        curFuzzItem.data[i] = orig + j;
        cb(curFuzzItem.data);
      }
      r = orig ^ (orig - j);
      if (!couldBeBitflip(r)) {
        curFuzzItem.data[i] = orig - j;
        cb(curFuzzItem.data);
      }
      curFuzzItem.data[i] = orig;
    }
  }
}

void Mutation::twoArith(OnMutateFunc cb) {
  byte *buf = &curFuzzItem.data[0];
  for (int i = 0; i < dataSize - 1; i += 1) {
    u16 orig = *(u16*)(buf + i);
    if (!eff[effAPos(i)] && !eff[effAPos(i + 1)]) {
      continue;
    }
    for (int j = 0; j < ARITH_MAX; j += 1) {
      u16 r1 = orig ^ (orig + j);
      u16 r2 = orig ^ (orig - j);
      u16 r3 = orig ^ swap16(swap16(orig) + j);
      u16 r4 = orig ^ swap16(swap16(orig) - j);
      if ((orig & 0xFF) + j > 0xFF && !couldBeBitflip(r1)) {
        *(u16*)(buf + i) = orig + j;
        cb(curFuzzItem.data);
      }
      if ((orig & 0xFF) < j && !couldBeBitflip(r2)) {
        *(u16*)(buf + i) = orig - j;
        cb(curFuzzItem.data);
      }
      if ((orig >> 8) + j > 0xFF && !couldBeBitflip(r3)) {
        *(u16*)(buf + i) = swap16(swap16(orig) + j);
        cb(curFuzzItem.data);
      };
      if ((orig >> 8) < j && !couldBeBitflip(r4)) {
        *(u16*)(buf + i) = swap16(swap16(orig) - j);
        cb(curFuzzItem.data);
      };
      *(u16*)(buf + i) = orig;
    }
  }
}

void Mutation::fourArith(OnMutateFunc cb) {
  byte *buf = &curFuzzItem.data[0];
  for (int i = 0; i < dataSize - 3; i += 1) {
    u32 orig = *(u32*)(buf + i);
    /* Let's consult the effector map... */
    if (!eff[effAPos(i)] && !eff[effAPos(i + 1)] && !eff[effAPos(i + 2)] && !eff[effAPos(i + 3)]) {
      continue;
    }
    for (int j = 0; j < ARITH_MAX; j += 1) {
      u32 r1 = orig ^ (orig + j);
      u32 r2 = orig ^ (orig - j);
      u32 r3 = orig ^ swap32(swap32(orig) + j);
      u32 r4 = orig ^ swap32(swap32(orig) - j);
      if ((orig & 0xFFFF) + j > 0xFFFF && !couldBeBitflip(r1)) {
        *(u32*)(buf + i) = orig + j;
        cb(curFuzzItem.data);
      }
      if ((orig & 0xFFFF) < (u32)j && !couldBeBitflip(r2)) {
        *(u32*)(buf + i) = orig - j;
        cb(curFuzzItem.data);
      };
      if ((swap32(orig) & 0xFFFF) + j > 0xFFFF && !couldBeBitflip(r3)) {
        *(u32*)(buf + i) = swap32(swap32(orig) + j);
        cb(curFuzzItem.data);
      };
      if ((swap32(orig) & 0xFFFF) < (u32) j && !couldBeBitflip(r4)) {
        *(u32*)(buf + i) = swap32(swap32(orig) - j);
        cb(curFuzzItem.data);
      };
      *(u32*)(buf + i) = orig;
    }
  }
}

void Mutation::singleInterest(OnMutateFunc cb) {
  for (int i = 0; i < dataSize; i += 1) {
    u8 orig = curFuzzItem.data[i];
    /* Let's consult the effector map... */
    if (!eff[effAPos(i)]) {
      continue;
    }
    for (int j = 0; j < (int) INTERESTING_8.size(); j += 1) {
      if (couldBeBitflip(orig ^ (u8)INTERESTING_8[j]) || couldBeArith(orig, (u8)INTERESTING_8[j], 1)) {
        continue;
      }
      curFuzzItem.data[i] = INTERESTING_8[j];
      cb(curFuzzItem.data);
      curFuzzItem.data[i] = orig;
    }
  }
}

void Mutation::twoInterest(OnMutateFunc cb) {
  byte *out_buf = &curFuzzItem.data[0];
  for (int i = 0; i < dataSize - 1; i += 1) {
    u16 orig = *(u16*)(out_buf + i);
    if (!eff[effAPos(i)] && !eff[effAPos(i + 1)]) {
      continue;
    }
    for (int j = 0; j < (int) INTERESTING_16.size() / 2; j += 1) {
      if (!couldBeBitflip(orig ^ (u16)INTERESTING_16[j]) &&
          !couldBeArith(orig, (u16)INTERESTING_16[j], 2) &&
          !couldBeInterest(orig, (u16)INTERESTING_16[j], 2, 0)) {
        *(u16*)(out_buf + i) = INTERESTING_16[j];
        cb(curFuzzItem.data);
      }
      
      if ((u16)INTERESTING_16[j] != swap16(INTERESTING_16[j]) &&
          !couldBeBitflip(orig ^ swap16(INTERESTING_16[j])) &&
          !couldBeArith(orig, swap16(INTERESTING_16[j]), 2) &&
          !couldBeInterest(orig, swap16(INTERESTING_16[j]), 2, 1)) {
        *(u16*)(out_buf + i) = swap16(INTERESTING_16[j]);
        cb(curFuzzItem.data);
      }
    }
    *(u16*)(out_buf + i) = orig;
  }
}

void Mutation::fourInterest(OnMutateFunc cb) {
  byte *out_buf = &curFuzzItem.data[0];
  for (int i = 0; i < dataSize - 3; i++) {
    u32 orig = *(u32*)(out_buf + i);
    /* Let's consult the effector map... */
    if (!eff[effAPos(i)] && !eff[effAPos(i + 1)] &&
        !eff[effAPos(i + 2)] && !eff[effAPos(i + 3)]) {
      continue;
    }
    for (int j = 0; j < (int) INTERESTING_32.size() / 4; j++) {
      /* Skip if this could be a product of a bitflip, arithmetics,
       or word interesting value insertion. */
      if (!couldBeBitflip(orig ^ (u32)INTERESTING_32[j]) &&
          !couldBeArith(orig, INTERESTING_32[j], 4) &&
          !couldBeInterest(orig, INTERESTING_32[j], 4, 0)) {
        *(u32*)(out_buf + i) = INTERESTING_32[j];
        cb(curFuzzItem.data);
      }
      if ((u32)INTERESTING_32[j] != swap32(INTERESTING_32[j]) &&
          !couldBeBitflip(orig ^ swap32(INTERESTING_32[j])) &&
          !couldBeArith(orig, swap32(INTERESTING_32[j]), 4) &&
          !couldBeInterest(orig, swap32(INTERESTING_32[j]), 4, 1)) {
        *(u32*)(out_buf + i) = swap32(INTERESTING_32[j]);
        cb(curFuzzItem.data);
      }
    }
    *(u32*)(out_buf + i) = orig;
  }
}
/*
 Has to update: doingDet, perfScore, havocDiv, extraCnt, aExtraCnt
 */
void Mutation::havoc(OnMutateFunc) {
  int stageMax = 0;
  int extrasCnt = 0;
  int aExtrasCnt = 0;
  int tempLen = dataSize;
  byte *out_buf = &curFuzzItem.data[0];
  if (!spliceCycle) {
    stageMax = (doingDet ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) * perfScore / havocDiv / 100;
  } else {
    stageMax = SPLICE_HAVOC * perfScore / havocDiv / 100;
  }
  if (stageMax < HAVOC_MIN) stageMax = HAVOC_MIN;
  for (int stageCur = 0; stageCur < stageMax; stageCur += 1) {
    u32 useStacking = 1 << (1 + UR(HAVOC_STACK_POW2));
    for (u32 i = 0; i < useStacking; i += 1) {
      u32 val = UR(15 + ((extrasCnt + aExtrasCnt) ? 2 : 0));
      val = 4;
      switch (val) {
        case 0: {
          /* Flip a single bit somewhere. Spooky! */
          flipbit(UR(tempLen << 3));
          break;
        }
        case 1: {
          /* Set byte to interesting value. */
          curFuzzItem.data[UR(tempLen)] = INTERESTING_8[UR(INTERESTING_8.size())];
          break;
        }
        case 2: {
          /* Set word to interesting value, randomly choosing endian. */
          if (tempLen < 2) break;
          if (UR(2)) {
            *(u16*)(out_buf + UR(tempLen - 1)) = INTERESTING_16[UR(INTERESTING_16.size() >> 1)];
          } else {
            *(u16*)(out_buf + UR(tempLen - 1)) = swap16(INTERESTING_16[UR(INTERESTING_16.size() >> 1)]);
          }
          break;
        }
        case 3: {
          /* Set dword to interesting value, randomly choosing endian. */
          if (tempLen < 4) break;
          if (UR(2)) {
            *(u32*)(out_buf + UR(tempLen - 3)) = INTERESTING_32[UR(INTERESTING_32.size() >> 2)];
          } else {
            *(u32*)(out_buf + UR(tempLen - 3)) = swap32(INTERESTING_32[UR(INTERESTING_32.size() >> 2)]);
          }
          break;
        }
        case 4: {
          /* Randomly subtract from byte. */
          out_buf[UR(tempLen)] -= 1 + UR(ARITH_MAX);
          break;
        }
        case 5: {
          /* Randomly add to byte. */
          out_buf[UR(tempLen)] += 1 + UR(ARITH_MAX);
          break;
        }
        case 6: {
          /* Randomly subtract from word, random endian. */
          if (tempLen < 2) break;
          if (UR(2)) {
            u32 pos = UR(tempLen - 1);
            *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(tempLen - 1);
            u16 num = 1 + UR(ARITH_MAX);
            *(u16*)(out_buf + pos) = swap16(swap16(*(u16*)(out_buf + pos)) - num);
          }
          break;
        }
        case 7: {
          /* Randomly add to word, random endian. */
          if (tempLen < 2) break;
          if (UR(2)) {
            u32 pos = UR(tempLen - 1);
            *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(tempLen - 1);
            u16 num = 1 + UR(ARITH_MAX);
            *(u16*)(out_buf + pos) = swap16(swap16(*(u16*)(out_buf + pos)) + num);
          }
          break;
        }
        case 8: {
          /* Randomly subtract from dword, random endian. */
          if (tempLen < 4) break;
          if (UR(2)) {
            u32 pos = UR(tempLen - 3);
            *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(tempLen - 3);
            u32 num = 1 + UR(ARITH_MAX);
            *(u32*)(out_buf + pos) = swap32(swap32(*(u32*)(out_buf + pos)) - num);
          }
          break;
        }
        case 9: {
          /* Randomly add to dword, random endian. */
          if (tempLen < 4) break;
          if (UR(2)) {
            u32 pos = UR(tempLen - 3);
            *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(tempLen - 3);
            u32 num = 1 + UR(ARITH_MAX);
            *(u32*)(out_buf + pos) = swap32(swap32(*(u32*)(out_buf + pos)) + num);
          }
          break;
        }
        case 10: {
          /* Just set a random byte to a random value. Because,
           why not. We use XOR with 1-255 to eliminate the
           possibility of a no-op. */
          out_buf[UR(tempLen)] ^= 1 + UR(255);
          break;
        }
        case 11 ... 12: {
          break;
        }
        case 13:
        case 14:
        case 15:
        case 16:
        default:
          break;
      }
    }
  }
}

void Mutation::splice(OnMutateFunc) {
  
}
