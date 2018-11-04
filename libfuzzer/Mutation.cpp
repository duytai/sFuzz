#include "Mutation.h"
#include "Dictionary.h"
#include "Util.h"
#include "AutoDictionary.h"

using namespace std;
using namespace fuzzer;


Mutation::Mutation(FuzzItem item, Dictionary dict, AutoDictionary& autoDict, Logger& logger): curFuzzItem(item), dict(dict), autoDict(autoDict), logger(logger), dataSize(item.data.size()) {
  effCount = 0;
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
  bytes autoExtras;
  h256 prevCksum = curFuzzItem.res.cksum;
  for (int i = 0; i < maxStage ; i += 1) {
    flipbit(i);
    FuzzItem item = cb(curFuzzItem.data);
    flipbit(i);
    logger.entry.fuzzed += 1;
    /* Handle auto extra here */
    if ((i & 7) == 7) {
      /* End of each byte */
      h256 cksum = item.res.cksum;
      if (i == maxStage - 1 && prevCksum == cksum) {
        if (autoExtras.size() < MAX_AUTO_EXTRA) {
          autoExtras.push_back(curFuzzItem.data[i >> 3]);
        }
        if (autoExtras.size() > MIN_AUTO_EXTRA && autoExtras.size() < MAX_AUTO_EXTRA) {
          autoDict.maybeAddAuto(autoExtras);
        }
      } else if (cksum != prevCksum) {
        if (autoExtras.size() > MIN_AUTO_EXTRA && autoExtras.size() < MAX_AUTO_EXTRA) {
          autoDict.maybeAddAuto(autoExtras);
          autoExtras.clear();
        }
        prevCksum = cksum;
      }
      if (cksum != curFuzzItem.res.cksum) {
        if (autoExtras.size() < MAX_AUTO_EXTRA) {
          autoExtras.push_back(curFuzzItem.data[i >> 3]);
        }
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

void Mutation::overwriteWithAutoDictionary(OnMutateFunc cb) {
  byte *outBuf = &curFuzzItem.data[0];
  byte inBuf[curFuzzItem.data.size()];
  memcpy(inBuf, outBuf, curFuzzItem.data.size());
  u32 extrasCount = autoDict.extras.size();
  /*
   * In solidity - data block is 32 bytes then change to step = 32, not 1
   * Size of extras is alway 32
   */
  for (u32 i = 0; i < (u32)dataSize; i += 32) {
    u32 lastLen = 0;
    for (u32 j = 0; j < extrasCount; j += 1) {
      byte *extrasBuf = &autoDict.extras[j].data[0];
      byte *effBuf = &eff[0];
      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
       skip them if there's no room to insert the payload, if the token
       is redundant, or if its entire span has no bytes set in the effector
       map. */
      if ((extrasCount > MAX_DET_EXTRAS
           && UR(extrasCount) > MAX_DET_EXTRAS)
          || !memcmp(extrasBuf, outBuf + i, 32)
          || !memchr(effBuf + effAPos(i), 1, effSpanALen(i, 32))
          ) {
        continue;
      }
      lastLen = 32;
      memcpy(outBuf + i, extrasBuf, lastLen);
      cb(curFuzzItem.data);
    }
    /* Restore all the clobbered memory. */
    memcpy(outBuf + i, inBuf + i, lastLen);
  }
}

void Mutation::overwriteWithDictionary(OnMutateFunc cb) {
  byte *outBuf = &curFuzzItem.data[0];
  byte inBuf[curFuzzItem.data.size()];
  memcpy(inBuf, outBuf, curFuzzItem.data.size());
  u32 extrasCount = dict.extras.size();
  /*
   * In solidity - data block is 32 bytes then change to step = 32, not 1
   * Size of extras is alway 32
   */
  for (u32 i = 0; i < (u32)dataSize; i += 32) {
    u32 lastLen = 0;
    for (u32 j = 0; j < extrasCount; j += 1) {
      byte *extrasBuf = &dict.extras[j].data[0];
      byte *effBuf = &eff[0];
      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
       skip them if there's no room to insert the payload, if the token
       is redundant, or if its entire span has no bytes set in the effector
       map. */
      if ((extrasCount > MAX_DET_EXTRAS
          && UR(extrasCount) > MAX_DET_EXTRAS)
          || !memcmp(extrasBuf, outBuf + i, 32)
          || !memchr(effBuf + effAPos(i), 1, effSpanALen(i, 32))
          ) {
        continue;
      }
      lastLen = 32;
      memcpy(outBuf + i, extrasBuf, lastLen);
      cb(curFuzzItem.data);
    }
    /* Restore all the clobbered memory. */
    memcpy(outBuf + i, inBuf + i, lastLen);
  }
}

void Mutation::insertWithDictionary(OnMutateFunc cb) {
  u32 extrasCount = dict.extras.size();
  bytes temp = bytes(curFuzzItem.data.size() + 32, 0);
  byte * tempBuf = &temp[0];
  byte * outBuf = &curFuzzItem.data[0];
  for (int i = 0; i < dataSize; i += 32) {
    for (u32 j = 0; j < extrasCount; j += 1) {
      if (dataSize + dict.extras[j].data.size() > MAX_FILE) {
        /* Larger than MAX_FILE */
        continue;
      }
      byte * extraBuf = &dict.extras[j].data[0];
      /* Insert token */
      memcpy(tempBuf + i, extraBuf, 32);
      /* Copy tail */
      memcpy(tempBuf + i + 32, outBuf + i, dataSize - i);
      cb(temp);
    }
    /* Copy head */
    memcpy(tempBuf + i, outBuf + i, 32);
  }
}

/*
 Has to update: doingDet, perfScore, havocDiv, extraCnt, aExtraCnt
 */
void Mutation::havoc(OnMutateFunc) {
  byte *out_buf = &curFuzzItem.data[0];
  for (int stageCur = 0; stageCur < HAVOC_MIN; stageCur += 1) {
    u32 useStacking = 1 << (1 + UR(HAVOC_STACK_POW2));
    for (u32 i = 0; i < useStacking; i += 1) {
      u32 val = UR(15 + ((dict.extras.size() + autoDict.extras.size()) ? 2 : 0));
      switch (val) {
        case 0: {
          /* Flip a single bit somewhere. Spooky! */
          flipbit(UR(dataSize << 3));
          break;
        }
        case 1: {
          /* Set byte to interesting value. */
          curFuzzItem.data[UR(dataSize)] = INTERESTING_8[UR(INTERESTING_8.size())];
          break;
        }
        case 2: {
          /* Set word to interesting value, randomly choosing endian. */
          if (dataSize < 2) break;
          if (UR(2)) {
            *(u16*)(out_buf + UR(dataSize - 1)) = INTERESTING_16[UR(INTERESTING_16.size() >> 1)];
          } else {
            *(u16*)(out_buf + UR(dataSize - 1)) = swap16(INTERESTING_16[UR(INTERESTING_16.size() >> 1)]);
          }
          break;
        }
        case 3: {
          /* Set dword to interesting value, randomly choosing endian. */
          if (dataSize < 4) break;
          if (UR(2)) {
            *(u32*)(out_buf + UR(dataSize - 3)) = INTERESTING_32[UR(INTERESTING_32.size() >> 2)];
          } else {
            *(u32*)(out_buf + UR(dataSize - 3)) = swap32(INTERESTING_32[UR(INTERESTING_32.size() >> 2)]);
          }
          break;
        }
        case 4: {
          /* Randomly subtract from byte. */
          out_buf[UR(dataSize)] -= 1 + UR(ARITH_MAX);
          break;
        }
        case 5: {
          /* Randomly add to byte. */
          out_buf[UR(dataSize)] += 1 + UR(ARITH_MAX);
          break;
        }
        case 6: {
          /* Randomly subtract from word, random endian. */
          if (dataSize < 2) break;
          if (UR(2)) {
            u32 pos = UR(dataSize - 1);
            *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(dataSize - 1);
            u16 num = 1 + UR(ARITH_MAX);
            *(u16*)(out_buf + pos) = swap16(swap16(*(u16*)(out_buf + pos)) - num);
          }
          break;
        }
        case 7: {
          /* Randomly add to word, random endian. */
          if (dataSize < 2) break;
          if (UR(2)) {
            u32 pos = UR(dataSize - 1);
            *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(dataSize - 1);
            u16 num = 1 + UR(ARITH_MAX);
            *(u16*)(out_buf + pos) = swap16(swap16(*(u16*)(out_buf + pos)) + num);
          }
          break;
        }
        case 8: {
          /* Randomly subtract from dword, random endian. */
          if (dataSize < 4) break;
          if (UR(2)) {
            u32 pos = UR(dataSize - 3);
            *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(dataSize - 3);
            u32 num = 1 + UR(ARITH_MAX);
            *(u32*)(out_buf + pos) = swap32(swap32(*(u32*)(out_buf + pos)) - num);
          }
          break;
        }
        case 9: {
          /* Randomly add to dword, random endian. */
          if (dataSize < 4) break;
          if (UR(2)) {
            u32 pos = UR(dataSize - 3);
            *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(dataSize - 3);
            u32 num = 1 + UR(ARITH_MAX);
            *(u32*)(out_buf + pos) = swap32(swap32(*(u32*)(out_buf + pos)) + num);
          }
          break;
        }
        case 10: {
          /* Just set a random byte to a random value. Because,
           why not. We use XOR with 1-255 to eliminate the
           possibility of a no-op. */
          out_buf[UR(dataSize)] ^= 1 + UR(255);
          break;
        }
        case 11 ... 12: {
          /* Delete bytes. We're making this a bit more likely
           than insertion (the next option) in hopes of keeping
           files reasonably small. */
          if (dataSize < 2) break;
          u32 delLen = chooseBlockLen(dataSize - 1);
          u32 delFrom = UR(dataSize - delLen + 1);
          curFuzzItem.data.erase(curFuzzItem.data.begin() + delFrom, curFuzzItem.data.begin() + delFrom + delLen);
          dataSize -= delLen;
          break;
        }
        case 13: {
          break;
        }
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
