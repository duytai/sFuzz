#include <iostream>
#include "AutoDictionary.h"

using namespace std;

namespace fuzzer {
  /*
   * FIXME: could be duplicate entry extras
   * try to compare and fix later
   */
  void AutoDictionary::maybeAddAuto(bytes autoExtras) {
    /* Skip runs of identical bytes. */
    byte *autoExtraBuf = &autoExtras[0];
    bytes::size_type len = autoExtras.size();
    bytes::size_type i;
    for (i = 1; i < len; i++)
      if (autoExtras[0] ^ autoExtras[i]) break;
    if (i == len) return;
    /* Reject builtin interesting values. */
    if (len == 2) {
      i = INTERESTING_16.size() >> 1;
      while (i--)
        if (*((u16*)autoExtraBuf) == INTERESTING_16[i] || *((u16*)autoExtraBuf) == swap16(INTERESTING_16[i])) return;
      
    }
    if (len == 4) {
      i = INTERESTING_32.size() >> 2;
      while (i--)
        if (*((u32*)autoExtraBuf) == (u32)INTERESTING_32[i] ||
            *((u32*)autoExtraBuf) == swap32(INTERESTING_32[i])) return;
      
    }
    /* Pad left and Right to enough 32 bytes */
    for (i = 0; i < (32 - len); i += 1) {
      bytes ret(i, 0);
      bytes right((32 - len - i), 0);
      ret.insert(ret.begin(), autoExtras.begin(), autoExtras.end());
      ret.insert(ret.begin(), right.begin(), right.end());
      ExtraData ext;
      ext.data = ret;
      ext.hitCount = 0;
      if (this->extras.size() < MAX_AUTO_EXTRAS) {
        this->extras.push_back(ext);
      } else {
        int idx = MAX_AUTO_EXTRAS / 2 + UR((MAX_AUTO_EXTRAS + 1) / 2);
        this->extras[idx] = ext;
      }
    }
  }
}
