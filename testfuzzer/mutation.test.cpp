#include <iostream>

#include "gtest/gtest.h"
#include <libfuzzer/Mutation.h>
#include <libfuzzer/Fuzzer.h>
#include <libfuzzer/Dictionary.h>
#include <libfuzzer/Logger.h>

using namespace fuzzer;
using namespace std;

TEST(AutoDict, maybeAddAuto) {
  AutoDictionary autoDict;
  bytes data = bytes(20, 0);
  /* Same bytes */
  autoDict.maybeAddAuto(data);
  EXPECT_EQ(autoDict.extras.size(), 0);
  /* Len 2 */
  data = bytes(2, 0);
  data[0] = 3;
  data[1] = 232;
  autoDict.maybeAddAuto(data);
}
TEST(Mutation, DISABLED_singleWalkingBit)
{
  FuzzItem item(fromHex("0x0000000000000000"));
  fuzzer::Logger logger;
  Dictionary dict;
  AutoDictionary autoDict;
  Mutation m = Mutation(item, dict, autoDict, logger);
  int exps[8] = { 1 << 7, 1 << 6, 1 << 5, 1 << 4, 1 << 3, 1 << 2, 1 << 1, 1 };
  int bitCount = 0;
  auto callback = [&](bytes data) {
    int r = data[bitCount >> 3] ^ item.data[bitCount >> 3];
    EXPECT_EQ(r, exps[bitCount % 8]);
    bitCount++;
    return FuzzItem(data);
  };
  m.singleWalkingBit(callback);
  EXPECT_EQ(item.data.size() * 8, bitCount);
}
