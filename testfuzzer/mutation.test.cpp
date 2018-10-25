#include <iostream>

#include "gtest/gtest.h"
#include <libfuzzer/Mutation.h>

using namespace fuzzer;
using namespace std;

TEST(Mutation, bitFlip)
{
  Mutation m = Mutation(fromHex("0xffffffffaaaaaaaabbbbbbbbcccccccc"));
  auto emptyCallback = [](bytes){};
//  auto outCallback = [](bytes b) {
//    cout << toHex(b) << endl;
//  };
  m.singleWalkingBit(emptyCallback);
  m.twoWalkingBit(emptyCallback);
  m.fourWalkingBit(emptyCallback);
  m.singleWalkingByte(emptyCallback);
  m.twoWalkingByte(emptyCallback);
  m.fourWalkingByte(emptyCallback);
  EXPECT_EQ(1, 1);
}
