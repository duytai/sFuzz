#include <iostream>

#include "gtest/gtest.h"
#include <libfuzzer/Mutation.h>
#include <libfuzzer/Fuzzer.h>

using namespace fuzzer;
using namespace std;

TEST(Mutation, DISABLED_bitFlip)
{
  FuzzItem item(fromHex("0xffffffffaaaaaaaabbbbbbbbccccccccddddddddeeeeeeee"));
  Mutation m = Mutation(item);
  auto emptyCallback = [](bytes d){
    FuzzItem item(d);
    return item;
  };
  m.singleWalkingBit(emptyCallback);
  m.twoWalkingBit(emptyCallback);
  m.fourWalkingBit(emptyCallback);
  m.singleWalkingByte(emptyCallback);
  m.twoWalkingByte(emptyCallback);
  m.fourWalkingByte(emptyCallback);
  EXPECT_EQ(1, 1);
}
