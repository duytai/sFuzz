#include <iostream>

#include "gtest/gtest.h"
#include <libfuzzer/Mutation.h>
#include <libfuzzer/Fuzzer.h>
#include <libfuzzer/Dictionary.h>

using namespace fuzzer;
using namespace std;

TEST(Mutation, DISABLED_bitFlip)
{
  FuzzItem item(fromHex("0xffffffffaaaaaaaabbbbbbbbccccccccddddddddeeeeeeee"));
  Dictionary dict(fromHex("0x00"));
  AutoDictionary autoDict;
  Mutation m = Mutation(item, dict, autoDict);
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
