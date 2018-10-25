#include <iostream>

#include "gtest/gtest.h"
#include <libfuzzer/Mutation.h>

using namespace fuzzer;
using namespace std;

TEST(Mutation, bitFlip)
{
  Mutation m = Mutation(fromHex("0xffffffff"));
  m.bitflip([](bytes d) {
    cout << toHex(d) << endl;
  });
  EXPECT_EQ(1, 1);
}
