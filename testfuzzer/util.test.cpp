#include <iostream>

#include "gtest/gtest.h"
#include <libfuzzer/Util.h>

using namespace fuzzer;
using namespace std;

TEST(Util, DISABLED_swap32)
{
  EXPECT_EQ(swap32(2878005473), 3789589163);
  EXPECT_EQ(swap32(2747706352), 4037789347);
}
TEST(Util, DISABLED_swap16)
{
  EXPECT_EQ(swap16(4080), 61455);
  EXPECT_EQ(swap16(52275), 13260);
}
TEST(Util, DISABLED_f)
{
  EXPECT_EQ(effAPos(20), 2);
  EXPECT_EQ(effRem(20), 4);
  EXPECT_EQ(effALen(20), 3);
}

TEST(Util, DISABLED_CouldBeBitflip)
{
  EXPECT_EQ(couldBeBitflip(32), true);
}
