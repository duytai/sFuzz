#include <iostream>

#include "gtest/gtest.h"
#include <libfuzzer/Util.h>

using namespace fuzzer;
using namespace std;

TEST(Util, DISABLED_f)
{
  EXPECT_EQ(effAPos(20), 2);
  EXPECT_EQ(effRem(20), 4);
  EXPECT_EQ(effALen(20), 3);
}
