#include <iostream>

#include "gtest/gtest.h"
#include <libfuzzer/Abi.h>

TEST(Abi, encode)
{
    int result = add(10, 1);
    EXPECT_EQ(result, 11);
}
