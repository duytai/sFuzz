#include <iostream>

#include "gtest/gtest.h"
#include <libfuzzer/Abi.h>

using namespace fuzzer;

TEST(ABI, encodeMethod)
{
  EXPECT_EQ(functionSelector("inc", vector<string> {"int", "uint[2]"}), fromHex("0x99481ac9"));
  EXPECT_EQ(functionSelector("baz", vector<string> {"uint32", "bool"}), fromHex("0xcdcd77c0"));
  EXPECT_EQ(functionSelector("f", vector<string> {"uint", "uint32[]", "bytes10", "bytes"}), fromHex("0x8be65246"));
}

TEST(ABI, fullType)
{
  EXPECT_EQ(tofullType("int"), "int256");
  EXPECT_EQ(tofullType("int2"), "int2");
  EXPECT_EQ(tofullType("uint"), "uint256");
  EXPECT_EQ(tofullType("uint2"), "uint2");
  EXPECT_EQ(tofullType("fixed"), "fixed128x128");
  EXPECT_EQ(tofullType("fixed2"), "fixed2");
  EXPECT_EQ(tofullType("ufixed"), "ufixed128x128");
  EXPECT_EQ(tofullType("ufixed2"), "ufixed2");
  EXPECT_EQ(tofullType("int[10]"), "int256[10]");
  EXPECT_EQ(tofullType("int2[10]"), "int2[10]");
  EXPECT_EQ(tofullType("uint[10]"), "uint256[10]");
  EXPECT_EQ(tofullType("uint2[10]"), "uint2[10]");
  EXPECT_EQ(tofullType("fixed[10]"), "fixed128x128[10]");
  EXPECT_EQ(tofullType("fixed2[10]"), "fixed2[10]");
  EXPECT_EQ(tofullType("ufixed[10]"), "ufixed128x128[10]");
  EXPECT_EQ(tofullType("ufixed2[10]"), "ufixed2[10]");
}

TEST(ABI, encodeParam)
{
  bytes d = encode("baz", vector<string> {"uint32", "bool"});
  EXPECT_EQ(d.size(), 68);
}
