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

TEST(ABI, toExactType)
{
  EXPECT_EQ(toExactType("bool"), "uint8");
  EXPECT_EQ(toExactType("address"), "uint160");
  EXPECT_EQ(toExactType("int"), "int256");
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
TEST(ABI, encodeConstructor)
{
  vector<string> types = {"uint32", "bool"};
  vector<bytes> values = {fromHex("0x05"), fromHex("0x01")};
  bytes d = encodeABI("", types, values);
  EXPECT_EQ(d.size(), 64);
  EXPECT_EQ(d, fromHex("00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000001"));
}
TEST(ABI, encodeFunction)
{
  vector<string> types = {"uint32", "bool"};
  vector<bytes> values = {fromHex("0x05"), fromHex("0x01")};
  bytes d = encodeABI("baz", types, values);
  EXPECT_EQ(d.size(), 68);
  EXPECT_EQ(d, fromHex("cdcd77c000000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000001"));
}

TEST(ABI, encodeTestcase) {
  vector<string> types = {"int32", "int32", "bool", "address", "uint"};
  bytes d = createEmptyTestcase(types);
  EXPECT_EQ(d.size(), 61);
}

TEST(ABI, decodeTestcase) {
  vector<string> types = {"int32", "int32", "bool", "address"};
  bytes data = fromHex("0000000a0000000b01000000000000000000000000000000000000000f");
  vector<bytes> result = decodeTestcase(types, data);
  EXPECT_EQ(result[0], fromHex("0x0000000a"));
  EXPECT_EQ(result[1], fromHex("0x0000000b"));
  EXPECT_EQ(result[2], fromHex("0x1"));
  EXPECT_EQ(result[3], fromHex("0x000000000000000000000000000000000000000f"));
}
