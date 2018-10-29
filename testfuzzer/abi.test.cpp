#include <iostream>

#include "gtest/gtest.h"
#include <libfuzzer/Abi.h>

using namespace fuzzer;

TEST(ABI, DISABLED_encodeMethod)
{
  EXPECT_EQ(functionSelector("inc", vector<string> {"int", "uint[2]"}), fromHex("0x99481ac9"));
  EXPECT_EQ(functionSelector("baz", vector<string> {"uint32", "bool"}), fromHex("0xcdcd77c0"));
  EXPECT_EQ(functionSelector("f", vector<string> {"uint", "uint32[]", "bytes10", "bytes"}), fromHex("0x8be65246"));
}

TEST(ABI, DISABLED_getTypeSize)
{
  EXPECT_EQ(getTypeSize("uint256"), 32);
  EXPECT_EQ(getTypeSize("string"), 255);
  EXPECT_EQ(getTypeSize("bytes"), 255);
}

TEST(ABI, DISABLED_toExactType)
{
  EXPECT_EQ(toExactType("bool"), "uint8");
  EXPECT_EQ(toExactType("address"), "uint160");
  EXPECT_EQ(toExactType("int"), "int256");
  EXPECT_EQ(toExactType("bool[10]"), "uint8[10]");
  EXPECT_EQ(toExactType("address[10]"), "uint160[10]");
  EXPECT_EQ(toExactType("int[100][20]"), "int256[100][20]");
  EXPECT_EQ(toExactType("address[29][]"), "uint160[29][]");
}

TEST(ABI, DISABLED_fullType)
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

TEST(ABI, DISABLED_encodeDynamicType)
{
  vector<string> types = {"int", "bytes8", "string", "bytes"};
  bytes intType = bytes(32, 0);
  intType[31] = 255;
  bytes byte8Type = bytes(32, 0);
  byte8Type[0] = 255;
  bytes stringType = bytes(64, 0);
  stringType[0] = 11;
  stringType[1] = 14;
  bytes bytesType = bytes(96, 0);
  vector<bytes> values = {intType, byte8Type, stringType, bytesType};
  bytes d = encodeABI("", types, values);
  cout << toHex(d) << endl;
}

TEST(ABI, DISABLED_encodeConstructor)
{
  vector<string> types = {"uint32", "bool"};
  vector<bytes> values = {fromHex("0x05"), fromHex("0x01")};
  bytes d = encodeABI("", types, values);
  EXPECT_EQ(d.size(), 64);
  EXPECT_EQ(d, fromHex("00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000001"));
}
TEST(ABI, DISABLED_encodeFunction)
{
  vector<string> types = {"uint32", "bool"};
  vector<bytes> values = {fromHex("0x05"), fromHex("0x01")};
  bytes d = encodeABI("baz", types, values);
  EXPECT_EQ(d.size(), 68);
  EXPECT_EQ(d, fromHex("cdcd77c000000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000001"));
}

TEST(ABI, DISABLED_encodeTestcase) {
  vector<string> types = {"int32", "int32", "bool", "address", "uint"};
  bytes d = createElem(types);
  EXPECT_EQ(d.size(), 61);
}

TEST(ABI, DISABLED_decodeTestcase) {
  vector<string> types = {"int32", "int32", "bool", "address"};
  bytes data = fromHex("0000000a0000000b01000000000000000000000000000000000000000f");
  vector<bytes> result = decodeElem(types, data);
  EXPECT_EQ(result[0], fromHex("0x0000000a"));
  EXPECT_EQ(result[1], fromHex("0x0000000b"));
  EXPECT_EQ(result[2], fromHex("0x1"));
  EXPECT_EQ(result[3], fromHex("0x000000000000000000000000000000000000000f"));
}

TEST(ABI, DISABLED_getTestElemSize) {
  vector<string> types = {"int32", "int32", "bool", "address", "uint"};
  EXPECT_EQ(getElemSize(types), 61);
}
