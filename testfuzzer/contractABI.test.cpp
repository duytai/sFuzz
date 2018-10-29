#include <iostream>

#include "gtest/gtest.h"
#include <libfuzzer/ContractABI.h>

using namespace fuzzer;

TEST(ContractABI, encodeArrayDynamic)
{
  DataType dt1(fromHex("0xffffff"), false, true);
  DataType dt2(fromHex("0xaaaaaa"), false, true);
  DataType dt3(fromHex("0xdddddddddd"), false, true);
  vector<DataType> dts = { dt1, dt2, dt3};
  ContractABI ca;
  bytes ret = ca.encodeArray(dts, true);
  cout << toHex(ret) << endl;
}

TEST(ContractABI, encodeArrayStatic)
{
  DataType dt1(fromHex("0xffff"), false, true);
  DataType dt2(fromHex("0xaaaa"), false, true);
  vector<DataType> dts = { dt1, dt2 };
  ContractABI ca;
  bytes ret = ca.encodeArray(dts, false);
  EXPECT_EQ(ret, fromHex("0000000000000000000000000000000000000000000000000000000000000002ffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002aaaa000000000000000000000000000000000000000000000000000000000000"));
}

TEST(ContractABI, encodeSingle)
{
  bytes value = fromHex("0xffff");
  DataType l(value, true /* pad left*/, true /* isDynamic */);
  DataType r(value, false, false);
  EXPECT_EQ(l.header(), fromHex("0000000000000000000000000000000000000000000000000000000000000002"));
  EXPECT_EQ(r.header(), fromHex("0000000000000000000000000000000000000000000000000000000000000002"));
  EXPECT_EQ(l.payload(), fromHex("000000000000000000000000000000000000000000000000000000000000ffff"));
  EXPECT_EQ(r.payload(), fromHex("ffff000000000000000000000000000000000000000000000000000000000000"));
  ContractABI ca;
  EXPECT_EQ(ca.encodeSingle(l), fromHex("0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000ffff"));
  EXPECT_EQ(ca.encodeSingle(r), fromHex("ffff000000000000000000000000000000000000000000000000000000000000"));
  bytes longValue = bytes(33, 0);
  DataType ll(longValue, false, true);
  EXPECT_EQ(ll.payload().size(), 64);
  EXPECT_EQ(ca.encodeSingle(ll).size(), 96);
}
