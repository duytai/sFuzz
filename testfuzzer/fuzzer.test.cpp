#include <iostream>

#include "gtest/gtest.h"
#include <libfuzzer/Fuzzer.h>
#include <libfuzzer/Util.h>

using namespace fuzzer;
using namespace std;

TEST(Fuzzer, DISABLED_hasNewBits)
{
  bytes code;
  map<string, vector<string>> abi;
  Fuzzer fuzzer(code, abi);
  bytes tracebits0(MAP_SIZE, 0);
  bytes tracebits1(MAP_SIZE, 0);
  bytes tracebits2(MAP_SIZE, 0);
  bytes tracebits3(MAP_SIZE, 0);
  tracebits1[10] = 1;
  tracebits2[10] = 100;
  tracebits3[1] = 2;
  EXPECT_EQ(fuzzer.hasNewBits(tracebits0), 0);
  // Hit new branches
  EXPECT_EQ(fuzzer.hasNewBits(tracebits1), 2);
  // No new branches
  EXPECT_EQ(fuzzer.hasNewBits(tracebits1), 0);
  // Hit again but more than prev tracebits1
  EXPECT_EQ(fuzzer.hasNewBits(tracebits2), 1);
  // Hit new branches
  EXPECT_EQ(fuzzer.hasNewBits(tracebits3), 2);
}

TEST(Fuzzer, start) {
  bytes code = fromHex("6080604052600a60005534801561001557600080fd5b5060405160208061016d83398101806040528101908080519060200190929190505050806000819055505061011e8061004f6000396000f300608060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a5f3c23b146044575b600080fd5b348015604f57600080fd5b50607660048036038101908080359060200190929190803590602001909291905050506092565b604051808260030b60030b815260200191505060405180910390f35b60008183141560a3576000905060ec565b8183131560b2576001905060ec565b8183121560c1576002905060ec565b600054828401131560d4576003905060ec565b600054828401121560e7576004905060ec565b600590505b929150505600a165627a7a72305820c9e5797295240dd5844a6d0633b82e12235d83781afde20f13a6d4f2577c5c880029");
  map<string, vector<string>> abi;
  abi[""] = vector<string>{"int"};
  abi["add"] = vector<string>{"int", "int"};
  Fuzzer fuzzer(code, abi);
  fuzzer.start();
}
