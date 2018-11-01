#include <iostream>

#include "gtest/gtest.h"
#include <libfuzzer/Fuzzer.h>
#include <libfuzzer/Util.h>
#include <libfuzzer/ContractABI.h>

using namespace fuzzer;
using namespace std;

TEST(Fuzzer, DISABLED_hasNewBits)
{
  bytes code;
  ContractABI ca;
  Fuzzer fuzzer(code, ca);
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
  bytes code = fromHex("60806040526000805534801561001457600080fd5b506040516020806101a68339810180604052810190808051906020019092919050505080600081905550506101588061004e6000396000f300608060405260043610610041576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a5f3c23b14610046575b600080fd5b34801561005257600080fd5b5061007b6004803603810190808035906020019092919080359060200190929190505050610091565b6040518082815260200191505060405180910390f35b6000818313156100c25760006002848115156100a957fe5b0714156100b95760009050610126565b60019050610126565b828213156100f15760006002838115156100d857fe5b0714156100e85760009050610126565b60029050610126565b8183141561012057600060028481151561010757fe5b0714156101175760039050610126565b60049050610126565b60005490505b929150505600a165627a7a7230582049191804b62fc1bc3b034998fdb1840907690dd09bdace0268e759ea49e101f30029");
  string abiJson = "[{\"constant\":false,\"inputs\":[{\"name\":\"a\",\"type\":\"int256\"},{\"name\":\"b\",\"type\":\"int256\"}],\"name\":\"add\",\"outputs\":[{\"name\":\"\",\"type\":\"int256\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"name\":\"init\",\"type\":\"int256\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]";
  ContractABI ca(abiJson);
  Fuzzer fuzzer(code, ca);
  fuzzer.start();
}
