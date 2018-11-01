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
  bytes code = fromHex("60806040526000805534801561001457600080fd5b5060405160208061011583398101806040528101908080519060200190929190505050806000819055505060c88061004d6000396000f300608060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a5f3c23b146044575b600080fd5b348015604f57600080fd5b5060766004803603810190808035906020019092919080359060200190929190505050608c565b6040518082815260200191505060405180910390f35b60008054828401019050929150505600a165627a7a723058203d93221ed677738fe25d32fee10274c53e90ffa7d72db614c33c14b18a83ebc20029");
  string abiJson = "[{\"constant\":false,\"inputs\":[{\"name\":\"a\",\"type\":\"int256\"},{\"name\":\"b\",\"type\":\"int256\"}],\"name\":\"add\",\"outputs\":[{\"name\":\"\",\"type\":\"int256\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"name\":\"init\",\"type\":\"int256\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]";
  ContractABI ca(abiJson);
  Fuzzer fuzzer(code, ca);
  fuzzer.start();
}
