
#include <iostream>

#include "gtest/gtest.h"
#include <libfuzzer/TargetProgram.h>
#include <libfuzzer/Abi.h>

using namespace fuzzer;

TEST(TargetProgram, DISABLED_deploy)
{
  string codeStr = "608060405260008060006101000a81548163ffffffff021916908360030b63ffffffff16021790555034801561003457600080fd5b5060405160208061016a83398101806040528101908080519060200190929190505050806000806101000a81548163ffffffff021916908360030b63ffffffff1602179055505060e1806100896000396000f300608060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063e42a722b146044575b600080fd5b348015604f57600080fd5b50607c600480360381019080803560030b9060200190929190803560030b90602001909291905050506098565b604051808260030b60030b815260200191505060405180910390f35b600081836000809054906101000a900460030b01019050929150505600a165627a7a7230582001ebfb62992d52bb602c8aed5791818ca598630b3fc7229432ab4cfcc2b7f5dc0029";
  OnOpFunc onOp = [](uint64_t, uint64_t, Instruction, bigint, bigint, bigint,
                     VMFace const*, ExtVMFace const*) {};
  TargetProgram p;
  p.deploy(fromHex(codeStr));
  bytes data = encodeABI("", vector<string>{"int32"}, vector<bytes>{fromHex("4")});
  bytes addData = encodeABI("add", vector<string> {"int32", "int32"}, vector<bytes> {fromHex("1"), fromHex("4")});
  p.invoke(CONTRACT_CONSTRUCTOR,data, onOp);
  auto r = p.invoke(CONTRACT_FUNCTION,addData, onOp);
  cout << r.output << endl;
}
