#include "TargetContainer.h"
#include "Abi.h"

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;

TargetContainer::TargetContainer(bytes c, map<string, vector<string>> a): code(c), abi(a){
  program.deploy(code);
}

void TargetContainer::exec(bytes data) {
  OnOpFunc onOp = [](uint64_t, uint64_t, Instruction, bigint, bigint, bigint, VMFace const*, ExtVMFace const*) {
  };
  int startAt = 0;
  for (auto it : abi) {
    // Break into function data
    auto elemSize = getElemSize(it.second);
    bytes elemData;
    copy(data.begin() + startAt, data.begin() + startAt + elemSize, back_inserter(elemData));
    vector<bytes> values = decodeElem(it.second, elemData);
    // Try to decode and call function here
    bytes signature = encodeABI(it.first, it.second, values);
    int type = it.first == "" ? CONTRACT_CONSTRUCTOR : CONTRACT_FUNCTION;
    program.invoke(type, signature, onOp);
    startAt += elemSize;
  }
  // Reset program and deploy again becuase it changed after invoke constructor
  program.reset();
  program.deploy(code);
}
