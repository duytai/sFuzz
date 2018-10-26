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
  OnOpFunc onOp = [](uint64_t, uint64_t pc, Instruction inst, bigint, bigint, bigint, VMFace const*, ExtVMFace const*) {
    auto info = instructionInfo(inst);
    cout << ":: " << info.name << endl;
    if (inst == Instruction::JUMPI) {
      cout << " -> " << pc << endl;
    }
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
    if (it.first == "")
      program.invokeConstructor(signature, onOp);
    else
      program.invokeFunction(signature, onOp);
    startAt += elemSize;
  }
  // Reset program and deploy contract
  program.reset();
  program.deploy(code);
}
