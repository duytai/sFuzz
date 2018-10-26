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
  int startAt = 0;
  ExecutionResult res;
  for (auto it : abi) {
    // break into function data
    auto elemSize = getElemSize(it.second);
    bytes elemData;
    copy(data.begin() + startAt, data.begin() + startAt + elemSize, back_inserter(elemData));
    vector<bytes> values = decodeElem(it.second, elemData);
    // try to decode and call function here
    bytes signature = encodeABI(it.first, it.second, values);
    if (it.first == "")
      res = program.invokeConstructor(signature);
    else
      res = program.invokeFunction(signature);
    startAt += elemSize;
  }
  // reset program and deploy contract
  program.reset();
  program.deploy(code);
}
