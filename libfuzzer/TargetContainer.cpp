#include "TargetContainer.h"
#include "Abi.h"
#include "Util.h"

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;

namespace fuzzer {
  TargetContainer::TargetContainer(bytes c, map<string, vector<string>> a): code(c), abi(a){
    program.deploy(code);
  }
  
  TargetContainerResult TargetContainer::exec(bytes data) {
    /* Save all hit branches to trace_bits */
    Instruction prevInst;
    u64 prevLocation = 0;
    bytes tracebits(MAP_SIZE, 0);
    OnOpFunc onOp = [&](u64, u64 pc, Instruction inst, bigint, bigint, bigint, VMFace const*, ExtVMFace const*) {
      if (prevInst == Instruction::JUMPCI) {
        tracebits[pc ^ prevLocation]++;
        prevLocation = pc >> 1;
      }
      prevInst = inst;
    };
    /* Decode and call functions */
    int startAt = 0;
    Timer timer;
    for (auto it : abi) {
      /* Break into function data */
      auto elemSize = getElemSize(it.second);
      bytes elemData;
      copy(data.begin() + startAt, data.begin() + startAt + elemSize, back_inserter(elemData));
      vector<bytes> values = decodeElem(it.second, elemData);
      /* Try to decode and call function here */
      bytes signature = encodeABI(it.first, it.second, values);
      int type = it.first == "" ? CONTRACT_CONSTRUCTOR : CONTRACT_FUNCTION;
      program.invoke(type, signature, onOp);
      startAt += elemSize;
    }
    /*
     Reset program and deploy again becuase
     it changed after invoke constructor
     */
    program.reset();
    program.deploy(code);
    /*
     Calculate checksum and return response
     */
    return TargetContainerResult(tracebits, sha3(tracebits), timer.elapsed());
  }
}
