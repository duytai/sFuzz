#include "TargetContainer.h"
#include "Util.h"
#include "ContractABI.h"

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;

namespace fuzzer {
  TargetContainer::TargetContainer(bytes code, ContractABI ca): code(code), ca(ca){
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
    Timer timer;
    ca.updateTestData(data);
    bytes con = ca.encodeConstructor();
    vector<bytes> funcs = ca.encodeFunctions();
    program.invoke(CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), onOp);
    for (auto func: funcs) {
      program.invoke(CONTRACT_FUNCTION, func, onOp);
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
