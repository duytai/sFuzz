## 1. Project structure

I keep the same structure of origin project and added some folders:
- `libfuzzer`: fuzzer functions
- `testfuzzer`: writing unit tests for libfuzzer
- `fuzzer`: build executable fuzzer

## 2. How to build current project

```bash
cd YOUR_PROJECT_FOLDER/
mkdir build 
cd build
cmake .. # common editors
cmake -G Xcode .. # create Xcode's project structure
```
## 3. How to interact with c++ EVM
The source code is not stable yet, but you can do like this:

```c++
#include <libfuzzer/TargetProgram.h>
#include <libfuzzer/Abi.h>

int main() {
  string codeStr = "608060405260008060006101000a81548163ffffffff021916908360030b63ffffffff16021790555034801561003457600080fd5b5060405160208061016a83398101806040528101908080519060200190929190505050806000806101000a81548163ffffffff021916908360030b63ffffffff1602179055505060e1806100896000396000f300608060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063e42a722b146044575b600080fd5b348015604f57600080fd5b50607c600480360381019080803560030b9060200190929190803560030b90602001909291905050506098565b604051808260030b60030b815260200191505060405180910390f35b600081836000809054906101000a900460030b01019050929150505600a165627a7a7230582001ebfb62992d52bb602c8aed5791818ca598630b3fc7229432ab4cfcc2b7f5dc0029";
  OnOpFunc onOp = [](uint64_t, uint64_t, Instruction, bigint, bigint, bigint, VMFace const*, ExtVMFace const*) {
    /*
    * TODO: Write your code to catch opcode
    */
  };
  TargetProgram p;
  p.deploy(fromHex(codeStr));
  bytes constructorData = fromHex("ENCODED ABI");
  bytes functionData = fromHex("ENCODED ABI");
  /* Call contract constructor */
  p.invoke(CONTRACT_CONSTRUCTOR, constructorData, onOp);
  /* Call contract function */
  p.invoke(CONTRACT_FUNCTION, functionData, onOp);
  return 1;
}
```
or you can take a look at this file [main.cpp](https://github.com/duytai/aleth/blob/master/aleth-vm/main.cpp) to see offcial example of etheremum c++.
## 4. Suggestions
- You can create new library and executable target for your project like: `libasan`(library) and `asan` (library)
- If you are familar with CMake then it is easy to add new target otherwise [CMake](https://cmake.org/cmake-tutorial/) or copy my CMakelist.txt file and edit.

## 5. IDE
There are two great editors which support CMake by nature.
- [Clion](https://www.jetbrains.com/clion/)
- Xcode
