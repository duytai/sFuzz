#include "Logger.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  void Logger::log(string content) {
    outfile << content;
  }
}
