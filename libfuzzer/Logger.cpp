#include "Logger.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  void Logger::log(string d) {
    data << d;
  }
  
  void Logger::clear() {
    data.str("");
  }
  
  void Logger::writeOut(bool isInteresting) {
    if (!enable) return;
    ofstream outfile;
    counter ++;
    string filename = contractName + "/log" + (isInteresting ? "_i_" : "_");
    filename = filename + to_string(counter) + ".txt";
    outfile.open(filename, std::ios_base::out);
    outfile << data.str() << endl;
    clear();
    outfile.close();
  }
}
