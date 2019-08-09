#include "Logger.h"

using namespace std;

namespace fuzzer {
  Logger::Logger() {
    debugFile = ofstream("debug.txt", ios_base::app);
    infoFile = ofstream("info.txt", ios_base::app);
  }

  Logger::~Logger() {
    debugFile.close();
    infoFile.close();
  }

  void Logger::setEnabled(bool _enabled) {
    enabled = _enabled;
  }

  void Logger::debug(string str) {
    if (enabled) {
      debugFile << str << endl;
    }
  }

  void Logger::info(string str) {
    if (enabled) {
      infoFile << str << endl;
    }
  }

  string Logger::testFormat(bytes data) {
    auto idx = 0;
    stringstream ss;
    while (idx < data.size()) {
      bytes d(data.begin() + idx, data.begin() + idx + 32);
      idx += 32;
      ss << toHex(d) << endl;
    }
    return ss.str();
  }
}
