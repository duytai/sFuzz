#pragma once
#include<iostream>
#include <fstream>
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;
namespace fuzzer {
  class Logger {
    private:
      bool enabled = false;
      ofstream debugFile;
      ofstream infoFile;
    public:
      Logger();
      ~Logger();
      void setEnabled(bool enabled);
      void info(string str);
      void debug(string str);
      string testFormat(bytes data);
  };
}
