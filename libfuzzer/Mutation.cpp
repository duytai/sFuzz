#include "Mutation.h"

using namespace std;
using namespace fuzzer;

Mutation::Mutation(bytes b): data(b){}

void Mutation::bitflip(void (*cb)(bytes)) {
  for (int i = 0; i < (int) data.size() * 8 ; i += 1) {
    data[i >> 3] ^= (128 >> (i & 7));
    cb(data);
  }
}

