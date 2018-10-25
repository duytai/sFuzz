#include "Mutation.h"

using namespace std;
using namespace fuzzer;

Mutation::Mutation(bytes b): data(b), dataSize(b.size()) {}

void Mutation::flipbit(int pos) {
  data[pos >> 3] ^= (128 >> (pos & 7));
}

void Mutation::singleWalkingBit(OnMutateFunc cb) {
  int maxStage = dataSize << 3;
  for (int i = 0; i < maxStage ; i += 1) {
    flipbit(i);
    cb(data);
    flipbit(i);
  }
}

void Mutation::twoWalkingBit(OnMutateFunc cb) {
  int maxStage = (dataSize << 3) - 1;
  for (int i = 0; i < maxStage; i += 1) {
    flipbit(i);
    flipbit(i + 1);
    cb(data);
    flipbit(i);
    flipbit(i + 1);
  }
}

void Mutation::fourWalkingBit(OnMutateFunc cb) {
  int maxStage = (dataSize << 3) - 3;
  for (int i = 0; i < maxStage; i += 1) {
    flipbit(i);
    flipbit(i + 1);
    flipbit(i + 2);
    flipbit(i + 3);
    cb(data);
    flipbit(i);
    flipbit(i + 1);
    flipbit(i + 2);
    flipbit(i + 3);
  }
}

void Mutation::singleWalkingByte(OnMutateFunc cb) {
  for (int i = 0; i < dataSize; i += 1) {
    data[i] ^= 0xFF;
    cb(data);
    data[i] ^= 0xFF;
  }
}

void Mutation::twoWalkingByte(OnMutateFunc cb) {
  int maxStage = dataSize - 1;
  for (int i = 0; i < maxStage; i += 1) {
    data[i] ^= 0xFF;
    data[i + 1] ^= 0xFF;
    cb(data);
    data[i] ^= 0xFF;
    data[i + 1] ^= 0xFF;
  }
}

void Mutation::fourWalkingByte(OnMutateFunc cb) {
  int maxStage = dataSize - 3;
  for (int i = 0; i < maxStage; i += 1) {
    data[i] ^= 0xFF;
    data[i + 1] ^= 0xFF;
    data[i + 2] ^= 0xFF;
    data[i + 3] ^= 0xFF;
    cb(data);
    data[i] ^= 0xFF;
    data[i + 1] ^= 0xFF;
    data[i + 2] ^= 0xFF;
    data[i + 3] ^= 0xFF;
  }
}
