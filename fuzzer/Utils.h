#include <iostream>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <libfuzzer/Fuzzer.h>

using namespace std;
using namespace fuzzer;
using namespace boost::filesystem;
namespace pt = boost::property_tree;
namespace po = boost::program_options;

ContractInfo parseJson(string jsonFile, string contractName) {
  std::ifstream file(jsonFile);
  if (!file.is_open()) {
    stringstream output;
    output << "[x] File " + jsonFile + " is not found" << endl;
    cout << output.str();
    exit(0);
  }
  pt::ptree root;
  pt::read_json(jsonFile, root);
  string fullContractName = "";
  for (auto key : root.get_child("contracts")) {
    if (boost::ends_with(key.first, contractName)) {
      fullContractName = key.first;
      break;
    }
  }
  if (!fullContractName.length()) {
    cout << "[x] No contract " << contractName << endl;
    exit(0);
  }
  pt::ptree::path_type abiPath("contracts|"+ fullContractName +"|abi", '|');
  pt::ptree::path_type binPath("contracts|"+ fullContractName +"|bin", '|');
  pt::ptree::path_type binRuntimePath("contracts|" + fullContractName + "|bin-runtime", '|');
  ContractInfo contractInfo;
  contractInfo.abiJson = root.get<string>(abiPath);
  contractInfo.bin = root.get<string>(binPath);
  contractInfo.binRuntime = root.get<string>(binRuntimePath);
  contractInfo.contractName = fullContractName;
  return contractInfo;
}

string toContractName(directory_entry jsonFile) {
  string filePath = jsonFile.path().string();
  string fileName = jsonFile.path().filename().string();
  string fileNameWithoutExtension = fileName.substr(0, fileName.length() - 9);
  string contractName = fileNameWithoutExtension.find("_0x") != string::npos
  ? fileNameWithoutExtension.substr(0, fileNameWithoutExtension.find("_0x"))
  : fileNameWithoutExtension;
  return contractName;
}

void forEachFile(string folder, string extension, function<void (directory_entry)> cb) {
  path folderPath(folder);
  for (auto& file : boost::make_iterator_range(directory_iterator(folderPath), {})) {
    if (!is_directory(file.status()) && boost::ends_with(file.path().string(), extension)) cb(file);
  }
}

string compileSolFiles(string folder) {
  stringstream ret;
  forEachFile(folder, ".sol", [&](directory_entry file) {
    string filePath = file.path().string();
    ret << "solc";
    ret << " --combined-json abi,bin,bin-runtime " + filePath;
    ret << " > " + filePath + ".json";
    ret << endl;
  });
  return ret.str();
}

string fuzzJsonFiles(string contracts, string assets, int duration, int mode) {
  stringstream ret;
  forEachFile(contracts, ".json", [&](directory_entry file) {
    auto filePath = file.path().string();
    auto contractName = toContractName(file);
    ret << "./fuzzer";
    ret << " -f " + filePath;
    ret << " -n " + contractName;
    ret << " -a " + assets;
    ret << " -d " + to_string(duration);
    ret << " -m " + to_string(mode);
    ret << endl;
  });
  return ret.str();
}


vector<ContractInfo> parseAssets(string assets) {
  vector<ContractInfo> ls;
  forEachFile(assets, ".json", [&](directory_entry file) {
    auto contractName = toContractName(file);
    auto jsonFile = file.path().string();
    ls.push_back(parseJson(jsonFile, contractName));
  });
  return ls;
}
