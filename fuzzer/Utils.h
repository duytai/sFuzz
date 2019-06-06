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

ContractInfo parseJson(string jsonFile, string contractName, bool isMain) {
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
  contractInfo.isMain = isMain;
  contractInfo.abiJson = root.get<string>(abiPath);
  contractInfo.bin = root.get<string>(binPath);
  contractInfo.binRuntime = root.get_child_optional(binRuntimePath) ? root.get<string>(binRuntimePath) : "";
  contractInfo.contractName = fullContractName;
  return contractInfo;
}

string toContractName(directory_entry file) {
  string filePath = file.path().string();
  string fileName = file.path().filename().string();
  string fileNameWithoutExtension = fileName.find(".") != string::npos
  ? fileName.substr(0, fileName.find("."))
  : fileName;
  string contractName = fileNameWithoutExtension.find("_0x") != string::npos
  ? fileNameWithoutExtension.substr(0, fileNameWithoutExtension.find("_0x"))
  : fileNameWithoutExtension;
  return contractName;
}

void forEachFile(string folder, string extension, function<void (directory_entry)> cb) {
  path folderPath(folder);
  for (auto& file : boost::make_iterator_range(directory_iterator(folderPath), {})) {
    if (is_directory(file.status())) forEachFile(file.path.string(), extension, cb);
    if (!is_directory(file.status()) && boost::ends_with(file.path().string(), extension)) cb(file);
  }
}

string compileSolFiles(string folder) {
  stringstream ret;
  forEachFile(folder, ".sol", [&](directory_entry file) {
    string filePath = file.path().string();
    ret << "solc";
    ret << " --combined-json abi,bin,bin-runtime,srcmap,srcmap-runtime " + filePath;
    ret << " > " + filePath + ".json";
    ret << endl;
  });
  return ret.str();
}

string fuzzJsonFiles(string contracts, string assets, int duration, int mode, int reporter, int logOption, string attackerName, int storageOption) {
  stringstream ret;
  /* search for json file */
  unordered_set<string> contractNames;
  forEachFile(contracts, ".json", [&](directory_entry file) {
    auto filePath = file.path().string();
    auto contractName = toContractName(file);
    contractNames.insert(contractName);
    ret << "./fuzzer";
    ret << " --file " + filePath;
    ret << " --name " + contractName;
    ret << " --assets " + assets;
    ret << " --duration " + to_string(duration);
    ret << " --mode " + to_string(mode);
    ret << " --reporter " + to_string(reporter);
    ret << " --log " + to_string(logOption);
    ret << " --attacker " + attackerName;
    ret << " --storage " + to_string(storageOption);
    ret << endl;
  });
  /* search for sol file */
  forEachFile(contracts, ".sol", [&](directory_entry file) {
    auto filePath = file.path().string();
    auto contractName = toContractName(file);
    if (contractNames.count(contractName)) return;
    ret << "./fuzzer";
    ret << " --file " + filePath + ".json";
    ret << " --name " + contractName;
    ret << " --assets " + assets;
    ret << " --duration " + to_string(duration);
    ret << " --mode " + to_string(mode);
    ret << " --reporter " + to_string(reporter);
    ret << " --log " + to_string(logOption);
    ret << " --attacker " + attackerName;
    ret << " --storage " + to_string(storageOption);
    ret << endl;
  });
  return ret.str();
}


vector<ContractInfo> parseAssets(string assets) {
  vector<ContractInfo> ls;
  forEachFile(assets, ".json", [&](directory_entry file) {
    auto contractName = toContractName(file);
    auto jsonFile = file.path().string();
    ls.push_back(parseJson(jsonFile, contractName, false));
  });
  return ls;
}

void showHelp(po::options_description desc) {
  stringstream output;
  output << desc << endl;
  output << "Example:" << endl;
  output << "> Generate executable scripts" << endl;
  output << "  " cGRN "./fuzzer -g" cRST << endl;
  cout << output.str();
}

void showGenerate() {
  stringstream output;
  output << cGRN "> Created \"fuzzMe\"" cRST "\n";
  output << cGRN "> To fuzz contracts:" cRST "\n";
  output << "  chmod +x fuzzMe\n";
  output << "  ./fuzzMe\n";
  cout << output.str();
}
