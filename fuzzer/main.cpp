#include <iostream>
#include <vector>
#include <fstream>
#include <thread>
#include <libfuzzer/Fuzzer.h>
#include <libfuzzer/CFG.h>
#include <libfuzzer/ContractABI.h>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <fstream>
#include <unistd.h>

using namespace std;
using namespace fuzzer;
using namespace boost::filesystem;
namespace pt = boost::property_tree;
namespace po = boost::program_options;

static int DEFAULT_MODE = 1; // AFL
static int DEFAULT_DURATION = 600; // 10 mins
static string DEFAULT_CONTRACTS_FOLDER = "contracts/";
static string DEFAULT_ASSETS_FOLDER = "assets/";

string compileSolFiles(string folder) {
  stringstream ret;
  path folderPath(folder);
  for (auto& file : boost::make_iterator_range(directory_iterator(folderPath), {})) {
    if (!is_directory(file.status()) && boost::ends_with(file.path().string(), ".sol")) {
      string filePath = file.path().string();
      ret << "solc";
      ret << " --combined-json abi,bin,bin-runtime " + filePath;
      ret << " > " + filePath + ".json";
      ret << endl;
    }
  }
  return ret.str();
}


string fuzzJsonFiles(string folder, int duration, int mode) {
  stringstream ret;
  path folderPath(folder);
  for (auto& file : boost::make_iterator_range(directory_iterator(folderPath), {})) {
    if (!is_directory(file.status()) && boost::ends_with(file.path().string(), ".json")) {
      string filePath = file.path().string();
      string fileName = file.path().filename().string();
      string fileNameWithoutExtension = fileName.substr(0, fileName.length() - 9);
      string contractName = fileNameWithoutExtension.find("_0x") != string::npos
        ? fileNameWithoutExtension.substr(0, fileNameWithoutExtension.find("_0x"))
        : fileNameWithoutExtension;
      ret << "./fuzzer";
      ret << " -f " + filePath;
      ret << " -n " + contractName;
      ret << " -d " + to_string(duration);
      ret << " -m " + to_string(mode);
      ret << endl;
    }
  }
  return ret.str();
}

int main(int argc, char* argv[]) {
  /* Run EVM silently */
  dev::LoggingOptions logOptions;
  logOptions.verbosity = VerbositySilent;
  dev::setupLogging(logOptions);
  /* Program options */
  int mode = DEFAULT_MODE;
  int duration = DEFAULT_DURATION;
  string contractsFolder = DEFAULT_CONTRACTS_FOLDER;
  string assetsFolder = DEFAULT_ASSETS_FOLDER;
  string jsonFile = "";
  string contractName = "";
  po::options_description desc("Allowed options");
  po::variables_map vm;
  
  desc.add_options()
    ("help,h", "produce help message")
    ("contracts,c", po::value(&contractsFolder), "contract's folder path")
    ("generate,g", "generate fuzzMe script")
    ("assets,a", po::value(&assetsFolder), "asset's folder path")
    ("file,f", po::value(&jsonFile), "fuzz a contract")
    ("name,n", po::value(&contractName), "contract name")
    ("mode,m", po::value(&mode), "choose mode: 0 - Random | 1 - AFL ")
    ("duration,d", po::value(&duration), "fuzz duration");
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);
  /* Show help message */
  if (vm.count("help")) {
    stringstream output;
    output << desc << endl;
    output << "Example:" << endl;
    output << "> Generate executable scripts" << endl;
    output << "  " cGRN "./fuzzer -g" cRST << endl;
    cout << output.str();
    return 0;
  }
  /* Generate working scripts */
  if (vm.count("generate")) {
    std::ofstream fuzzMe("fuzzMe");
    stringstream output;
    fuzzMe << "#!/bin/bash" << endl;
    fuzzMe << compileSolFiles(contractsFolder);
    fuzzMe << compileSolFiles(assetsFolder);
    fuzzMe << fuzzJsonFiles(contractsFolder, duration, mode);
    /* Show response */
    output << cGRN "> Created \"fuzzMe\"" cRST "\n";
    output << cGRN "> To run fuzz contracts:" cRST "\n";
    output << "  chmod +x fuzzMe\n";
    output << "  ./fuzzMe\n";
    cout << output.str();
    fuzzMe.close();
    return 0;
  }
  /* Fuzz a single contract */
  if (vm.count("file") && vm.count("name") && vm.count("duration")) {
    std::ifstream file(jsonFile);
    if (!file.is_open()) {
      stringstream output;
      output << "[x] File " + jsonFile + " is not found" << endl;
      cout << output.str();
      return 0;
    }
    /* Use ptree to read */
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
      return 0;
    }
    cout << fullContractName << endl;
    pt::ptree::path_type abiPath("contracts|"+ fullContractName +"|abi", '|');
    pt::ptree::path_type binPath("contracts|"+ fullContractName +"|bin", '|');
    pt::ptree::path_type binRuntimePath("contracts|" + fullContractName + "|bin-runtime", '|');
    FuzzParam fuzzParam;
    fuzzParam.abiJson = root.get<string>(abiPath);
    fuzzParam.bin = root.get<string>(binPath);
    fuzzParam.binRuntime = root.get<string>(binRuntimePath);
    fuzzParam.mode = !mode ? RANDOM : AFL;
    fuzzParam.contractName = fullContractName;
    fuzzParam.duration = duration;
    Fuzzer fuzzer(fuzzParam);
    fuzzer.start();
    return 0;
  }
  return 0;
}
