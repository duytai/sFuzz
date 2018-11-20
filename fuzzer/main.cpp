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

int main(int argc, char* argv[]) {
  /* Run EVM silently */
  dev::LoggingOptions logOptions;
  logOptions.verbosity = VerbositySilent;
  dev::setupLogging(logOptions);
  /* Program options */
  path p("contracts/");
  string jsonFile = "";
  string contractName = "";
  int mode = 1;
  int duration = 600;
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help,h", "produce help message")
    ("scan,s", "scan and generate working script")
    ("file,f", po::value(&jsonFile), "fuzz a contract")
    ("name,n", po::value(&contractName), "contract name")
    ("clean,c", "clean all generated files")
  ("mode,m", po::value(&mode), "choose mode: 0 - Random | 1 - AFL ")
    ("duration,d", po::value(&duration), "fuzz duration");
  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);
  
  if (vm.count("help")) {
    cout << desc << "\n";
    printf("Example: \n");
    printf("> Scan contracts/ folder to create executable file\n");
    printf("  " cGRN "./fuzzer -s" cRST "\n");
    printf("> Clean all generated files\n");
    printf("> Fuzz one contract\n");
    printf("  " cGRN "./fuzzer -s" cRST "\n");
    return 0;
  }
  if (vm.count("clean")) {
    remove_all("fuzzMe");
    for (auto& file : boost::make_iterator_range(directory_iterator(p), {})) {
      if (is_directory(file) || !boost::ends_with(file.path().string(), ".sol")) {
        remove_all(file);
      }
    }
  }
  if (vm.count("scan")) {
    std::ofstream fuzzMe("fuzzMe");
    int numContracts = 0;
    /* List all .sol files */
    stringstream os;
    fuzzMe << "#!/bin/bash" << endl;
    for (auto& file : boost::make_iterator_range(directory_iterator(p), {})) {
      if (!is_directory(file.status()) && boost::ends_with(file.path().string(), ".sol")) {
        string filePath = file.path().string();
        string fileName = file.path().filename().replace_extension("").string();
        fuzzMe << "solc --combined-json abi,bin,bin-runtime ";
        fuzzMe << filePath;
        fuzzMe << " > " << filePath + ".json" << endl;
        string contractName = fileName.find("_0x") != string::npos ? fileName.substr(0, fileName.find("_0x")) : fileName;
        os << "./fuzzer -f " + filePath + ".json";
        os << " -n " + contractName;
        os << " -d " + to_string(duration);
        os << " -m " + to_string(mode);
        os << "\n";
        numContracts ++;
      }
    }
    fuzzMe << os.str() << endl;
    fuzzMe.close();
    printf(cGRN "> Created \"fuzzMe\" file with the following properties:" cRST "\n");
    printf("  - Duration = %d\n", duration);
    printf("  - Contracts = %d\n", numContracts);
    printf(cGRN "> To run fuzz contracts:" cRST "\n");
    printf("  chmod +x fuzzMe\n");
    printf("  ./fuzzMe\n");
    return 0;
  }
  if (vm.count("file") && vm.count("name") && vm.count("duration")) {
    std::ifstream file(jsonFile);
    if (!file.is_open()) {
      cout << "[x] File " << jsonFile << " is not found " << endl;
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
    auto abiJson = root.get<string>(abiPath);
    auto bin = root.get<string>(binPath);
    auto binRuntime = root.get<string>(binRuntimePath);
    ContractABI ca(abiJson);
    CFG cfg(bin, binRuntime);
    FuzzMode fuzzMode = mode == 1 ? AFL : RANDOM;
    Fuzzer fuzzer(fromHex(bin), ca, cfg, fullContractName, duration, fuzzMode);
    fuzzer.start();
    return 0;
  }
  return 0;
}
