#include <iostream>
#include <vector>
#include <libfuzzer/Fuzzer.h>
#include "Utils.h"

using namespace std;
using namespace fuzzer;

static int DEFAULT_MODE = 1; // AFL
static int DEFAULT_DURATION = 600; // 10 mins
static string DEFAULT_CONTRACTS_FOLDER = "contracts/";
static string DEFAULT_ASSETS_FOLDER = "assets/";

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
    fuzzMe << fuzzJsonFiles(contractsFolder, assetsFolder, duration, mode);
    /* Show response */
    output << cGRN "> Created \"fuzzMe\"" cRST "\n";
    output << cGRN "> To fuzz contracts:" cRST "\n";
    output << "  chmod +x fuzzMe\n";
    output << "  ./fuzzMe\n";
    cout << output.str();
    fuzzMe.close();
    return 0;
  }
  /* Fuzz a single contract */
  if (vm.count("file") && vm.count("name")) {
    FuzzParam fuzzParam;
    fuzzParam.mode = !mode ? RANDOM : AFL;
    fuzzParam.duration = duration;
    fuzzParam.fuzzContract = parseJson(jsonFile, contractName);
    fuzzParam.assetContracts = parseAssets(assetsFolder);
    Fuzzer fuzzer(fuzzParam);
    fuzzer.start();
    return 0;
  }
  return 0;
}
