## Building from source

### Get the source code

Git and GitHub are used to maintain the source code. Clone the repository by:

```shell
git clone --recursive git clone --recursive https://github.com/duytai/sFuzz
cd aleth
```

The `--recursive` option is important. It orders git to clone additional
submodules to build the project.
If you missed `--recursive` option, you are able to correct your mistake with command
`git submodule update --init`.

### Install CMake

CMake is used to control the build configuration of the project. Latest version of CMake is required
(at the time of writing [3.4.3 is the minimum](CMakeLists.txt#L25)).
We strongly recommend you to install CMake by downloading and unpacking the binary
distribution  of the latest version available on the
[**CMake download page**](https://cmake.org/download/).

The CMake package available in your operating system can also be installed
and used if it meets the minimum version requirement.

> **Alternative method**
>
> The repository contains the
[scripts/install_cmake.sh](scripts/install_cmake.sh) script that downloads
> a fixed version of CMake and unpacks it to the given directory prefix.
> Example usage: `scripts/install_cmake.sh --prefix /usr/local`.

### Install dependencies (Linux, macOS)

The following *libraries* are required to be installed in the system in their
development variant:

- leveldb

They usually can be installed using system-specific package manager.
The examples for some systems are shown below:

Operating system | Installation command
---------------- | --------------------
Debian-based     | `sudo apt-get install libleveldb-dev`
RedHat-based     | `dnf install leveldb-devel`
macOS            | `brew install leveldb`


We also support a "one-button" shell script
[scripts/install_deps.sh](scripts/install_deps.sh)
which attempts to aggregate dependencies installation instructions for Unix-like
operating systems. It identifies your distro and installs the external packages.
Supporting the script is non-trivial task so please [inform us](#contact)
if it does not work for your use-case.

### Install dependencies (Windows)

We provide prebuilt dependencies to build the project. Download them
with the [scripts\install_deps.bat](scripts/install_deps.bat) script.

```shell
scripts\install_deps.bat
```

### Build

Configure the project build with the following command to create the
`build` directory with the configuration.

```shell
mkdir build; cd build  # Create a build directory.
cmake ..               # Configure the project.
cd fuzzer; make        # Build fuzzer targets.
```

On **Windows** Visual Studio 2015 is required. You should generate Visual Studio
solution file (.sln) for 64-bit architecture by adding
`-G "Visual Studio 14 2015 Win64"` argument to the CMake configure command.
After configuration is completed, the `aleth.sln` can be found in the
`build` directory.

```shell
cmake .. -G "Visual Studio 14 2015 Win64"
```
#### Common Issues Building on Windows
##### LINK : fatal error LNK1158: cannot run 'rc.exe'
Rc.exe is the [Microsoft Resource Compiler](https://docs.microsoft.com/en-us/windows/desktop/menurc/resource-compiler). It's distributed with the [Windows SDK](https://developer.microsoft.com/en-US/windows/downloads/windows-10-sdk) and is required for generating the Visual Studio solution file. It can be found in the following directory: ```%ProgramFiles(x86)%\Windows Kits\<OS major version>\bin\<OS full version>\<arch>\```

If you hit this error, adding the directory to your path (and launching a new command prompt) should fix the issue. 

## Fuzz contract
Create two folders `assets/` and `contracts/` in the same folder as the executable fuzzer file
```shell
mkdir assets/
mkdir contracts/
```
Place two attacker contracts to `assets/`
```shell
# filename: NormalAttacker.sol
pragma solidity ^0.4.2;

contract NormalAttacker {
  uint counter = 0;
  function() payable {
    revert();
  }
}
```
```shell
# filename: ReentrancyAttacker.sol
pragma solidity ^0.4.2;

contract ReentrancyAttacker {
  uint counter = 0;
  function() payable {
    counter ++;
    if (counter <= 2) {
      msg.sender.call(bytes4(255));
    }
    revert();
  }
}
```
Start fuzzing using the command:
```shell
./fuzzer -g -r 0 -d 120 && chmod +x fuzzMe && ./fuzzMe
```

**Note:** sfuzz uses Solidity compiler of linux's enviroment, don't forget to install the compiler which is able to compile your smart contracts. If x.sol is the filename, x is the name of a smart contract in file x.sol. Otherwise, no contract will be found

## License

[![License](https://img.shields.io/github/license/ethereum/aleth.svg)](LICENSE)

All contributions are made under the [GNU General Public License v3](https://www.gnu.org/licenses/gpl-3.0.en.html). See [LICENSE](LICENSE).
