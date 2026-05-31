#include "pefile.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string.h>
#include <vector>
#include <windows.h>


static bool isPe32Plus(const char *path) {
	std::ifstream file(path, std::ios::binary);
	if (!file) {
		return false;
	}

	file.seekg(0, std::ios::end);
	std::streamoff size = file.tellg();
	if (size < 0x3C + static_cast<std::streamoff>(sizeof(DWORD))) {
		return false;
	}

	file.seekg(0x3C, std::ios::beg);
	DWORD peOffset = 0;
	file.read(reinterpret_cast<char *>(&peOffset), sizeof(peOffset));
	if (!file) {
		return false;
	}

	std::streamoff optMagicOffset = static_cast<std::streamoff>(peOffset) + 0x18;
	if (size < optMagicOffset + static_cast<std::streamoff>(sizeof(WORD))) {
		return false;
	}

	file.seekg(peOffset, std::ios::beg);
	DWORD signature = 0;
	file.read(reinterpret_cast<char *>(&signature), sizeof(signature));
	if (!file || signature != IMAGE_NT_SIGNATURE) {
		return false;
	}

	file.seekg(optMagicOffset, std::ios::beg);
	WORD magic = 0;
	file.read(reinterpret_cast<char *>(&magic), sizeof(magic));
	if (!file) {
		return false;
	}

	return magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

int main(int argc, char *argv[]) {
	if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
		std::cout << "pefile.exe [.dll/.exe] [.dll] [function separated by commas]" << std::endl;
		return 1;
	}

	if (strlen(argv[1]) < 4 || (strcasecmp(argv[1] + strlen(argv[1]) - 4, ".dll") != 0 && strcasecmp(argv[1] + strlen(argv[1]) - 4, ".exe") != 0)) {
		std::cout << "Invalid file type. Please specify a .dll/.exe file." << std::endl;
		std::cout << "pefile.exe [.dll/.exe] [.dll] [function separated by commas]" << std::endl;
		return 1;
	} else {
		std::cout << "File specified: " << argv[1] << std::endl;
	}

	if (!isPe32Plus(argv[1])) {
		std::cout << "ERROR: Invalid PE file. Please specify a valid PE32+ .dll/.exe file." << std::endl;
		return 1;
	}

	if (strlen(argv[2]) < 4 || strcasecmp(argv[2] + strlen(argv[2]) - 4, ".dll") != 0) {
		std::cout << "Invalid file type. Please specify a .dll file." << std::endl;
		std::cout << "pefile.exe [.dll/.exe] [.dll] [function separated by commas]" << std::endl;
		return 1;
	} else {
		std::cout << "File specified: " << argv[2] << std::endl;
	}

	if (!isPe32Plus(argv[2])) {
		std::cout << "ERROR: Invalid PE file. Please specify a valid PE32+ .dll file." << std::endl;
		return 1;
	}

	std::vector<std::string> functions;
	std::string function;
	std::stringstream ss(argv[3]);
	while (std::getline(ss, function, ',')) {
		functions.push_back(function);
	}

	std::vector<char *> functionNames;
	functionNames.reserve(functions.size());
	for (std::string &name : functions) {
		functionNames.push_back(const_cast<char *>(name.c_str()));
	}

	PEFile pe(argv[1]);
	std::string importName = std::filesystem::path(argv[2]).filename().string();
	pe.addImport(const_cast<char *>(importName.c_str()), functionNames.data(),
			 static_cast<int>(functionNames.size()));

	std::string outPath = argv[1];
	std::string::size_type sepPos = outPath.find_last_of("\\/");
	std::string::size_type dotPos = outPath.find_last_of('.');
	if (dotPos != std::string::npos && (sepPos == std::string::npos || dotPos > sepPos)) {
		outPath.insert(dotPos, "_mod");
	} else {
		outPath += "_mod";
	}
	std::vector<char> outPathC(outPath.begin(), outPath.end());
	outPathC.push_back('\0');

	pe.saveToFile(outPathC.data());

	std::cout << "Saved file to " << outPath << std::endl;

	return 0;
}