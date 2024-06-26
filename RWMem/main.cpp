#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>
#include <fstream>
#include <sstream>
#include <dirent.h>
#include <cinttypes>
#include <iostream>
#include "MapRegionHelper.h"
#include "MemSearchKit/MemSearchKitUmbrella.h"
#include "MemoryReaderWriter37.h"
#include "MapRegionType.h"

using namespace MemorySearchKit;

std::mutex g_lock;

int findPID(const char *lpszCmdline, CMemoryReaderWriter *pDriver) {
	int nTargetPid = 0;

	//Driver Obtain the PID list of the process
	std::vector<int> vPID;
	BOOL bOutListCompleted;
	BOOL b = pDriver->GetProcessPidList(vPID, FALSE, bOutListCompleted);
	printf("Call the driver GetProcessPidList to return a value:%d\n", b);

	//Prints the process list information
	for (int pid : vPID) {
		//Driver Open process
		uint64_t hProcess = pDriver->OpenProcess(pid);
		if (!hProcess) { continue; }

		//Driver Get Process Command Line
		char cmdline[100] = { 0 };
		pDriver->GetProcessCmdline(hProcess, cmdline, sizeof(cmdline));

		//Driver shutdown process
		pDriver->CloseHandle(hProcess);

		if (strcmp(lpszCmdline, cmdline) == 0) {
			nTargetPid = pid;
			break;
		}
	}
	return nTargetPid;
}

void read_memory(CMemoryReaderWriter *pRwDriver, uint64_t hProcess, void *pBuf, size_t bufSize) {
    char readBuf[1024] = { 0 };
    size_t real_read = 0;
    BOOL read_res = pRwDriver->ReadProcessMemory(hProcess, reinterpret_cast<uint64_t>(pBuf), readBuf, bufSize, &real_read, TRUE);
    printf("ReadProcessMemory at address: %p, return value: %d, read content: %s, actual read size: %zu\n", pBuf, read_res, readBuf, real_read);
}

template <typename T>
void write_memory(CMemoryReaderWriter *pRwDriver, uint64_t hProcess, const char *addressStr, const char *userValue) {
    void *pBuf = reinterpret_cast<void*>(std::stoull(addressStr, nullptr, 16));

    T value;
    std::istringstream(userValue) >> value;

    size_t real_write = 0;
    BOOL write_res = pRwDriver->WriteProcessMemory(hProcess, reinterpret_cast<uint64_t>(pBuf), &value, sizeof(value), &real_write, TRUE);
    printf("WriteProcessMemory at address: %p, return value: %d, actual write size: %zu\n", pBuf, write_res, real_write);
}

template <typename T>
void filter_memory(CMemoryReaderWriter *pRwDriver, uint64_t hProcess, const char *fileName, T value, const char *file2Name) {
    std::vector<uint64_t> matchingAddresses;

    std::ifstream infile(fileName);
    if (!infile.is_open()) {
        std::cerr << "Failed to open file: " << fileName << std::endl;
        return;
    }

    std::string line;
    while (std::getline(infile, line)) {
        std::istringstream iss(line);
        std::string addressStr;
        if (!(iss >> addressStr)) {
            continue;
        }

        char *end;
        uint64_t address = strtoull(addressStr.c_str(), &end, 16);
        if (*end != '\0') {
            std::cerr << "Invalid address format: " << addressStr << std::endl;
            continue;
        }

        T readBuf;
        size_t real_read = 0;
        BOOL read_res = pRwDriver->ReadProcessMemory(hProcess, address, &readBuf, sizeof(T), &real_read, TRUE);

        if (read_res && real_read == sizeof(T) && readBuf == value) {
            matchingAddresses.push_back(address);
        }
    }

    std::ofstream outfile(file2Name);
    if (!outfile.is_open()) {
        std::cout << "Failed to open file for writing: " << file2Name << std::endl;
        return;
    }

    for (const auto& addr : matchingAddresses) {
        outfile << "0x" << std::hex << addr << std::endl;
    }

    outfile.close();
    std::cout << "Matching addresses saved to file: " << file2Name << std::endl;
}

template <typename T>
void performBlockSearch(
    CMemoryReaderWriter *pRwDriver,
    uint64_t hProcess,
    std::shared_ptr<MemSearchSafeWorkSecWrapper> spvWaitScanMemSec,
    T searchValue,
    size_t nWorkThreadCount,
    std::vector<ADDR_RESULT_INFO> &vSearchResult,
    size_t blockSize = 1000
) {
    for (size_t i = 0; i < spvWaitScanMemSec->size(); i += blockSize) {
        size_t end = std::min(i + blockSize, spvWaitScanMemSec->size());
        auto block = std::make_shared<MemSearchSafeWorkSecWrapper>(
            spvWaitScanMemSec->begin() + i,
            spvWaitScanMemSec->begin() + end
        );

        std::vector<ADDR_RESULT_INFO> vBlockResult;
        SearchValue<T>(
            pRwDriver,
            hProcess,
            block,
            searchValue,
            0.0f,
            0.01,
            SCAN_TYPE::ACCURATE_VAL,
            nWorkThreadCount,
            vBlockResult,
            4
        );

        vSearchResult.insert(vSearchResult.end(), vBlockResult.begin(), vBlockResult.end());
    }
}

template <typename T>
void performAddrNextValueSearch(
    CMemoryReaderWriter *pRwDriver,
    uint64_t hProcess,
    std::vector<ADDR_RESULT_INFO> &vSearchResult,
    T nextSearchValue,
    size_t nWorkThreadCount,
    std::vector<ADDR_RESULT_INFO> &vErrorList,
    size_t blockSize = 1000
) {
    std::vector<ADDR_RESULT_INFO> vWaitSearchAddr;
    vWaitSearchAddr.reserve(vSearchResult.size());
    for (auto& item : vSearchResult) {
        vWaitSearchAddr.push_back(item);
    }

    vSearchResult.clear();

    for (size_t i = 0; i < vWaitSearchAddr.size(); i += blockSize) {
        size_t end = std::min(i + blockSize, vWaitSearchAddr.size());
        std::vector<ADDR_RESULT_INFO> block(vWaitSearchAddr.begin() + i, vWaitSearchAddr.begin() + end);

        std::vector<ADDR_RESULT_INFO> vBlockResult;
        SearchAddrNextValue<T>(
            pRwDriver,
            hProcess,
            block,
            nextSearchValue,
            0.0f,
            0.01f,
            SCAN_TYPE::ACCURATE_VAL,
            nWorkThreadCount,
            vBlockResult,
            vErrorList
        );

        vSearchResult.insert(vSearchResult.end(), vBlockResult.begin(), vBlockResult.end());
    }
}

template <typename T>
void normal_val_search_and_save(
    CMemoryReaderWriter *pRwDriver,
    uint64_t hProcess,
    size_t nWorkThreadCount,
    T searchValue,
    bool physicalMemoryOnly,
    const char *fileName
) {
    std::vector<DRIVER_REGION_INFO> vScanMemMaps;
    GetMemRegion(pRwDriver, hProcess, R0_0, physicalMemoryOnly, vScanMemMaps);

    if (vScanMemMaps.empty()) {
        std::cout << "No memory to search" << std::endl;
        pRwDriver->CloseHandle(hProcess);
        std::cout << "Driver call CloseHandle: " << hProcess << std::endl;
        return;
    }

    auto spvWaitScanMemSec = std::make_shared<MemSearchSafeWorkSecWrapper>();
    if (!spvWaitScanMemSec) {
        return;
    }

    for (const auto& item : vScanMemMaps) {
        spvWaitScanMemSec->push_back(item.baseaddress, item.size, 0, item.size);
    }

    std::vector<ADDR_RESULT_INFO> vSearchResult;
    std::vector<ADDR_RESULT_INFO> vErrorList;

    // Perform initial block search
    performBlockSearch(pRwDriver, hProcess, spvWaitScanMemSec, searchValue, nWorkThreadCount, vSearchResult);

    std::cout << "Found " << vSearchResult.size() << " addresses" << std::endl;

    if (!vSearchResult.empty()) {
        // Adjust addresses and perform next value search in blocks
        for (auto& item : vSearchResult) {
            item.addr += 20;
        }

        performAddrNextValueSearch<float>(pRwDriver, hProcess, vSearchResult, 1.19175350666f, nWorkThreadCount, vErrorList);

        if (!vSearchResult.empty()) {
            // Adjust addresses and perform next value search in blocks
            for (auto& item : vSearchResult) {
                item.addr += 952;
            }

            performAddrNextValueSearch<int>(pRwDriver, hProcess, vSearchResult, -2147483648, nWorkThreadCount, vErrorList);
        }
    }

    std::ofstream outfile(fileName);
    if (!outfile.is_open()) {
        std::cout << "Failed to open file for writing: " << fileName << std::endl;
        return;
    }

    for (const auto& addr : vSearchResult) {
        outfile << "0x" << std::hex << addr.addr << std::endl;
    }

    outfile.close();
    std::cout << "Matching addresses saved to file: " << fileName << std::endl;
}

int main(int argc, const char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s <target_pkgname> <sub_command> <arg1> <arg2> [<thread_count>]\n", argv[0]);
        printf("Sub commands: read_memory, search_memory, write_memory, filter_memory\n");
        printf("For read_memory: arg1 - memory address, arg2 - buffer size\n");
        printf("For search_memory: arg1 - value type (int, float, long), arg2 - value to search, arg3 - physical memory only (0 for all memory, 1 for physical memory only), arg4 - output file name, [thread_count - optional]\n");
        printf("For write_memory: arg1 - memory address, arg2 - content to write\n");
        printf("For filter_memory: arg1 - file name containing memory addresses in hex format, arg2 - value type (int, float, long), arg3 - value to compare, arg4 - outfile\n");
        return -1;
    }

    const char *targetpkgname = argv[1];
    const char *subCommand = argv[2];

    printf("Target pkgname: %s, Sub command: %s\n", targetpkgname, subCommand);

    CMemoryReaderWriter rwDriver;
    int err;
    BOOL b = rwDriver.ConnectDriver(RWPROCMEM_FILE_NODE, FALSE, err);
    if (!b) {
        printf("Failed to connect to driver\n");
        return -1;
    }

    printf("Driver connected\n");

    pid_t pid = findPID(targetpkgname, &rwDriver);
	if (pid == 0) {
		printf("Process not found\n");
		fflush(stdout);
		return 0;
	}
	printf("PID of the target process:%d\n", pid);

    uint64_t hProcess = rwDriver.OpenProcess(pid);
    if (!hProcess) {
        printf("Failed to open process\n");
        return -1;
    }

    printf("Opened process handle: %" PRIu64 "\n", hProcess);
    fflush(stdout);

    if (strcmp(subCommand, "read_memory") == 0) {
        if (argc != 6) {
            printf("Usage: %s %s <memory_address> <buffer_size>\n", argv[0], subCommand);
            return -1;
        }
        void *pBuf = reinterpret_cast<void*>(std::stoull(argv[3], nullptr, 0));
        size_t bufSize = std::stoul(argv[4]);
        read_memory(&rwDriver, hProcess, pBuf, bufSize);
    } else if (strcmp(subCommand, "search_memory") == 0) {
        if (argc < 7 || argc > 8) {
            printf("Usage: %s %s <value_type> <value_to_search> <physical_memory_only> <output_file_name> [<thread_count>]\n", argv[0], subCommand);
            printf("value_type: int, float, long\n");
            printf("physical_memory_only: 0 for all memory, 1 for physical memory only\n");
            return -1;
        }
        std::string valueType = argv[3];
        bool physicalMemoryOnly = std::stoi(argv[4]);
        size_t threadCount = (argc == 8) ? std::stoul(argv[7]) : 1; // Use 1 thread if not specified

        if (valueType == "int") {
            int searchValue = std::stoi(argv[5]);
            normal_val_search_and_save<int>(&rwDriver, hProcess, threadCount, searchValue, physicalMemoryOnly, argv[6]);
        } else if (valueType == "float") {
            float searchValue = std::stof(argv[5]);
            normal_val_search_and_save<float>(&rwDriver, hProcess, threadCount, searchValue, physicalMemoryOnly, argv[6]);
        } else if (valueType == "long") {
            long searchValue = std::stol(argv[5]);
            normal_val_search_and_save<long>(&rwDriver, hProcess, threadCount, searchValue, physicalMemoryOnly, argv[6]);
        } else {
            printf("Unsupported value type %s\n", valueType.c_str());
            rwDriver.CloseHandle(hProcess);
            return -1;
        }
    } else if (strcmp(subCommand, "write_memory") == 0) {
        if (argc != 5) {
            printf("Usage: %s %s <memory_address> <user_value>\n", argv[0], subCommand);
            return -1;
        }
        const char *addressStr = argv[3];
        const char *userValue = argv[4];

        // Determine the type of the value to write based on the input
        if (strchr(userValue, '.') != nullptr) {
            write_memory<float>(&rwDriver, hProcess, addressStr, userValue);
        } else {
            long tempValue = std::stol(userValue);
            if (tempValue > INT32_MAX || tempValue < INT32_MIN) {
                write_memory<long>(&rwDriver, hProcess, addressStr, userValue);
            } else {
                write_memory<int>(&rwDriver, hProcess, addressStr, userValue);
            }
        }
    } else if (strcmp(subCommand, "filter_memory") == 0) {
        if (argc != 7) {
            printf("Usage: %s %s <file_name> <value_type> <value_to_compare> <outfile>\n", argv[0], subCommand);
            printf("value_type: int, float, long\n");
            return -1;
        }
        const char *fileName = argv[3];
        std::string valueType = argv[4];
        const char *outfile = argv[6];

        if (valueType == "int") {
            int compareValue = std::stoi(argv[5]);
            filter_memory<int>(&rwDriver, hProcess, fileName, compareValue, outfile);
        } else if (valueType == "float") {
            float compareValue = std::stof(argv[5]);
            filter_memory<float>(&rwDriver, hProcess, fileName, compareValue, outfile);
        } else if (valueType == "long") {
            long compareValue = std::stol(argv[5]);
            filter_memory<long>(&rwDriver, hProcess, fileName, compareValue, outfile);
        } else {
            printf("Unsupported value type %s\n", valueType.c_str());
            rwDriver.CloseHandle(hProcess);
            return -1;
        }
    } else {
        printf("Unsupported sub command %s\n", subCommand);
        rwDriver.CloseHandle(hProcess);
        return -1;
    }

    std::cout << "Press any key to exit" << std::endl;
    std::cin.get();
    rwDriver.CloseHandle(hProcess);
    return 0;
}
