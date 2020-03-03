#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <inttypes.h>
#include <windows.h>

// list all PIDs and TIDs
#include <tlhelp32.h>
#include <Psapi.h>

#include "ntinfo.h"

std::vector<uint64_t> threadList(uint64_t pid);
uint64_t GetThreadStartAddress(HANDLE processHandle, HANDLE hThread);

int main(int argc, char** argv) {
	std::string pid = argv[1]; //
	uint64_t dwProcID;

	std::stringstream stringstream(pid);
	stringstream >> std::dec >> dwProcID;

	if (!dwProcID) {
		std::cerr << pid << " is not a valid process id (PID)" << std::endl;
		return EXIT_FAILURE;
	}

	HANDLE hProcHandle = NULL;
	
	printf("PID %d (0x%x)\n", dwProcID, dwProcID);
	std::cout << "Grabbing handle" << std::endl;
	hProcHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcID);

	if (hProcHandle == INVALID_HANDLE_VALUE || hProcHandle == NULL) {
		std::cerr << "Failed to open process -- invalid handle" << std::endl;
		std::cerr << "Error code: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}
	else {
		std::cout << "Success" << std::endl;
	}
	
	std::vector<uint64_t> threadId = threadList(dwProcID);
	uint64_t stackNum = 0;
	for (auto it = threadId.begin(); it != threadId.end(); ++it) {
		HANDLE threadHandle = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, *it);
		uint64_t threadStartAddress = GetThreadStartAddress(hProcHandle, threadHandle);
		printf("TID: 0x% " PRIx64 " = THREADSTACK%2d BASE ADDRESS: 0x%" PRIx64 "\n", *it, stackNum, threadStartAddress);
		stackNum++;
	}

	return EXIT_SUCCESS;
}

std::vector<uint64_t> threadList(uint64_t pid) {
	/* solution from http://stackoverflow.com/questions/1206878/enumerating-threads-in-windows */
	std::vector<uint64_t> vect = std::vector<uint64_t>();
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h == INVALID_HANDLE_VALUE)
		return vect;

	THREADENTRY32 te;
	te.dwSize = sizeof(te);
	if (Thread32First(h, &te)) {
		do {
			if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
				sizeof(te.th32OwnerProcessID)) {

				if (te.th32OwnerProcessID == pid) {
					printf("PID: %08d Thread ID: 0x%08x\n", te.th32OwnerProcessID, te.th32ThreadID);
					vect.push_back(te.th32ThreadID);
				}
			}
			te.dwSize = sizeof(te);
		} while (Thread32Next(h, &te));
	}

	return vect;
}

uint64_t GetThreadStartAddress(HANDLE processHandle, HANDLE hThread) {
	/* rewritten from https://github.com/cheat-engine/cheat-engine/blob/master/Cheat%20Engine/CEFuncProc.pas#L3080 */
	uint64_t used = 0, ret = 0;
	uint64_t stacktop = 0, result = 0;

	MODULEINFO mi;

	GetModuleInformation(processHandle, GetModuleHandle("kernel32.dll"), &mi, sizeof(mi));
	stacktop = (uint64_t)GetThreadStackTopAddress_x86(processHandle, hThread);

	/* The stub below has the same result as calling GetThreadStackTopAddress_x86() 
	change line 54 in ntinfo.cpp to return tbi.TebBaseAddress
	Then use this stub
	*/
	//LPCVOID tebBaseAddress = GetThreadStackTopAddress_x86(processHandle, hThread);
	//if (tebBaseAddress)
	//	ReadProcessMemory(processHandle, (LPCVOID)((DWORD)tebBaseAddress + 4), &stacktop, 4, NULL);

	/* rewritten from 32 bit stub (line3141)
	Result: fail -- can't get GetThreadContext() 
	*/
	//CONTEXT context;
	//LDT_ENTRY ldtentry;
	//GetModuleInformation(processHandle, LoadLibrary("kernel32.dll"), &mi, sizeof(mi));
	//
	//if (GetThreadContext(processHandle, &context)) {
	//	
	//	if (GetThreadSelectorEntry(hThread, context.SegFs, &ldtentry)) {
	//		ReadProcessMemory(processHandle,
	//			(LPCVOID)( (DWORD*)(ldtentry.BaseLow + ldtentry.HighWord.Bytes.BaseMid << ldtentry.HighWord.Bytes.BaseHi << 24) + 4),
	//			&stacktop,
	//			4,
	//			NULL);
	//	}
	//}

	CloseHandle(hThread);

	if (stacktop) {
		//find the stack entry pointing to the function that calls "ExitXXXXXThread"
		//Fun thing to note: It's the first entry that points to a address in kernel32

		uint64_t* buf32 = new uint64_t[8192];

		if (ReadProcessMemory(processHandle, (LPCVOID)(stacktop - 8192), buf32, 8192, NULL)) {
			for (int i = 8192 / 8 - 1; i >= 0; --i) {
				if (buf32[i] >= (uint64_t)mi.lpBaseOfDll && buf32[i] <= (uint64_t)mi.lpBaseOfDll + mi.SizeOfImage) {
					result = stacktop - 8192 + i * 8;
					break;
				}
			}
		}

		delete buf32;
	}

	return result;
}
