/*
	Author : Zuk0
	
	DLL Code written in C++ to hook Import Address Table (IAT)

	Compiling Instruction
	> cl.exe /D_USRDLL /D_WINDLL main.cpp /link /DLL /OUT:hook.dll
*/

#include<windows.h>
#include<stdio.h>
#include<stdlib.h>

#pragma comment(lib, "user32.lib")

int (WINAPI * pMessageBox) (HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) = MessageBox;

/*
	Defining my Malicious function to hook 
*/

int MaliciousFunction(HWND hWnde, LPSTR lpText, LPCTSTR lpCaption, UINT uType) {

	return pMessageBox(NULL, "Hello From Zuk0", "MESSAGE", MB_OK);
}


/*
	Creating a custom function to get the address of Import Descriptor Table.
	It takes base address of the image and returns pointer to IMAGE_IMPORT_DESCRIPTOR
*/

PIMAGE_IMPORT_DESCRIPTOR GetBaseToImportDirectory(HANDLE baseAddress) {

	// IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER) baseAddress;

#ifdef _M_X64
	IMAGE_NT_HEADERS64 *ntHeader = (IMAGE_NT_HEADERS64 *) ((BYTE *) baseAddress + *((DWORD *) ((BYTE *) baseAddress + 0x3c)));
	IMAGE_OPTIONAL_HEADER64 *optionalHeader = (IMAGE_OPTIONAL_HEADER64 *) &ntHeader->OptionalHeader;
#else
	IMAGE_NT_HEADER32 *ntHeader = (IMAGE_NT_HEADER32 *) (((BYTE *) baseAddress) + *((DWORD *) ((BYTE *) baseAddress + 0x3c)));
	IMAGE_OPTIONAL_HEADER32 *optionalHeader = (IMAGE_OPTIONAL_HEADER32 *) &ntHeader->OptionalHeader;
#endif

	IMAGE_DATA_DIRECTORY *dateDirectory = &optionalHeader->DataDirectory[1];

	return (PIMAGE_IMPORT_DESCRIPTOR) (((BYTE *) baseAddress) + dateDirectory->VirtualAddress);
}

/*
	Our Hooking Function which will take the module name,  function name and hook function (our malicious function).
*/

int HookFunction(LPSTR moduleName, LPSTR procName, PROC hookFunction) {
	
	BOOL found = FALSE;

	HANDLE baseAddress = GetModuleHandle(NULL);

/*
	typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	    union {
	        DWORD   Characteristics;
	        DWORD   OriginalFirstThunk;
	    } DUMMYUNIONNAME;
	    DWORD   TimeDateStamp;
	    DWORD   ForwarderChain;
	    DWORD   Name;
	    DWORD   FirstThunk;
	} IMAGE_IMPORT_DESCRIPTOR;
	typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
*/


//	Getting the address to import descriptor table
	IMAGE_IMPORT_DESCRIPTOR *importTable = GetBaseToImportDirectory(baseAddress);

	int index = 0;

/*
	Traversing the Import Descriptor Table and checking the name of loaded module.
*/

	while(importTable[index].Name) {
		// printf("[+] %s\n", ((BYTE *) baseAddress + importTable[index].Name));

		if(!_stricmp(moduleName, (char *) ((BYTE *) baseAddress + importTable[index].Name))) {
			found = TRUE;
			break;
		}
		index++;
	}

	if(!found) {
		return 0;
	}

/*
	After finding the correct module. It goes ahead and get the address of required function address
*/

	PROC originalProcAddress = GetProcAddress(GetModuleHandle(moduleName), procName);

	IMAGE_THUNK_DATA *thunkData = (IMAGE_THUNK_DATA *) ((BYTE *) baseAddress + importTable[index].FirstThunk);

/*
	Traversing the IAT to find the address containing the address of required function.
*/

	while(thunkData->u1.Function) {

		PROC *currentProcAddress = (PROC *) &thunkData->u1.Function;

		if(originalProcAddress == *currentProcAddress) {

/*
		After finding the entry containing the address of required function we will replace it with the
		address of out malicious function.
*/

			DWORD oldSecurity = 0;

/*
		Changing permission of the memory region in order to overwrite the IAT
*/

			VirtualProtect(currentProcAddress, 4096, PAGE_READWRITE, &oldSecurity);

/*
		Replacing the IAT entry with our malicious function.
*/

			*currentProcAddress = (PROC) hookFunction;

/*
		Changing permission of memory back to original
*/

			VirtualProtect(currentProcAddress, 4096, oldSecurity, &oldSecurity);
			return TRUE;
		}

		thunkData++;
	}


	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    // Perform actions based on the reason for calling.
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
         // Initialize once for each new process.
         // Return FALSE to fail DLL load.
        	HookFunction("user32.dll", "MessageBoxA", (PROC) MaliciousFunction);
		// MessageBox(NULL, "HelloWorld", "FromZuk0", MB_OK);
            break;

        case DLL_THREAD_ATTACH:
         // Do thread-specific initialization.
            break;

        case DLL_THREAD_DETACH:
         // Do thread-specific cleanup.
            break;

        case DLL_PROCESS_DETACH:
         // Perform any necessary cleanup.
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}