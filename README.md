# Win32_Offensive_Cheatsheet
Win32 and Kernel abusing techniques for pentesters

** Dev mode enabled, open to any help :)**

**Windows Binary Documentation**

- [PE structure](#pe-headers)
 - [PE Headers ](#pe-headers)
 - [Parsing PE ](#parsing-pe)
 - [Export Address Table (EAT) ](#export-address-table)
  - [Resolve function address ](#export-address-table)
    - [Using address (Obvious :D)](#export-address-table)
    - [Using ordinal number](#export-address-table)
    - [Using function name](#export-address-table)
 - [Import Address Table (IAT) ](#import-address-table)
   - [Parsing IAT ](#parsing-iat)
 - [Import Lookup Table (ILT) ](#import-lookup-table)



**Execute some binary**

- [Classic shellcode execution](https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/shellcode_samples/classic.cpp)
- [DLL execute ](#dll-execute)
- [Reflective DLL execution ⏳]()
- [RAW file to PE ⏳]()


**Code injection techniques**

- [CreateRemoteThread injection](#createremotethread-injection)
- [Process Hollowing ⏳]()
- [APC technique⏳]()
 - [Early Bird ⏳]()
- [Reflective DLL Injection ⏳]()
- [Dll injection](#dll-injection)
- [Process Doppelganging ⏳]()
- [Fibers ⏳]()
- [CreateThreadPoolWait ⏳]()
- [Thread Hijacking ⏳]()
- [MapView code injection ⏳]()
- [Module Stomping ⏳]()
- [Function Stomping ⏳]()
- [Complete PE injection in remote process ⏳]()

**Hooking techniques**
- [Inline hooking](#inline-hooking)
- [IAT hooking](#iat-hooking)


**RE Bypass techniques**

- [Call and Strings obfuscation](#call-and-strings-obfuscation)
- [Manual function resolve](#manual-function-resolve) 
- [Win32 API Hashing](#win32-api-hashing)


**EDR/Endpoint bypass**

- [Direct syscall ](#direct-syscall)
- [High level languages ](#high-level-languages)
- [Patch inline hooking](#patch-inline-hooking)
- [Patch ntdll hooking ⏳]()
- [Detect hooks ⏳]()
- [Patch ETW ⏳]()
- [Sandbox bypass](#sandbox-bypass)
- [Debugging Bypass](#debugging-bypass)
- [Patch Kernel callbacks ⏳]()
- [VirtualProtect technique](#virtualprotect-technique)
- [Fresh copy unhook ⏳]()
- [Hell's Gate ⏳]()
- [Heaven's Gate ⏳]()
- [PPID spoofing ⏳]()


**Driver Programming basics**

- [General concepts](#general-concepts)
- [Driver entry](#driver-entry)
- [IO (Input/Output) ⏳]()
- [Symlinks ⏳]()
- [Communicate with driver ⏳]()
- [Client code to kernel code ⏳]()
- [Driver signing (Microsoft) ⏳]()

**Offensive Driver Programming**

- [Process protection removing ⏳]()
- [Patch kernel callback (dev way) ⏳]()
- [Integrity and privileges levels ⏳]()
- [Enable SeDebug privilege ⏳]()

**Using Win32 API to increase OPSEC**

- [Persistence ⏳]()
 - [Scheduled Tasks ⏳]()
- [Command line spoofing ⏳]()

<br>
<br>

  
    
      
       

# Useful tools and Websites/Books


**Websites/Books**

:skull: https://www.ired.team/ (Awesome red team cheatsheet with great code injection notes)

:skull: https://undocumented.ntinternals.net/ (Undocumented NT functions)

:skull: https://docs.microsoft.com/en-us/windows/win32/api/ (Microsoft Official Doc)

:skull: Windows Kernel Programming - Pavel Yosifovich

:skull: https://research.checkpoint.com/ (Very interesting docs about evasion, anti-debug and so more)
<br>
<br>

## PE Headers

```
DOS_HEADER : First Header of PE, contains MS DOS message ("This programm cannot be run in DOS mode...."), MZ Header (Magic bytes to identify PE) and some stub content.
```

```
IMAGE_NT_HEADER : Contains PE file signature, File Header and Optionnal Header
```

```
SECTION_TABLE : Contains sections headers
```

```
SECTIONS : Not a header but useful to know : these are sections of the PE
``` 
<br>
Details : https://www.researchgate.net/figure/PE-structure-of-normal-executable_fig1_259647266

<br>


## Parsing PE

**Simple PE parsing to retrieve IAT and ILT absolute address : **

Obtain base address : GetModuleHandleA(NULL)

PIMAGE_DOS_HEADER = base address, dos header

PIMAGE_NT_HEADER = BaseAddress+PIMAGE_DOS_HEADER.e_lfnanew (RVA NT_HEADER)

IMAGE_DATA_DIRECTORY = OptionnalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] of PIMAGE_NT_HEADER

IMAGE_IMPORT_DIRECTORY = IMAGE_DATA_DIRECTORY.VirtualAddress (RVA of IMAGE_IMPORT_DIRECTORY)

IMAGE_IMPORT_DESCRIPTOR = BaseAddress + IMAGE_IMPORT_DIRECTORY.VirtualAddress (RVA du image_import_descriptor)

IAT absolute address : IMAGE_IMPORT_DESCRIPTOR.FirstThunk (RVA IAT) + BaseAddress

ILT absolute address : IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk (RVA ILT) + BaseAddress

<br>
<br>

## Export Address Table

- Often called "EAT"
- Resolve all functions that are exported by the PE
- Resolve DLLs

- Defined in IMAGE_EXPORT_DIRECTORY  structure : 
 ```
 public struct IMAGE_EXPORT_DIRECTORY
    {
        public UInt32 Characteristics;
        public UInt32 TimeDateStamp;
        public UInt16 MajorVersion;
        public UInt16 MinorVersion;
        public UInt32 Name;
        public UInt32 Base;
        public UInt32 NumberOfFunctions;
        public UInt32 NumberOfNames;
        public UInt32 AddressOfFunctions;     // RVA EAT and contains also RVA of exported functions
        public UInt32 AddressOfNames;     // Pointer array contains address of function names
        public UInt32 AddressOfNameOrdinals;  // Pointer array contains address of ordinal number of functions (index in AddressOfFunctions)
    }
  ```
  
 <br>
 <br>
 
 ## Resolve function address
 
 <br> 
 
 **Using function address**
 
 What do you wait ? Find this function !
 
 <br>
 
 **Using ordinal number**
 
 An ordinal number is an index position to the corresponding function address in AddressOfFunctions array. It can be used to retrieve the correct address of function, like below : 
 
 Let's try to find the corresponding address (Addr4) with given ordinal number 3.
 
 AddressOfFunctions : Addr1 Addr2 Addr3 Addr4 .... AddrN
 
 AdressOfNameOrdinals : 2 5 7 3 ... N
 
 The address we are looking for is on 3th position (from 0), and our ordinal number corresponds to the index of this address.
 
 <br>
 
 **Using function name**
 
 The Nth element in AddressOfNames array corresponding to the Nth element in AddressOfNameOrdinals array : using a given name, you can retrieve the corresponding ordinal number, and proceed to find the function address using this number.
 
<br>

## Import Address Table

- Often called "IAT"
- The PE loader doesn't know what address is corresponding to which function (again more with ASLR) : Let's call IAT to save us 
- Defined in IMAGE_IMPORT_DIRECTORY struct: 

```
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
  
    DWORD	Characteristics; 
    DWORD	OriginalFirstThunk;	//RVA to ILT
    DWORD	TimeDateStamp;	
    DWORD	ForwarderChain;
    DWORD	Name; //RVA of imported DLL name
    DWORD	FirstThunk; //RVA to IAT
} IMAGE_IMPORT_DESCRIPTOR,*PIMAGE_IMPORT_DESCRIPTOR;
```
<br>
<br>

## Parsing IAT

1) Obtain RVA of IAT 
2) Parse trough IMPORT_DESCRIPTOR structure : Name member is the RVA of the name of current DLL
3) To get the real DLL name : find it in ILT (originalFirstThunk+BaseAddress)
4) To get exported functions of current DLL : PIMAGE_IMPORT_BY_NAME function_name->Name = ImageBase+AdressOfData

Detailed code example here : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/miscellaneous/iat_parser.cpp
<br>
<br>

## Import Lookup Table

Every DLLs imported by PE has its own ILT.
<br>
```
Absolute address of ILT = BaseAddress + OriginalFirstThunk (IAT)
```

Contains all functions name that are in imported DLL.
<br>
<br>

## DLL Execute

This technique had some good successful bypass rates few years ago; however, because of increasing number of EDR and other endpoint solutions, writing on disk should as possible be avoided.

Sample : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/shellcode_samples/dll_classic.cpp
<br>
<br>

##

## Direct Syscall

Most EDR products will hook win32 api calls in user mode (PatchGuard strongly decrease kernel hooks availability). To avoid these hooks, you can directly call Nt() equivalent to your api functions.

**Set up asm :**
<br>

```
.code
	SysNtCreateFile proc
			mov r10, rcx //syscall convention
			mov eax, 55h //syscall number : in this case it's NtCreateFile
			syscall //call nt function
			ret
	SysNtCreateFile endp
end
```

Find the right syscall number at this table : https://j00ru.vexillium.org/syscalls/nt/64/
<br>

**Provide a winapi template :**
<br>

```
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
<br>

**Resolve Nt address :**
<br>

```
FARPROC addr = GetProcAddress(LoadLibraryA("ntdll"), "NtCreateFile");
```
<br>

**Use it ! (code from : https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs)** (SysNtCreateFile instead of NtCreateFile)
<br>
```
#include "pch.h"
#include <Windows.h>
#include "winternl.h"
#pragma comment(lib, "ntdll")

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

int main()
{
	FARPROC addr = GetProcAddress(LoadLibraryA("ntdll"), "NtCreateFile");
	
	OBJECT_ATTRIBUTES oa;
	HANDLE fileHandle = NULL;
	NTSTATUS status = NULL;
	UNICODE_STRING fileName;
	IO_STATUS_BLOCK osb;

	RtlInitUnicodeString(&fileName, (PCWSTR)L"\\??\\c:\\temp\\test.txt");
	ZeroMemory(&osb, sizeof(IO_STATUS_BLOCK));
	InitializeObjectAttributes(&oa, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	SysNtCreateFile(
		&fileHandle, 
		FILE_GENERIC_WRITE, 
		&oa, 
		&osb, 
		0, 
		FILE_ATTRIBUTE_NORMAL, 
		FILE_SHARE_WRITE, 
		FILE_OVERWRITE_IF, 
		FILE_SYNCHRONOUS_IO_NONALERT, 
		NULL, 
		0);

	return 0;
}
```
<br>
<br>

## High Level Languages

C++/C are often more flagged by AV/EDR products than high level equivalent languages : use Go, Rust or other language to craft your best templates !

<br>
<br>

## DLL Injection

You can inject some code stored in a dll in a remote process. Unfortunately, EDRs product will likely catch it easily, especially if malicious dll touch the disk.

Code sample : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/shellcode_samples/dll_injection.cpp

<br>
<br>

## Sandbox Bypass

Sandbox are quite used by AV/EDRs to test some API calls and other part of code before to really execute your programm. There are several techniques to avoid this tool, here are some of them below : 
<br>

- Wait. Seriously. Such function as Sleep() or time.sleep() or equivalent will do the job, for some seconds before to execute the real shellcode.

- Try to allocate lot of memory (malloc), like 100000000 bytes.

- Try to detect if you are actually in a sandbox (VM) environnement : test for open process,files and others suspicious things.

- Try to resolve a fake (not working) URL : many AVs products will respond with fake page.

- Use strange and rarely used Api calls, like VirtualAllocExNuma(): most sandbox cannot emulate this type of call.

<br>

```
IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
```

<br>
<br>

## Debugging Bypass

Not a real AV evasion technique, but still useful to avoid being reversed too easily by RE engineers. There are so many ways to detect or make debuggers crazy, but here are some of them below : 

<br>

**Flags way**

<br>

You can use ```IsDebuggerPresent()``` (Win32) or direct call ```NtQueryInformationProcess()``` (not so very documented) to check for debug flags.

**Handles way**

<br>

Try to close invalid (missing) handles with CloseHandle() API.
The debugger will try to catch the exception, which can be easily detected : 

<br>

```
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

<br>

**ASM way**

Try to make an INT 3 call (ASM) : it's an equivalent to a software breakpoint, which will trigger a debugger.

<br>

There are so many other ways to detect any debugger, a lot of them are compiled at : https://anti-debug.checkpoint.com/

<br>
<br>

## CreateRemoteThread injection

Simply write your shellcode in previously allocated memory space inside the target process. (Not OPSEC)

Code sample : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/shellcode_samples/create_thread_injection.cpp

<br>
<br>

 ## Inline Hooking
 
 Inline hooking is the most basic way to hook a function : it simply consists to redirect the API call to your own function (jump)
 
 <br>
 
 Code sample : https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/hooking/inline.cpp (from https://www.ired.team/offensive-security/code-injection-process-injection/how-to-hook-windows-api-using-c++)

<br>
<br>

## Patch Inline Hooking

Simply (re) hook your hooked functions by apply the right function call:)
https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/hooking/inline.cpp



## Driver Basics

<br>

## General Concepts

Driver are used to execute code in kernel mode rather than in user mode.
It is a powerful technique to bypass all usermode hooks and monitoring which were set by AV/EDRs.

It can be also used to bypass kernel callbacks and other kernel monitoring.

The code of any driver must be verified (any warning should be treated as an error) to ensure it will be crash-free (You don't want to cause BSOD during pentest, right ?).

Few years ago, Microsoft decided to ban unsigned drivers from his operating system : you must disable it before to load your own driver, or use any vulnerability (like https://github.com/hmnthabit/CVE-2018-19320-LPE) to disable driver signing.

In a real pentest, you must find any vulnerable driver and profit:)

<br>
<br>

## Win32 API Hashing

You can hide your API function calls by hash them with some hash algorithm (djb2 is the most used) : be careful of hash collision that are possible with some special funcs.

Then combine this technique with a direct address resolving in EAT, and let reversers cry:)

<br>
<br>

## Call and strings obfuscation

There are several techniques you can use to hide your calls to win32 api, here are some of them : 

- Use char[] array to splice your function/dll names into multiple chars

<br>

```
char sWrite[] = {'W','r','i','t','e','P','r','o','c','e','s','s','M','e','m','o','r','y',0x0}; //don't forget the null byte
```
<br>

You can even combine this trick with some ASCII char code convert.

<br>
<br>

## Manual Function resolve

You can manually resolve a pointer to any function of kernel32, ntdll and so more.

First declare the template of your function, based on the real function header : 

<br>

```
typedef HANDLE(WINAPI* myOpenProcess)(DWORD,BOOL,DWORD); //if you work directly with ntdll, use NTAPI*

```

<br>

Then resolve a pointer to the function :

<br>

```
myOpenProcess op_proc = (myOpenProcess*)GetProcAddress(LoadLibraryA("ndll.dll"),"OpenProcess"));
op_proc(PROCESS_ALL_ACCESS,NULL,12345);
```

<br>

Don't hesitate to combine this technique with some strings obfuscation to avoid passing the real func name in plaintext.

<br>
<br>

## VirtualProtect technique

By using some tricks with VirtualProtect() you can easily avoid been flagged in-memory : change between PAGE_EXECUTE_READWRITE and PAGE_READWRITE (less suspicious) to avoid triggering your favorite AV.

<br>
<br>

## Driver Entry

Driver entry proc is defined as below : 

<br>

```
#include <ntddk.h>

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	return STATUS_SUCCESS;
}
```

<br>

It is very important to use UNREFERENCED_PARAMETER() macro on two parameters (DriverObject and RegistryPath), unless they are referenced by adding some code later.

<br>


```
UNREFERENCED_PARAMETER(DriverObject);
UNREFERENCED_PARAMETER(RegistryPath);
```

<br>
<br>

## IAT Hooking

By modifying the corresponding function address to a pointer on your own function, you can make the programm executing your own code.

It can be done by following several steps : 

- Find the relative address of IAT
- Parse the IAT to find the function you want to hook
- Replace this function address ("patch") with the adress of your function
- Enjoy

<br>

Code sample : 






