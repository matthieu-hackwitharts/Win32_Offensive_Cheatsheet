# Win32_Offensive_Cheatsheet
Win32 and Kernel abusing techniques for pentesters



**Windows Binary Documentation**

- [PE structure⏳](#pe-headers)
 - [PE Headers ⏳](#pe-headers)
 - [Export Address Table (EAT) ⏳](#export-address-table)
  - [Resolve function address ⏳](#export-address-table)
    - [Using address (Obvious :D)](#export-address-table)
    - [Using ordinal number](#export-address-table)
    - [Using function name](#export-address-table)
 - [Import Address Table (IAT) ⏳](#import-address-table)
 - [Import Lookup Table (ILT) ⏳]()



**Execute some binary**

- [Classic shellcode execution⏳]()
- [DLL execute ⏳]()
- [Reflective DLL execution ⏳]()
- [RAW file to PE ⏳]()


**Code injection techniques**

- [CreateRemoteThread injection ⏳]()
- [Process Hollowing ⏳]()
- [APC technique⏳]()
 - [Early Bird ⏳]()
- [Reflective DLL Injection ⏳]()
- [Dll injection ⏳]()
- [Process Doppelganging ⏳]()
- [Fibers ⏳]()
- [CreateThreadPoolWait ⏳]()
- [Thread Hijacking ⏳]()
- [MapView code injection ⏳]()
- [Module Stomping ⏳]()
- [Function Stomping ⏳]()
- [Complete PE injection in remote process ⏳]()

**Hooking techniques**
- [Inline hooking ⏳]()
- [IAT hooking ⏳]()


**AV Bypass techniques (Signature based)**

- [Call and Strings obfuscation ⏳]()
- [Manual function resolves ⏳]() 
- [Win32 API Hashing ⏳]()


**EDR/Endpoint bypass**

- [Direct syscall ⏳]()
- [High level languages ⏳]()
- [Patch inline hooking ⏳]()
- [Patch ntdll hooking ⏳]()
- [Detect hooks ⏳]()
- [Patch ETW ⏳]()
- [Sandbox bypass ⏳]()
- [Debugging Bypass ⏳]()
- [Patch Kernel callbacks ⏳]()
- [VirtualProtect techniques ⏳]()
- [Fresh copy unhook ⏳]()
- [Hell's Gate ⏳]()
- [Heaven's Gate ⏳]()
- [PPID spoofing ⏳]()


**Driver Programming basics**

- [General concepts ⏳]()
- [Driver entry ⏳]()
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
    DWORD	OriginalFirstThunk;	//
    DWORD	TimeDateStamp;	
    DWORD	ForwarderChain;
    DWORD	Name;
    DWORD	FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR,*PIMAGE_IMPORT_DESCRIPTOR;
```

