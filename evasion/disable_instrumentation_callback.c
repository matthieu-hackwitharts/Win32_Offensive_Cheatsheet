#include <stdio.h>
#include <windows.h>

#define ProcessInstrumentationCallback  40

typedef LONG(WINAPI* NT_SET_INFORMATION_PROCESS)(
	_In_ HANDLE hProcess,
	_In_ PROCESS_INFORMATION_CLASS ProcessInformationClass,
	_In_reads_bytes_(ProcessInformationSize) LPVOID ProcessInformation,
	_In_ DWORD ProcessInformationSize
);

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, *PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

int main() 
{
  NT_SET_INFORMATION_PROCESS NtSetInformationProcess = ( NT_SET_INFORMATION_PROCESS )GetProcAddress( GetModuleHandle( "ntdll.dll" ), "NtSetInformationProcess" );

  PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION InstrumentationCallbackInfo;

  InstrumentationCallbackInfo.Version  = 0x0;
  InstrumentationCallbackInfo.Reserved = 0x0;
  InstrumentationCallbackInfo.Callback = NULL;

  NtSetInformationProcess( hProcess, ProcessInstrumentationCallback, &InstrumentationCallbackInfo, sizeof( InstrumentationCallbackInfo ) );
  
  return 0;
}
