// ref https://stackoverflow.com/questions/10487165/is-it-possible-to-call-a-non-exported-function-that-resides-in-an-exe
// file: unexported.c
//
// compile with Open Watcom C/C++: wcl386 /q /wx /we /s unexported.c
//   (Note: "/s" is needed to avoid stack check calls from the "unexported"
//    functions, these calls are through a pointer, and it'll be
//    uninitialized in our case.)
//
// compile with MinGW gcc 4.6.2: gcc unexported.c -o unexported.exe
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>

#ifndef C_ASSERT
#define C_ASSERT(expr) extern char CAssertExtern[(expr)?1:-1]
#endif

// Compile as a 32-bit app only.
C_ASSERT(sizeof(void*) * CHAR_BIT == 32);

#define EXC_CODE_AND_NAME(X) { X, #X }

const struct
{
  DWORD Code;
  PCSTR Name;
} ExcCodesAndNames[] =
{
  EXC_CODE_AND_NAME(EXCEPTION_ACCESS_VIOLATION),
  EXC_CODE_AND_NAME(EXCEPTION_ARRAY_BOUNDS_EXCEEDED),
  EXC_CODE_AND_NAME(EXCEPTION_BREAKPOINT),
  EXC_CODE_AND_NAME(EXCEPTION_DATATYPE_MISALIGNMENT),
  EXC_CODE_AND_NAME(EXCEPTION_FLT_DENORMAL_OPERAND),
  EXC_CODE_AND_NAME(EXCEPTION_FLT_DIVIDE_BY_ZERO),
  EXC_CODE_AND_NAME(EXCEPTION_FLT_INEXACT_RESULT),
  EXC_CODE_AND_NAME(EXCEPTION_FLT_INVALID_OPERATION),
  EXC_CODE_AND_NAME(EXCEPTION_FLT_OVERFLOW),
  EXC_CODE_AND_NAME(EXCEPTION_FLT_STACK_CHECK),
  EXC_CODE_AND_NAME(EXCEPTION_FLT_UNDERFLOW),
  EXC_CODE_AND_NAME(EXCEPTION_ILLEGAL_INSTRUCTION),
  EXC_CODE_AND_NAME(EXCEPTION_IN_PAGE_ERROR),
  EXC_CODE_AND_NAME(EXCEPTION_INT_DIVIDE_BY_ZERO),
  EXC_CODE_AND_NAME(EXCEPTION_INT_OVERFLOW),
  EXC_CODE_AND_NAME(EXCEPTION_INVALID_DISPOSITION),
  EXC_CODE_AND_NAME(EXCEPTION_NONCONTINUABLE_EXCEPTION),
  EXC_CODE_AND_NAME(EXCEPTION_PRIV_INSTRUCTION),
  EXC_CODE_AND_NAME(EXCEPTION_SINGLE_STEP),
  EXC_CODE_AND_NAME(EXCEPTION_STACK_OVERFLOW),
  EXC_CODE_AND_NAME(EXCEPTION_GUARD_PAGE),
  EXC_CODE_AND_NAME(DBG_CONTROL_C),
  { 0xE06D7363, "C++ EH exception" }
};

PCSTR GetExceptionName(DWORD code)
{
  DWORD i;

  for (i = 0; i < sizeof(ExcCodesAndNames) / sizeof(ExcCodesAndNames[0]); i++)
  {
    if (ExcCodesAndNames[i].Code == code)
    {
      return ExcCodesAndNames[i].Name;
    }
  }

  return "?";
}

typedef enum tCallConv
{
  CallConvCdecl,    // Params on stack; caller removes params
  CallConvStdCall,  // Params on stack; callee removes params
  CallConvFastCall  // Params in ECX, EDX and on stack; callee removes params
} tCallConv;

DWORD Execute32bitFunctionFromExe(PCSTR ExeName,
                                  int FunctionAddressIsRelative,
                                  DWORD FunctionAddress,
                                  tCallConv CallConvention,
                                  DWORD CodeDataStackSize,
                                  ULONG64* ResultEdxEax,
                                  DWORD DwordParamsCount,
                                  .../* DWORD params */)
{
  STARTUPINFO startupInfo;
  PROCESS_INFORMATION processInfo;
  DWORD dwContinueStatus = DBG_CONTINUE; // exception continuation
  DEBUG_EVENT dbgEvt;
  UCHAR* procMem = NULL;
  DWORD breakPointCount = 0;
  DWORD err = ERROR_SUCCESS;
  DWORD ecxEdxParams[2] = { 0, 0 };
  DWORD imageBase = 0;
  CONTEXT ctx;
  va_list ap;

  va_start(ap, DwordParamsCount);

  *ResultEdxEax = 0;

  memset(&startupInfo, 0, sizeof(startupInfo));
  startupInfo.cb = sizeof(startupInfo);
  memset(&processInfo, 0, sizeof(processInfo));

  if (!CreateProcess(
    NULL,
    (LPSTR)ExeName,
    NULL,
    NULL,
    FALSE,
    DEBUG_ONLY_THIS_PROCESS, // DEBUG_PROCESS,
    NULL,
    NULL,
    &startupInfo,
    &processInfo))
  {
    printf("CreateProcess() failed with error 0x%08X\n",
           err = GetLastError());
    goto Cleanup;
  }

  printf("Process 0x%08X (0x%08X) \"%s\" created,\n"
         "  Thread 0x%08X (0x%08X) created\n",
         processInfo.dwProcessId,
         processInfo.hProcess,
         ExeName,
         processInfo.dwThreadId,
         processInfo.hThread);

  procMem = (UCHAR *)VirtualAllocEx(
    processInfo.hProcess,
    NULL,
    CodeDataStackSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE);

  if (procMem == NULL)
  {
    printf("VirtualAllocEx() failed with error 0x%08X\n",
           err = GetLastError());
    goto Cleanup;
  }

  printf("Allocated RWX memory in process 0x%08X (0x%08X) "
         "at address 0x%08X\n",
         processInfo.dwProcessId,
         processInfo.hProcess,
         procMem);

  while (dwContinueStatus)
  {
    // Wait for a debugging event to occur. The second parameter indicates
    // that the function does not return until a debugging event occurs.
    if (!WaitForDebugEvent(&dbgEvt, INFINITE))
    {
      printf("WaitForDebugEvent() failed with error 0x%08X\n",
             err = GetLastError());
      goto Cleanup;
    }

    // Process the debugging event code.
    switch (dbgEvt.dwDebugEventCode)
    {
    case EXCEPTION_DEBUG_EVENT:
    // Process the exception code. When handling
    // exceptions, remember to set the continuation
    // status parameter (dwContinueStatus). This value
    // is used by the ContinueDebugEvent function.

      printf("%s (%s) Exception in process 0x%08X, thread 0x%08X\n"
             "  Exc. Code = 0x%08X (%s), Instr. Address = 0x%08X",
             dbgEvt.u.Exception.dwFirstChance ?
               "First Chance" : "Last Chance",
             dbgEvt.u.Exception.ExceptionRecord.ExceptionFlags ?
               "non-continuable" : "continuable",
             dbgEvt.dwProcessId,
             dbgEvt.dwThreadId,
             dbgEvt.u.Exception.ExceptionRecord.ExceptionCode,
             GetExceptionName(dbgEvt.u.Exception.ExceptionRecord.ExceptionCode),
             dbgEvt.u.Exception.ExceptionRecord.ExceptionAddress);

      if (dbgEvt.u.Exception.ExceptionRecord.ExceptionCode ==
          EXCEPTION_ACCESS_VIOLATION)
      {
        ULONG_PTR* info = dbgEvt.u.Exception.ExceptionRecord.ExceptionInformation;
        printf(",\n  Access Address = 0x%08X, Access = 0x%08X (%s)",
               (DWORD)info[1],
               (DWORD)info[0],
               (info[0] == 0) ?
                 "read" : ((info[0] == 1) ? "write" : "execute")); // 8 = DEP
      }

      printf("\n");

      // Get the thread context (register state).
      // We'll need to either display it (in case of unexpected exceptions) or
      // modify it (to execute our code) or read it (to get the results of
      // execution).
      memset(&ctx, 0, sizeof(ctx));
      ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
      if (!GetThreadContext(processInfo.hThread, &ctx))
      {
        printf("GetThreadContext() failed with error 0x%08X\n",
               err = GetLastError());
        goto Cleanup;
      }

#if 0
      printf("  EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X EFLAGS=0x%08X\n"
             "  ESI=0x%08X EDI=0x%08X EBP=0x%08X ESP=0x%08X EIP=0x%08X\n",
             ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx, ctx.EFlags, 
             ctx.Esi, ctx.Edi, ctx.Ebp, ctx.Esp, ctx.Eip);
#endif

      if (dbgEvt.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT &&
          breakPointCount == 0)
      {
        // Update the context so our code can be executed
        DWORD mem, i, data;
        SIZE_T numberOfBytesCopied;

        mem = (DWORD)procMem + CodeDataStackSize;

        // Child process memory layout (inside the procMem[] buffer):
        //
        //    higher
        //  addresses
        //      .
        //      .     UD2 instruction (causes #UD, indicator of successful
        //      .     completion of FunctionAddress())
        //      .
        //      .     last on-stack parameter for FunctionAddress()
        //      .     ...
        //      .     first on-stack parameter for FunctionAddress()
        //      .
        //      .     address of UD2 instruction (as if "call FunctionAddress"
        //      .     executed just before it and is going to return to UD2)
        //      .     (ESP will point here)
        //      .
        //      .     FunctionAddress()'s stack
        //      .
        //    lower
        //  addresses

        mem -= 2;
        data = 0x0B0F; // 0x0F, 0x0B = UD2 instruction
        if (!WriteProcessMemory(processInfo.hProcess,
                                (PVOID)mem,
                                &data,
                                2,
                                &numberOfBytesCopied))
        {
ErrWriteMem1:
          printf("WriteProcessMemory() failed with error 0x%08X\n",
                 err = GetLastError());
          goto Cleanup;
        }
        else if (numberOfBytesCopied != 2)
        {
ErrWriteMem2:
          printf("WriteProcessMemory() failed with error 0x%08X\n",
                 err = ERROR_BAD_LENGTH);
          goto Cleanup;
        }

        // Copy function parameters.

        mem &= 0xFFFFFFFC; // align the address for the stack

        for (i = 0; i < DwordParamsCount; i++)
        {
          if (CallConvention == CallConvFastCall && i < 2)
          {
            ecxEdxParams[i] = va_arg(ap, DWORD);
          }
          else
          {
            data = va_arg(ap, DWORD);
            if (!WriteProcessMemory(processInfo.hProcess,
                                    (DWORD*)mem - DwordParamsCount + i,
                                    &data,
                                    sizeof(data),
                                    &numberOfBytesCopied))
            {
              goto ErrWriteMem1;
            }
            else if (numberOfBytesCopied != sizeof(data))
            {
              goto ErrWriteMem2;
            }
          }
        }

        // Adjust what will become ESP according to the number of on-stack parameters.
        for (i = 0; i < DwordParamsCount; i++)
        {
          if (CallConvention != CallConvFastCall || i >= 2)
          {
            mem -= 4;
          }
        }

        // Store the function return address.
        mem -= 4;
        data = (DWORD)procMem + CodeDataStackSize - 2; // address of UD2
        if (!WriteProcessMemory(processInfo.hProcess,
                                (PVOID)mem,
                                &data,
                                sizeof(data),
                                &numberOfBytesCopied))
        {
          goto ErrWriteMem1;
        }
        else if (numberOfBytesCopied != sizeof(data))
        {
          goto ErrWriteMem2;
        }

        // Last-minute preparations for execution...
        // Set up the registers (ECX, EDX, EFLAGS, EIP, ESP).

        if (CallConvention == CallConvFastCall)
        {
          if (DwordParamsCount >= 1) ctx.Ecx = ecxEdxParams[0];
          if (DwordParamsCount >= 2) ctx.Edx = ecxEdxParams[1];
        }

        ctx.EFlags &= ~(1 << 10); // clear DF for string instructions
        ctx.Eip = FunctionAddress + imageBase * !!FunctionAddressIsRelative;
        ctx.Esp = mem;

        if (!SetThreadContext(processInfo.hThread, &ctx))
        {
          printf("SetThreadContext() failed with error 0x%08X\n",
                 err = GetLastError());
          goto Cleanup;
        }

        printf("Copied code/data to the process\n");

#if 0
        for (i = esp; i < (DWORD)procMem + CodeDataStackSize; i++)
        {
          data = 0;
          ReadProcessMemory(processInfo.hProcess,
                            (void*)i,
                            &data,
                            1,
                            &numberOfBytesCopied);
          printf("E[SI]P = 0x%08X: 0x%02X\n", i, data);
        }
#endif

        breakPointCount++;
        dwContinueStatus = DBG_CONTINUE; // continue execution of our code
      }
      else if (dbgEvt.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION &&
               breakPointCount == 1 &&
               ctx.Eip == (DWORD)procMem + CodeDataStackSize - 2/*UD2 size*/)
      {
        // The code has finished execution as expected.
        // Collect the results.

        *ResultEdxEax = ((ULONG64)ctx.Edx << 32) | ctx.Eax;

        printf("Copied code/data from the process\n");

        dwContinueStatus = 0; // stop debugging
      }
      else
      {
        // Unexpected event. Do not continue execution.

        printf("  EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X EFLAGS=0x%08X\n"
               "  ESI=0x%08X EDI=0x%08X EBP=0x%08X ESP=0x%08X EIP=0x%08X\n",
               ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx, ctx.EFlags, 
               ctx.Esi, ctx.Edi, ctx.Ebp, ctx.Esp, ctx.Eip);

        err = dbgEvt.u.Exception.ExceptionRecord.ExceptionCode;
        goto Cleanup;
      }
      break; // case EXCEPTION_DEBUG_EVENT:

    case CREATE_PROCESS_DEBUG_EVENT:
    // As needed, examine or change the registers of the
    // process's initial thread with the GetThreadContext and
    // SetThreadContext functions; read from and write to the
    // process's virtual memory with the ReadProcessMemory and
    // WriteProcessMemory functions; and suspend and resume
    // thread execution with the SuspendThread and ResumeThread
    // functions. Be sure to close the handle to the process image
    // file with CloseHandle.
      printf("Process 0x%08X (0x%08X) "
             "created, base = 0x%08X,\n"
             "  Thread 0x%08X (0x%08X) created, start = 0x%08X\n",
             dbgEvt.dwProcessId,
             dbgEvt.u.CreateProcessInfo.hProcess,
             dbgEvt.u.CreateProcessInfo.lpBaseOfImage,
             dbgEvt.dwThreadId,
             dbgEvt.u.CreateProcessInfo.hThread,
             dbgEvt.u.CreateProcessInfo.lpStartAddress);
      // Found image base!
      imageBase = (DWORD)dbgEvt.u.CreateProcessInfo.lpBaseOfImage;
      dwContinueStatus = DBG_CONTINUE;
      break;

    case EXIT_PROCESS_DEBUG_EVENT:
    // Display the process's exit code.
      printf("Process 0x%08X exited, exit code = 0x%08X\n",
             dbgEvt.dwProcessId,
             dbgEvt.u.ExitProcess.dwExitCode);
      // Unexpected event. Do not continue execution.
      err = ERROR_PROC_NOT_FOUND;
      goto Cleanup;

    case CREATE_THREAD_DEBUG_EVENT:
    case EXIT_THREAD_DEBUG_EVENT:
    case LOAD_DLL_DEBUG_EVENT:
    case UNLOAD_DLL_DEBUG_EVENT:
    case OUTPUT_DEBUG_STRING_EVENT:
      dwContinueStatus = DBG_CONTINUE;
      break;

    case RIP_EVENT:
      printf("RIP: Error = 0x%08X, Type = 0x%08X\n",
             dbgEvt.u.RipInfo.dwError,
             dbgEvt.u.RipInfo.dwType);
      // Unexpected event. Do not continue execution.
      err = dbgEvt.u.RipInfo.dwError;
      goto Cleanup;
    } // end of switch (dbgEvt.dwDebugEventCode)

    // Resume executing the thread that reported the debugging event.
    if (dwContinueStatus)
    {
      if (!ContinueDebugEvent(dbgEvt.dwProcessId,
                              dbgEvt.dwThreadId,
                              dwContinueStatus))
      {
        printf("ContinueDebugEvent() failed with error 0x%08X\n",
               err = GetLastError());
        goto Cleanup;
      }
    }
  } // end of while (dwContinueStatus)

  err = ERROR_SUCCESS;

Cleanup:

  if (processInfo.hProcess != NULL)
  {
    if (procMem != NULL)
    {
      VirtualFreeEx(processInfo.hProcess, procMem, 0, MEM_RELEASE);
    }
    TerminateProcess(processInfo.hProcess, 0);
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);
  }

  va_end(ap);

  return err;
}

int __cdecl FunctionCdecl(int x, int y, int z)
{
  return x + y + z;
}

int __stdcall FunctionStdCall(int x, int y, int z)
{
  return x * y * z;
}

ULONG64 __fastcall FunctionFastCall(DWORD x, DWORD y, DWORD z)
{
  return (ULONG64)x * y + z;
}

int main(int argc, char** argv)
{
  DWORD err;
  ULONG64 resultEdxEax;

  err = Execute32bitFunctionFromExe(argv[0]/*ExeName*/,
                                    1/*FunctionAddressIsRelative*/,
                                    (DWORD)&FunctionCdecl -
                                      (DWORD)GetModuleHandle(NULL),
                                    CallConvCdecl,
                                    4096/*CodeDataStackSize*/,
                                    &resultEdxEax,
                                    3/*DwordParamsCount*/,
                                    2, 3, 4);
  if (err == ERROR_SUCCESS)
    printf("2 + 3 + 4 = %d\n", (int)resultEdxEax);

  err = Execute32bitFunctionFromExe(argv[0]/*ExeName*/,
                                    1/*FunctionAddressIsRelative*/,
                                    (DWORD)&FunctionStdCall -
                                      (DWORD)GetModuleHandle(NULL),
                                    CallConvStdCall,
                                    4096/*CodeDataStackSize*/,
                                    &resultEdxEax,
                                    3/*DwordParamsCount*/,
                                    -2, 3, 4);
  if (err == ERROR_SUCCESS)
    printf("-2 * 3 * 4 = %d\n", (int)resultEdxEax);

  err = Execute32bitFunctionFromExe(argv[0]/*ExeName*/,
                                    1/*FunctionAddressIsRelative*/,
                                    (DWORD)&FunctionFastCall -
                                      (DWORD)GetModuleHandle(NULL),
                                    CallConvFastCall,
                                    4096/*CodeDataStackSize*/,
                                    &resultEdxEax,
                                    3/*DwordParamsCount*/,
                                    -1, -1, -1);
  if (err == ERROR_SUCCESS)
    printf("0xFFFFFFFF * 0xFFFFFFFF + 0xFFFFFFFF = 0x%llX\n",
           (unsigned long long)resultEdxEax);

  return 0;
}
