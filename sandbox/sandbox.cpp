#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>


static
BOOL accessible(LPCWSTR path)
{
  return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}


static
const char* user_accessible()
{
  WCHAR path[MAX_PATH + 1];

  if (ExpandEnvironmentStringsW(L"%TEMP%", path, sizeof(path) / sizeof(path[0]) - sizeof(path[0])) == 0)
    abort();

  return accessible(path) ? "true" : "false";
}


static
const char* system_accessible()
{
  return accessible(LR"(C:\Windows)") ? "true" : "false";
}


int main(int argc, char** argv)
{
  HANDLE section;
  HANDLE server_ready_event;
  HANDLE client_ready_event;

  if (argc != 2)
    abort();

  if (std::sscanf(argv[1], "%p,%p,%p", &section, &server_ready_event, &client_ready_event) != 3)
    abort();

  std::fprintf(stderr, "Trusted code using impersonation token: user = %-5s, system = %-5s\n",
               user_accessible(),
               system_accessible());

  // If you want to debug the process using Process Hacker. You can suspend the process in Process Hacker if you
  // need more time

  Sleep(20000);

  // !! THIS IS THE MOST IMPORTANT LINE OF CODE IN THIS FILE !!
  //
  // The broker process changes the main thread's token to an impersonation token using SetThreadToken() when the process
  // is initially is loaded and before the main thread begins execution. We did this so that the main thread can load the
  // required resources required by the process, such as the system DLLs, without crashing due to access denial.
  // Once the process is loaded we must end impersonation using RevertToSelf().
  //
  // This call MUST not fail, otherwise the execution will continue using the impersonation token.

  if (RevertToSelf() == FALSE)
    abort();

  // Now we using the process primary token. It is very restricted, even the system resources are inaccessible
  std::fprintf(stderr, "    Untrusted code using primary token: user = %-5s, system = %-5s\n",
               user_accessible(),
               system_accessible());

  Sleep(20000);

  // Let's do some IPC 

  auto* const buffer = MapViewOfFile(section, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0);
  if (buffer == nullptr)
    abort();

  WaitForSingleObject(server_ready_event, INFINITE);

  WCHAR message[] = L"Display message box, plz";
  std::memcpy(buffer, message, sizeof(message));

  SetEvent(client_ready_event);

  UnmapViewOfFile(buffer);

  CloseHandle(section);
  CloseHandle(server_ready_event);
  CloseHandle(client_ready_event);
}
