#include <windows.h>
#include <sddl.h>
#include <strsafe.h>
#include <cstdio>
#include <cwchar>
#include <cstdlib>
#include <vector>


[[noreturn]] static
void broker_fatal_error()
{
  const DWORD error_code = GetLastError();
  LPWSTR message;

  // Convert last error to human readable string
  if (FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                     nullptr,
                     error_code,
                     MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                     reinterpret_cast<LPWSTR>(&message),
                     0,
                     nullptr) != 0)
  {
    std::fwprintf(stderr, L"Error: failed with 0x%08lx: %ls", error_code, message);
    LocalFree(message);
  }

  // Break into the debugger if it is available
  if (IsDebuggerPresent())
    DebugBreak();

  abort();
}


#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 26812)
#endif
template <typename T>
T* broker_get_token_information(HANDLE token, TOKEN_INFORMATION_CLASS token_information_class)
{
  DWORD return_length;
  void* token_information;


  return_length = 8;

  for (;;)
  {
    token_information = operator new(return_length);

    if (GetTokenInformation(token,
                            token_information_class,
                            token_information,
                            return_length,
                            &return_length) != FALSE)
      break;

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
      broker_fatal_error();

    operator delete(token_information);
  }

  return static_cast<T*>(token_information);
}
#ifdef _MSC_VER
#pragma warning(pop)
#endif

static
void broker_lower_token_integrity_level(HANDLE token)
{
  PSID integrity_sid;
  TOKEN_MANDATORY_LABEL token_mandatory_label;


  // By default user processes launched without elevation run at Medium integrity level (S-1-16-8192) and can write to
  // user resources such as files. We will downgrade the integrity level to Low (S-1-16-4096) or Untrusted (S-1-16-0).
  // Processes at integrity level are denied from writing to resources with higher integrity level even if the
  // DACL allows it, unless it explicitly allow access by that integrity level. It still allows read access though.
  //
  // To deny read access, we will use restricted tokens.
  //

  if (ConvertStringSidToSidW(L"S-1-16-0", &integrity_sid) == FALSE)
    broker_fatal_error();

  token_mandatory_label.Label.Attributes = SE_GROUP_INTEGRITY;
  token_mandatory_label.Label.Sid = integrity_sid;

  if (SetTokenInformation(token,
                          TokenIntegrityLevel,
                          &token_mandatory_label,
                          sizeof(TOKEN_MANDATORY_LABEL)) == FALSE)
    broker_fatal_error();

  LocalFree(integrity_sid);
}


static
HANDLE broker_create_restricted_token(bool for_impersonation)
{
  HANDLE token;
  HANDLE restricted_token;
  LUID change_notify_privilege;
  PSID everyone_group_sid;
  PSID users_group_sid;
  std::vector<LUID_AND_ATTRIBUTES> deleted_privileges;
  std::vector<SID_AND_ATTRIBUTES> disabled_sids;


  if (OpenProcessToken(GetCurrentProcess(),
                       TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_IMPERSONATE,
                       &token) == FALSE)
    broker_fatal_error();


  // We are going to remove all privileges granted to the access token. We will except for SeChangeNotifyPrivilege while
  // creating the impersonation token. This privilege is used to bypass the access check on intermediate directories if the
  // target resource is assessable. It is required to load the process anyway.

  if (LookupPrivilegeValueW(nullptr, L"SeChangeNotifyPrivilege", &change_notify_privilege) == FALSE)
    broker_fatal_error();

  // Disable all privileges
  auto* const privileges = broker_get_token_information<TOKEN_PRIVILEGES>(token, TokenPrivileges);

  for (DWORD i = 0; i < privileges->PrivilegeCount; ++i)
  {
    const auto privilege = privileges->Privileges[i].Luid;

    // Except SeChangeNotifyPrivilege when creating an impersonation token
    if (for_impersonation &&
      (privilege.LowPart == change_notify_privilege.LowPart && privilege.HighPart == change_notify_privilege.HighPart))
      continue;

    deleted_privileges.push_back({privilege, 0});
  }

  // We are going to create a restricted token and use it as the primary token of the child process. We will turn all
  // SIDs into a deny-only SID which is similar to removing these SIDs. For the impersonation toke, we will keep the
  // Everyone and Users SIDs to allow the process to access the resources needed to load the process such as the system DLLs

  // Everyone group
  if (ConvertStringSidToSidW(L"S-1-1-0", &everyone_group_sid) == FALSE)
    broker_fatal_error();

  // Users group
  if (ConvertStringSidToSidW(L"S-1-5-32-545", &users_group_sid) == FALSE)
    broker_fatal_error();

  // Disable all group SIDs
  auto* const groups = broker_get_token_information<TOKEN_GROUPS>(token, TokenGroups);

  for (DWORD i = 0; i < groups->GroupCount; ++i)
  {
    const auto attributes = groups->Groups[i].Attributes;
    auto* sid = groups->Groups[i].Sid;

    // Filter out integrity and the logon SIDs
    if ((attributes & SE_GROUP_INTEGRITY) || (attributes & SE_GROUP_LOGON_ID))
      continue;

    // Filter out Everyone and Users SIDs if we are creating an impersonation token
    if (for_impersonation &&
      (EqualSid(sid, everyone_group_sid) || EqualSid(sid, users_group_sid)))
      continue;

    disabled_sids.push_back({sid, 0});
  }

  // Disallow accessing user resources
  auto* const user = broker_get_token_information<TOKEN_USER>(token, TokenUser);
  disabled_sids.push_back({user->User.Sid, 0});

  if (CreateRestrictedToken(token,
                            0,
                            static_cast<DWORD>(disabled_sids.size()),
                            disabled_sids.data(),
                            static_cast<DWORD>(deleted_privileges.size()),
                            deleted_privileges.data(),
                            0,
                            nullptr,
                            &restricted_token) == FALSE)
    broker_fatal_error();

  LocalFree(users_group_sid);
  LocalFree(everyone_group_sid);

  delete user;
  delete groups;
  delete privileges;

  CloseHandle(token);

  broker_lower_token_integrity_level(restricted_token);

  if (for_impersonation)
  {
    HANDLE impersonation_token;

    // Create an impersonation token
    if (DuplicateToken(restricted_token, SecurityImpersonation, &impersonation_token) == FALSE)
      broker_fatal_error();

    CloseHandle(restricted_token);

    restricted_token = impersonation_token;
  }

  return restricted_token;
}


static
HANDLE broker_create_restricted_job()
{
  HANDLE job;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION extended_limit_information;
  JOBOBJECT_BASIC_UI_RESTRICTIONS basic_ui_restrictions;


  job = CreateJobObjectW(nullptr, nullptr);
  if (job == nullptr)
    broker_fatal_error();

  // This restriction denies the child process from spawning new processes and terminates the child process once
  // the handle to the job object is closed. It is required so that the child process does not stay alive after the broker
  // process terminates.

  extended_limit_information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
    | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
  extended_limit_information.BasicLimitInformation.ActiveProcessLimit = 5;

  if (SetInformationJobObject(job,
                              JobObjectExtendedLimitInformation,
                              &extended_limit_information,
                              sizeof(extended_limit_information)) == FALSE)
    broker_fatal_error();

  // This sets various UI restriction most notably it disallows the process from switching to different desktops and accessing
  // the clipboard

  basic_ui_restrictions.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP
    | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
    | JOB_OBJECT_UILIMIT_EXITWINDOWS
    | JOB_OBJECT_UILIMIT_GLOBALATOMS
    | JOB_OBJECT_UILIMIT_HANDLES
    | JOB_OBJECT_UILIMIT_READCLIPBOARD
    | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
    | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;

  if (SetInformationJobObject(job,
                              JobObjectBasicUIRestrictions,
                              &basic_ui_restrictions,
                              sizeof(basic_ui_restrictions)) == FALSE)
    broker_fatal_error();

  return job;
}


static
void broker_create_process(PHANDLE job, PHANDLE process, HANDLE section, HANDLE server_ready_event,
                           HANDLE client_ready_event)
{
  HANDLE impersonation_token;
  HANDLE primary_token;
  STARTUPINFOW startup_information;
  PROCESS_INFORMATION process_information;
  WCHAR desktop_name[] = L"broker-process-isolation-desktop-e0fe9e56-2f0a-4567-9db6-4c1bd4f456d5";
  HDESK desktop;
  HANDLE restricted_job;
  WCHAR command_line_argument[MAX_PATH];


  // Create a separate desktop to isolate the process. Notice that the memory dedicated for desktop heaps is limited
  // to 48MB according to MSDN. This means we can not create that many desktop objects

  desktop = CreateDesktopW(desktop_name, nullptr, nullptr, 0, GENERIC_ALL, nullptr);
  if (desktop == nullptr)
    broker_fatal_error();

  restricted_job = broker_create_restricted_job();

  primary_token = broker_create_restricted_token(false);

  ZeroMemory(&startup_information, sizeof(startup_information));
  startup_information.cb = sizeof(startup_information);
  startup_information.lpDesktop = desktop_name;

  if (StringCchPrintfW(command_line_argument,
                       sizeof(command_line_argument) / sizeof(command_line_argument[0]),
                       L"sandbox.exe %p,%p,%p",
                       section, server_ready_event, client_ready_event) != S_OK)
    broker_fatal_error();

  if (CreateProcessAsUserW(primary_token,
                           LR"(.\\sandbox.exe)",
                           command_line_argument,
                           nullptr,
                           nullptr,
                           TRUE,
                           CREATE_SUSPENDED,
                           nullptr,
                           nullptr,
                           &startup_information,
                           &process_information) == FALSE)
    broker_fatal_error();

  if (AssignProcessToJobObject(restricted_job, process_information.hProcess) == FALSE)
  {
    if (TerminateProcess(process_information.hProcess, EXIT_FAILURE) == FALSE)
      DebugBreak();
    broker_fatal_error();
  }

  CloseDesktop(desktop);
  CloseHandle(primary_token);

  // If the process continued with the current primary token it will crash. So give the main thread
  // a less restricted impersonation token and resume execution. The child process MUST call RevertToSelf()
  // and drop the impersonation token before it executes insecure code

  impersonation_token = broker_create_restricted_token(true);

  if (SetThreadToken(&process_information.hThread, impersonation_token) == FALSE)
    broker_fatal_error();
  CloseHandle(impersonation_token);

  if (ResumeThread(process_information.hThread) == static_cast<DWORD>(-1))
    broker_fatal_error();
  CloseHandle(process_information.hThread);

  *job = restricted_job;
  *process = process_information.hProcess;
}


static
void broker_ipc_initialize(PHANDLE section, PHANDLE server_ready_event, PHANDLE client_ready_event)
{
  SECURITY_ATTRIBUTES security_attributes;
  HANDLE shared_section;
  HANDLE section_server_ready_event;
  HANDLE section_client_ready_event;


  ZeroMemory(&security_attributes, sizeof(security_attributes));
  security_attributes.nLength = sizeof(security_attributes);
  security_attributes.bInheritHandle = TRUE;

  shared_section = CreateFileMappingW(INVALID_HANDLE_VALUE,
                                      &security_attributes,
                                      PAGE_READWRITE,
                                      0,
                                      1024,
                                      nullptr);
  if (shared_section == nullptr)
    broker_fatal_error();

  section_server_ready_event = CreateEventW(&security_attributes, FALSE, FALSE, nullptr);
  if (section_server_ready_event == nullptr)
    broker_fatal_error();


  section_client_ready_event = CreateEventW(&security_attributes, FALSE, FALSE, nullptr);
  if (section_client_ready_event == nullptr)
    broker_fatal_error();

  *section = shared_section;
  *server_ready_event = section_server_ready_event;
  *client_ready_event = section_client_ready_event;
}


static
void broker_start_ipc(HANDLE process, HANDLE section, HANDLE server_ready_event, HANDLE client_ready_event)
{
  void* buffer;
  HANDLE waitable[] = {process, client_ready_event};


  // Designing a proper IPC system that is both secure and easy to use is a problem on its own. This code is insecure
  // and being sloppy. The focus here is on the restricted child process. The IPC is out of the scope

  buffer = MapViewOfFile(section, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0);
  if (buffer == nullptr)
    abort();

  // Notify the child process that we are ready
  SetEvent(server_ready_event);

  // Wait until the data is copied. We should avoid waiting forever on an object that might be controlled by a malicious code
  if (WaitForMultipleObjects(2, waitable, FALSE, INFINITE) == WAIT_OBJECT_0 + 1)
  {
    // We should never trust the data coming from this process and we should always work under the assumption that the
    // process is compromised. We should also copy the data into a separate buffer inaccessible by the sandbox process
    // and validate the data there to avoid race conditions

    // String might be not be null terminated and/or within the range of the shared buffer
    MessageBoxW(nullptr, static_cast<LPCWSTR>(buffer), L"Sandbox", MB_OK);
  }

  UnmapViewOfFile(buffer);
}


int main()
{
  HANDLE section;
  HANDLE server_ready_event;
  HANDLE client_ready_event;
  HANDLE job;
  HANDLE process;


  broker_ipc_initialize(&section, &server_ready_event, &client_ready_event);

  broker_create_process(&job, &process, section, server_ready_event, client_ready_event);

  broker_start_ipc(process, section, server_ready_event, client_ready_event);

  if (WaitForSingleObject(process, INFINITE) != WAIT_OBJECT_0)
    broker_fatal_error();

  CloseHandle(process);
  CloseHandle(job);
  CloseHandle(section);
  CloseHandle(server_ready_event);
  CloseHandle(client_ready_event);

  return EXIT_SUCCESS;
}
