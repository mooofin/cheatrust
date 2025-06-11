//Author - mooofin  
//Date:


/*
// EnumProcesses Notes:
// -------------------
// Purpose: Retrieves PIDs of all running processes in the system.
// Parameters:
//   - lpidProcess: Output array to store process IDs
//   - cb: Size of array in bytes
//   - lpcbNeeded: Outputs bytes used in array
// Return: Non-zero on success, zero on failure (use GetLastError())
// Important:
//   - Array size should be large (e.g., 1024*sizeof(DWORD))
//   - Calculate process count: lpcbNeeded/sizeof(DWORD)
//   - If lpcbNeeded == cb, array may be too small - retry with larger buffer
//   - Requires OpenProcess() to get handles from PIDs
// Windows 7+:
//   - PSAPI_VERSION determines function name:
//     - v2+: K32EnumProcesses (Kernel32.dll)
//     - v1: EnumProcesses (Psapi.dll wrapper)
// Compatibility: Use EnumProcesses name for all versions
*/

/*
// GetLastError Notes:
// ------------------
// Purpose: Retrieves last error code for calling thread (thread-specific)
// Return: DWORD error code
// Best Practices:
//   - Call IMMEDIATELY after API failure
//   - Some functions reset error code on success
//   - Use FormatMessage() to get error string
//   - System error codes vary by OS/driver
// Custom Errors:
//   - Application errors should set bit 29 (0x20000000)
//   - Use HRESULT_FROM_WIN32 to convert to HRESULT
// VB Note: Use err.LastDllError instead
*/
/*
// OpenProcess Notes:
// -----------------
// Purpose: Opens a handle to an existing local process
// Parameters:
//   - dwDesiredAccess: Requested access rights (e.g., PROCESS_ALL_ACCESS)
//     - Requires SeDebugPrivilege for full access to other processes
//   - bInheritHandle: Whether child processes inherit this handle
//   - dwProcessId: PID of target process
// Return: Process handle on success, NULL on failure (check GetLastError())
// Important:
//   - Always call CloseHandle() when finished
//   - Fails for special processes:
//     - System Idle Process (0): ERROR_INVALID_PARAMETER
//     - System/CSRSS processes: ERROR_ACCESS_DENIED
// Optimization:
//   - For current process, use GetCurrentProcess() instead
// Security:
//   - Access rights are checked against process security descriptor
//   - SeDebugPrivilege bypasses security checks
// Usage:
//   - Returned handle works with wait functions, etc.
//   - Combine with EnumProcesses() for process enumeration
*/
/*
// GetModuleBaseNameA Notes:
// ------------------------
// Purpose: Retrieves base name of a process module
// Parameters:
//   - hProcess: Handle with PROCESS_QUERY_INFORMATION|PROCESS_VM_READ
//   - hModule: Module handle (NULL = main executable)
//   - lpBaseName: Output buffer for base name
//   - nSize: Buffer size in characters
// Return: Length of string copied (0 on failure, check GetLastError())
// Important:
//   - Primarily for debuggers (may fail if target process modifies modules)
//   - For current process, prefer GetModuleFileName() + string parsing
//   - For remote process main exe, prefer GetProcessImageFileName()
// Limitations:
//   - Doesn't work with LOAD_LIBRARY_AS_DATAFILE modules
// Windows 7+:
//   - PSAPI_VERSION determines function name/location:
//     - v2+: K32GetModuleBaseName (Kernel32.dll)
//     - v1: GetModuleBaseName (Psapi.dll wrapper)
*/

/*
// EnumProcessModules Notes:
// ------------------------
// Purpose: Retrieves all module handles in a process
// Parameters:
//   - hProcess: Target process handle
//   - lphModule: Output array for module handles
//   - cb: Array size in bytes
//   - lpcbNeeded: Bytes actually used
// Return: Non-zero on success (0 = check GetLastError())
// Important:
//   - Primarily for debuggers (may fail if modules change during call)
//   - Calculate module count: lpcbNeeded/sizeof(HMODULE)
//   - If lpcbNeeded > cb, retry with larger buffer
//   - Don't CloseHandle() returned HMODULEs
// Limitations:
//   - 32-bit apps can't enum 64-bit process modules (ERROR_PARTIAL_COPY)
//   - Skips LOAD_LIBRARY_AS_DATAFILE modules
// Alternatives:
//   - CreateToolhelp32Snapshot() for more comprehensive snapshots
// Windows 7+:
//   - PSAPI_VERSION determines function name/location:
//     - v2+: K32EnumProcessModules (Kernel32.dll)
//     - v1: EnumProcessModules (Psapi.dll wrapper)
// Usage Pattern:
//   1. EnumProcessModules() to get HMODULE array
//   2. GetModuleBaseNameA/GetModuleFileNameEx for each HMODULE
*/
use std::io;
use std::mem;
use std::ptr::{self, NonNull};
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{DWORD, FALSE, HMODULE, MAX_PATH};
use winapi::um::psapi;
use winapi::um::winnt::PROCESS_QUERY_INFORMATION;
use std::mem::MaybeUninit;

// A handle to a process.
pub struct Process {
    pid: u32,
    handle: NonNull<c_void>,
}

impl Process {
    /// Opens a process by its PID with the necessary access rights.
    pub fn open(pid: u32) -> io::Result<Self> {
        // PROCESS_QUERY_INFORMATION is needed to get the process name.
        // PROCESS_VM_READ is also required for EnumProcessModules.
        let handle = unsafe {
            winapi::um::processthreadsapi::OpenProcess(
                PROCESS_QUERY_INFORMATION | winapi::um::winnt::PROCESS_VM_READ,
                FALSE,
                pid,
            )
        };

        NonNull::new(handle)
            .map(|handle| Self { pid, handle })
            .ok_or_else(io::Error::last_os_error)
    }

    /// Retrieves the name of the process.
    pub fn name(&self) -> io::Result<String> {
        let mut module = MaybeUninit::<HMODULE>::uninit();
        let mut size_needed = 0;

        // Get a handle to the first module of the process.
        // SAFETY: The handle is valid, and we are checking the return value.
        if unsafe {
            psapi::EnumProcessModules(
                self.handle.as_ptr(),
                module.as_mut_ptr(),
                mem::size_of::<HMODULE>() as u32,
                &mut size_needed,
            )
        } == FALSE
        {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: The call succeeded, so the module handle is initialized.
        let module = unsafe { module.assume_init() };

        let mut buffer: [u16; MAX_PATH] = [0; MAX_PATH];
        
        // Get the base name of the module (the process executable name).
        // SAFETY: The handle and module are valid, and the buffer is large enough.
        let len = unsafe {
            psapi::GetModuleBaseNameW(
                self.handle.as_ptr(),
                module,
                buffer.as_mut_ptr(),
                MAX_PATH as DWORD,
            )
        };

        if len == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(String::from_utf16_lossy(&buffer[..len as usize]))
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: The handle is valid and non-null.
        unsafe {
            winapi::um::handleapi::CloseHandle(self.handle.as_ptr());
        }
    }
}

/// Enumerates all running process IDs.
pub fn enum_proc() -> io::Result<Vec<u32>> {
    // Pre-allocate a vector with a reasonable starting size.
    let mut pids = Vec::<DWORD>::with_capacity(1024);
    let mut bytes_returned = 0;

    // SAFETY: We provide a valid pointer, its size in bytes, and a pointer for the output size.
    if unsafe {
        psapi::EnumProcesses(
            pids.as_mut_ptr(),
            (pids.capacity() * mem::size_of::<DWORD>()) as u32,
            &mut bytes_returned,
        )
    } == FALSE
    {
        return Err(io::Error::last_os_error());
    }

    let count = bytes_returned as usize / mem::size_of::<DWORD>();
    // SAFETY: The API has initialized 'count' elements of the vector.
    unsafe { pids.set_len(count) };
    
    Ok(pids)
}

fn main() {
    let processes = match enum_proc() {
        Ok(pids) => pids,
        Err(e) => {
            eprintln!("Failed to enumerate processes: {}", e);
            return;
        }
    };

    for pid in processes {
        // Skip the System Idle Process (PID 0) and System process (PID 4)
        // as they often cause access denied errors.
        if pid == 0 || pid == 4 {
            continue;
        }

        match Process::open(pid) {
            Ok(proc) => match proc.name() {
                Ok(name) => println!("[{}] {}", pid, name),
                Err(e) => eprintln!("\t> Could not get name for PID {}: {}", pid, e),
            },
            Err(e) => eprintln!("\t> Could not open process {}: {}", pid, e),
        }
    }
}


