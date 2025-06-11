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