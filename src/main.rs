use std::io;
use std::mem;
use std::vec;
use winapi::shared::minwindef::{DWORD, FALSE};
use std::ptr::NonNull;
use winapi::ctypes::c_void;

pub fn enum_proc() -> io::Result<Vec<u32>> {
    let mut pids = Vec::<DWORD>::with_capacity(1024);
    // heap allocated array for storing the PID 
    // 1024 
    let mut size = 0;
    if unsafe {
        winapi::um::psapi::EnumProcesses(
            pids.as_mut_ptr(),
            (pids.capacity() * mem::size_of::<DWORD>()) as u32,
            &mut size,
        )
    } == FALSE {
        return Err(io::Error::last_os_error());
    }
    // The API likes to use u32 for sizes, unlike Rust which uses usize, so we need a cast
    let count = size as usize / mem::size_of::<DWORD>();
    unsafe { pids.set_len(count); }
    Ok(pids)
}

// opening a process
// custom struct Process with an impl Drop

pub struct Process {
    pid: u32,
    handle: NonNull<c_void>,
}

impl Process {
    pub fn open(pid: u32) -> io::Result<Self> {
        // SAFETY: the call doesn't have dangerous side-effects.
        let handle = unsafe {
            winapi::um::processthreadsapi::OpenProcess(
                winapi::um::winnt::PROCESS_QUERY_INFORMATION,
                FALSE,
                pid,
            )
        } as *mut c_void;

        NonNull::new(handle)
            .map(|handle| Self { pid, handle })
            .ok_or_else(io::Error::last_os_error)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: the handle is valid and non-null.
        unsafe {
            let result = winapi::um::handleapi::CloseHandle(self.handle.as_mut());
            debug_assert!(result != 0, "Failed to close handle");
        }
    }
}

fn main() {
    let mut success = 0;
    let mut failed = 0;
    enum_proc().unwrap().into_iter().for_each(|pid| match Process::open(pid) {
        Ok(_) => success += 1,
        Err(_) => failed += 1,
    });

    println!("Successfully opened {} processes, failed to open {} processes", success, failed);
}
// NOTES 




// ---------------------------------------------------
// EnumProcesses
// ---------------------------------------------------
// - Purpose: Enumerates all the process IDs (PIDs) currently running on the system.
// - How it works: Fills an array with PIDs up to the provided capacity.
// - Parameters:
//     - Pointer to an array to receive process IDs.
//     - Size of the array in bytes.
//     - Pointer to a variable that receives the number of bytes returned.
// - Returns: Non-zero on success, zero on failure.
// - Usage: Used here to get a snapshot of all active processes on the machine.
// ---------------------------------------------------
// OpenProcess
// ---------------------------------------------------
// - Purpose: Opens a handle to a process identified by its PID, with specified access rights.
// - Parameters:
//     - dwDesiredAccess: Access level requested (e.g. PROCESS_QUERY_INFORMATION).
//     - bInheritHandle: Whether child processes inherit the handle (usually FALSE).
//     - dwProcessId: Process ID of the target process.
// - Returns: A handle to the process on success, or NULL on failure.
// - Notes:
//     - PROCESS_QUERY_INFORMATION allows querying process info but not modifying it.
//     - Opening some processes may fail if insufficient permissions.
// - Usage: Used here to get a handle to each process for querying info safely.
// ---------------------------------------------------
// CloseHandle
// ---------------------------------------------------
// - Purpose: Closes an open handle to any Windows object to free system resources.
// - Parameters:
//     - Handle to be closed.
// - Returns: Non-zero on success, zero on failure.
// - Usage: Called in Drop to clean up and avoid resource leaks for process handles.
