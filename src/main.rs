use std::io;
use std::mem;
use std::vec;
use winapi::shared::minwindef::{DWORD , FALSE};



pub fn enum_proc() -> io::Result<vec<u32>>{
    let mut pids = Vec ::<DWORD>::with_capacity(1024);
    //heap allocated array for storing the PID 
    //1024 is a big number 
    let mut size = 0;
    if unsafe {
        winapi::um::psapi::EnumProcesses(
            pids.as_mut_ptr()
        )
    }
    
}