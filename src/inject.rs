use log::{info, trace, warn};

use std::ffi::CString;
use std::ffi::OsString;
use std::io::Error;
use std::mem;
use std::os::windows::ffi::OsStringExt;
use std::ptr::null_mut;
use widestring::WideCString;

use std::fs::File;
use std::io::Read;

// Clean up these uses...
use winapi::shared::minwindef::{BOOL, FALSE, MAX_PATH, TRUE};
use winapi::shared::ntdef::NULL;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryW};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::{HANDLE, MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE, PROCESS_ALL_ACCESS};
use winapi::um::wow64apiset::IsWow64Process;

#[cfg(target_os = "windows")]
fn get_proc_id(application_name: &str) -> Result<u32, Error> {
    // Create a snapshot of the current processes
    let processes_snap_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

    if processes_snap_handle == INVALID_HANDLE_VALUE {
        return Err(Error::last_os_error());
    }

    // Initialise a process entry. In order to use `Process32First`, you need to set `dwSize`.
    let mut process_entry: PROCESSENTRY32W = PROCESSENTRY32W {
        dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; MAX_PATH],
    };

    // Get the first process from the snapshot.
    match unsafe { Process32FirstW(processes_snap_handle, &mut process_entry) } {
        1 => {
            // First process worked, loop to find the process with the correct name.
            let mut process_success: i32 = 1;
            let mut pid: u32 = 0;
            // Loop through all processes until we find one hwere `szExeFile` == `name`.
            while process_success == 1 {
                let process_name = OsString::from_wide(&process_entry.szExeFile);

                match process_name.into_string() {
                    Ok(s) => {
                        trace!(
                            "Found process with id {}: {}",
                            process_entry.th32ProcessID,
                            s
                        );
                        trace!(
                            "comparing {:?} with {:?}",
                            s.trim_matches(char::from(0)),
                            application_name
                        );
                        if s.trim_matches(char::from(0)) == application_name {
                            // we found it
                            pid = process_entry.th32ProcessID;
                        }
                    }
                    Err(_) => {
                        warn!(
                            "Error converting process name for PID {}",
                            process_entry.th32ProcessID
                        );
                    }
                }

                process_success =
                    unsafe { Process32NextW(processes_snap_handle, &mut process_entry) };
            }

            unsafe { CloseHandle(processes_snap_handle) };

            Ok(pid)
        }
        0 | _ => {
            unsafe { CloseHandle(processes_snap_handle) };
            Err(Error::last_os_error())
        }
    }
}

#[cfg(target_os = "windows")]
fn open_process(proc_id: u32) -> Result<HANDLE, Error> {
    // we don't care about getting caught :)
    // so lets do it in a noddy "proper" way
    unsafe {
        let h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, proc_id);
        if h_process == NULL {
            Err(Error::last_os_error())
        } else {
            Ok(h_process)
        }
    }
}

#[derive(Debug, PartialEq)]
enum Bitness {
    MACHINE64,
    MACHINE32,
}

fn get_pe_bits(p: &str) -> Bitness {
    let mut file = File::open(p).unwrap();
    let mut buf = vec![];
    file.read_to_end(&mut buf).unwrap();
    let exe = pe::Pe::new(&buf).unwrap();
    let header = exe.get_header();
    unsafe {
        if header.machine == pe::types::Machine::AMD64 || header.machine == pe::types::Machine::IA64
        {
            Bitness::MACHINE64
        } else {
            Bitness::MACHINE32
        }
    }
}

fn get_proc_bits(h_process: HANDLE) -> Result<Bitness, Error> {
    let mut b: BOOL = FALSE;
    unsafe {
        let ret = IsWow64Process(h_process, &mut b);
        if ret == FALSE {
            return Err(Error::last_os_error());
        }
    }
    unsafe {
        CloseHandle(h_process);
    }

    if b == TRUE {
        Ok(Bitness::MACHINE32)
    } else {
        Ok(Bitness::MACHINE64)
    }
}

#[cfg(target_os = "windows")]
pub fn inject_library(h_process: HANDLE, dll_path: &str) -> Result<(), Error> {

    // Check architecture of the injected code and program so we don't explode 
    let pe_bits = get_pe_bits(dll_path);
    let proc_bits = match get_proc_bits(h_process) {
        Ok(b) => b,
        Err(e) => return Err(e),
    };

    if pe_bits != proc_bits {
        warn!(
            "Architecture mismatch! Target: {:?}, DLL: {:?}",
            proc_bits, pe_bits
        );
        return Err(Error::last_os_error());
    }

    info!(
        "Bitness of DLL and Process matched {:?} and {:?}",
        proc_bits, pe_bits
    );

    // Get a handle to k32 and get address for LoadLibrary
    let h_kernel32;
    let loadlibrary;
    unsafe {
        h_kernel32 = LoadLibraryW(WideCString::from_str("kernel32.dll").unwrap().as_ptr());
        loadlibrary = GetProcAddress(h_kernel32, CString::new("LoadLibraryA").unwrap().as_ptr());
    }
    info!("kernel32 address: {:?}", h_kernel32);
    info!("LoadLibraryA address: {:?}", loadlibrary);

    // Calculate the size of the memory we need to allocate for the dll name
    let path_size: usize = (dll_path.len() as u64 + 1) as usize;
    info!("Calculated size to allocate: {:?}", path_size);

    // allocate some mem for thread_start
    let thread_start_addr;
    unsafe {
        thread_start_addr =
            VirtualAllocEx(h_process, null_mut(), path_size, MEM_COMMIT, PAGE_READWRITE);
        warn! {"{:?}",GetLastError()};
    }
    info!(
        "Thread start addresss allocated at: {:?}",
        thread_start_addr
    );

    if thread_start_addr.is_null() {
        return Err(Error::last_os_error());
    }
    info!("Allocated {} bytes at  {:?}", path_size, thread_start_addr);

    // write thread start
    let mut bytes_written = 0;
    let ret;
    unsafe {
        ret = WriteProcessMemory(
            h_process,
            thread_start_addr,
            CString::new(dll_path).unwrap().as_ptr() as *const std::os::raw::c_void,
            path_size,
            &mut bytes_written,
        );
    }
    info!("Wrote {} bytes at  {:?}", bytes_written, thread_start_addr);

    if ret == 0 || bytes_written == 0 {
        return Err(Error::last_os_error());
    }

    // initiate a thread
    let h_thread;
    unsafe {
        h_thread = CreateRemoteThread(
            h_process,
            null_mut(),
            0,
            Some(std::mem::transmute(loadlibrary)),
            thread_start_addr,
            0,
            null_mut(),
        );
    }
    info!("Thread handle creation returned: {:?}", h_thread);

    if h_thread.is_null() {
        unsafe {
            warn!(
                "h_thread was null, Freeing Memory at {:?}",
                thread_start_addr
            );
            VirtualFreeEx(h_process, thread_start_addr, path_size, MEM_RELEASE);
        }
        return Err(Error::last_os_error());
    }

    unsafe {
        CloseHandle(h_thread);
        WaitForSingleObject(h_thread, 0xFFFFFFFF);
    }

    Ok(())
}

pub fn inject(application_name: &str, dll_path: &str) -> Result<(), Error> {
    let proc_id = get_proc_id(application_name).unwrap();
    info!("Proc ID found for {}:{}", application_name, proc_id);
    let h_process = open_process(proc_id).unwrap();
    info!(
        "Handle for process got for {}:{:?}",
        application_name, h_process
    );
    inject_library(h_process, dll_path).unwrap();
    info!(
        "Sucessfully injected {:?} into {}",
        dll_path, application_name
    );
    Ok(())
}
