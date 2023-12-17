extern crate libc;

use std::ffi::{CStr, CString};
use libc::{c_int, c_void, ifaddrs, getifaddrs, sockaddr, sockaddr_in, AF_INET};

pub fn monitor_interface(interface: &str) -> Result<(), String> {
    unsafe {
        let mut ifap: *mut ifaddrs = std::ptr::null_mut();

        if getifaddrs(&mut ifap) == 0 {
            let mut ifa = ifap;

            while !ifa.is_null() {
                let ifa_name = (*ifa).ifa_name;
                let cstr = CStr::from_ptr(ifa_name);
                let name = cstr.to_str().unwrap();

                println!("Interface Name: {}", name);

                let ifa_addr = (*ifa).ifa_addr;
                if !ifa_addr.is_null() {
                    let sockaddr_ptr = ifa_addr as *const sockaddr;
                    if (*sockaddr_ptr).sa_family == AF_INET as u16 {
                        let sin = sockaddr_ptr as *const sockaddr_in;
                        let addr = (*sin).sin_addr.s_addr;
                        let ip = std::net::Ipv4Addr::from(addr);
                        println!("  IPv4 Address: {}", ip);
                    }
                }

                ifa = (*ifa).ifa_next;
            }

            libc::freeifaddrs(ifap);
            Ok(())
        } else {
            Err("Failed to get interface addresses".to_string())
        }
    }
}

