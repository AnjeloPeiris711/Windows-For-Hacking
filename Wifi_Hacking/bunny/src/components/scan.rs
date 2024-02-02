extern crate winapi;

use std::ptr;
use winapi::um::wlanapi::*;
use winapi::um::winnt::HANDLE;
use winapi::shared::ntdef::NULL;
use winapi::um::wlanapi::{
    WlanOpenHandle, 
    WlanCloseHandle, 
    WlanGetAvailableNetworkList, 
    WLAN_API_VERSION_2_0,
    WLAN_AVAILABLE_NETWORK_LIST,
};

pub fn scan_network() {
    // Declare variables for WLAN API handles and data structures
    unsafe {
        // Open a handle to the WLAN client
        let mut client_handle: HANDLE = ptr::null_mut();
        let mut available_network_list: *mut WLAN_AVAILABLE_NETWORK_LIST = std::ptr::null_mut();
        let mut version = WLAN_API_VERSION_2_0; // Use WLAN API version 2

        let result = WlanOpenHandle(
            WLAN_API_VERSION_2_0,
            NULL,
            &mut version as *mut _ as *mut _,
            &mut client_handle,
        );

        if result == 0 {
            let mut interface_list: *mut WLAN_INTERFACE_INFO_LIST = ptr::null_mut();
            let result = WlanEnumInterfaces(
                client_handle,
                ptr::null_mut(),
                &mut interface_list,
            );

            if result == 0 {
                let interface_count = (*interface_list).dwNumberOfItems as usize;
                let interface_info_slice = 
                    std::slice::from_raw_parts((*interface_list).InterfaceInfo.as_ptr(), interface_count);
                
                // Call WlanGetAvailableNetworkList to retrieve the list of available networks
                let result = WlanGetAvailableNetworkList(
                    client_handle,
                    &interface_info_slice[1].InterfaceGuid,
                    0,
                    std::ptr::null_mut(),
                    &mut available_network_list as *mut _,
                );

                if result == 0 {
                    // Access the available network list through the `available_network_list` variable
                    let network_list = &*available_network_list; // Dereference the pointer
                    println!("{}",network_list.dwNumberOfItems as usize);
                    let network = &network_list.Network[0];
                    let ssid = String::from_utf8_lossy(&network.dot11Ssid.ucSSID);
                    println!("SSID: {:?}", ssid);
                    
                } else {
                    println!("WlanGetAvailableNetworkList failed with result: {}", result);
                }
                WlanFreeMemory(interface_list as *mut std::ffi::c_void);
            } else {
                println!("WlanEnumInterfaces failed with result: {}", result);
            }
        } else {
            println!("WlanOpenHandle failed with result: {}", result);
        }
        WlanFreeMemory(available_network_list as *mut std::ffi::c_void);
        WlanCloseHandle(client_handle, std::ptr::null_mut());
    }
}

