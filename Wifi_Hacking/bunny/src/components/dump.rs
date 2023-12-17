// use pcap::*;

// fn capture_wpa2_handshake() {
//     // List available devices and choose the one you want
//     let device = Device::list().unwrap()[4].clone();
//     // Choose the device (you may need to change the index based on your setup)
    

//     // Open the selected device for capturing
//     let mut cap = device.open().unwrap();
//     let mut savefile = cap.savefile("test.pcap").unwrap();
//     // Keep capturing until the 4-way handshake is complete
//     let mut handshake_complete = false;
//     // Set a filter to capture only TCP packets
//     cap.filter("eapol", true).unwrap();
//     while !handshake_complete {
//         if let Ok(packet) = cap.next_packet() {
//             // Process the packet, check if it's part of the WPA2 4-way handshake
//             // You need to implement the logic to identify EAPOL-Key messages
//             // and keep track of the handshake state
//             println!("Received packet: {:?}", packet);

//             // Check if the WPA2 4-way handshake is complete
//             // You need to implement the logic to detect the completion of the handshake
//         handshake_complete = is_wpa2_handshake_complete(&packet);
//         // handshake_complete = true;
//         savefile.write(&packet);
//         }

//     }
//     println!("WPA2 4-way handshake complete!");
// }

// fn is_wpa2_handshake_complete(packet: &Packet) -> bool {
//     println!("{:?}",packet);
//     // Implement the logic to check if the packet is part of the WPA2 4-way handshake
//     // You need to examine the packet content and EAPOL-Key messages
//     // Return true if the handshake is complete, otherwise false
//     // unimplemented!("Implement the logic to check if the WPA2 handshake is complete");
//     true
// }
extern crate winapi;


use std::ptr;
use winapi::shared::ntdef::NULL;
use winapi::um::wlanapi::*;
use winapi::um::winnt::HANDLE;
use winapi::um::wlanapi::WLAN_API_VERSION_2_0;
use winapi::shared::winerror::ERROR_SUCCESS;

pub fn packet_dump() {
    // capture_wpa2_handshake();
    unsafe {
        let mut client_handle: HANDLE = ptr::null_mut();
        let mut version=WLAN_API_VERSION_2_0; // Use WLAN API version 2

        let result = WlanOpenHandle(
            WLAN_API_VERSION_2_0,
            NULL,
            &mut version as *mut _ as *mut _,
            &mut client_handle,
            
        );

        if result == ERROR_SUCCESS {
            let mut interface_list: *mut WLAN_INTERFACE_INFO_LIST = ptr::null_mut();
            // Iterate through each interface and display capabilities
            let mut p_cap: *mut WLAN_INTERFACE_CAPABILITY = ptr::null_mut();
            let result = WlanEnumInterfaces(
                client_handle,
                ptr::null_mut(),
                &mut interface_list,
            );

            if result == ERROR_SUCCESS {
                let interface_count = (*interface_list).dwNumberOfItems as usize;
                let interface_info_slice = 
                    std::slice::from_raw_parts((*interface_list).InterfaceInfo.as_ptr(), interface_count);

                for (i, interface_info) in interface_info_slice.iter().enumerate() {
                    let description = String::from_utf16_lossy(&interface_info.strInterfaceDescription);
                    let dw_result = WlanGetInterfaceCapability(
                        client_handle,
                        &interface_info.InterfaceGuid,
                        ptr::null_mut(),
                        &mut p_cap,
                    );
                    println!("Interface {}: {}", i, description);
                    println!("InterfaceGUID: {:x}-{:x}-{:x}-{:x?}", interface_info.InterfaceGuid.Data1, interface_info.InterfaceGuid.Data2, interface_info.InterfaceGuid.Data3, interface_info.InterfaceGuid.Data4);
                    println!("IsState: {}", interface_info.isState);
                    if dw_result == ERROR_SUCCESS {
                        println!(
                            "802.11d Supported: {}",
                            if (*p_cap).bDot11DSupported != 0 {
                                "Yes"
                            } else {
                                "No"
                            }
                    );
                    println!("  Interface Type: {}", (*p_cap).interfaceType);
                    println!("  Max SSID List Size: {}", (*p_cap).dwMaxDesiredSsidListSize);
                    println!("  Max BSSID List Size: {}", (*p_cap).dwMaxDesiredBssidListSize);
                    println!("  Number of Supported PHYs: {}", (*p_cap).dwNumberOfSupportedPhys);
                    // Display supported PHY types
                    print!("  Supported PHY Types:");
                    for j in 0..(*p_cap).dwNumberOfSupportedPhys as usize {
                        print!(" {}", (*p_cap).dot11PhyTypes[j]);
                    }
                    }
                    println!("");
                }

                WlanFreeMemory(interface_list as *mut _);
                WlanFreeMemory(p_cap as *mut std::ffi::c_void);
            } else {
                println!("Failed to enumerate interfaces: {}", result);
            }

            WlanCloseHandle(client_handle, ptr::null_mut());
        } else {
            println!("Failed to open WLAN handle: {}", result);
        }
    }
}



















    




