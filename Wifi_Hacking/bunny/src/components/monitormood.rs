extern crate winapi;


use std::ptr;
use winapi::shared::ntdef::NULL;
use winapi::um::wlanapi::*;
use winapi::um::winnt::HANDLE;
use winapi::um::wlanapi::WLAN_API_VERSION_2_0;
use winapi::shared::winerror::ERROR_SUCCESS;
use winapi::um::winnt::PVOID;
use winapi::shared::windot11::{
    DOT11_OPERATION_MODE_NETWORK_MONITOR,
    DOT11_OPERATION_MODE_EXTENSIBLE_STATION,
    DOT11_OPERATION_MODE_EXTENSIBLE_AP
};
use  winapi::shared::minwindef::DWORD;
use owo_colors::OwoColorize;
pub fn monitor_interface(
    interface_id : usize,
    mode_type: &str
    
){
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
            //let mut p_cap: *mut WLAN_INTERFACE_CAPABILITY = ptr::null_mut();
            let mut opcode_result: WLAN_OPCODE_VALUE_TYPE = std::mem::zeroed();
            let mut data_size: u32 = 0;
            let mut data: PVOID = ptr::null_mut();
            let reserved: PVOID = ptr::null_mut();
            let mood = match mode_type {
                "ExtSTA"=>DOT11_OPERATION_MODE_EXTENSIBLE_STATION,
                "NetMon"=>DOT11_OPERATION_MODE_NETWORK_MONITOR,
                "ExtAP"=>DOT11_OPERATION_MODE_EXTENSIBLE_AP,
                _=> {panic!("Unsupported mode type: {}", mode_type);}
            };
            // let mood: DWORD = DOT11_OPERATION_MODE_NETWORK_MONITOR;
            let result = WlanEnumInterfaces(
                client_handle,
                ptr::null_mut(),
                &mut interface_list,
            );

            if result == ERROR_SUCCESS {
                let interface_count = (*interface_list).dwNumberOfItems as usize;
                let interface_info_slice = 
                    std::slice::from_raw_parts((*interface_list).InterfaceInfo.as_ptr(), interface_count);
                if interface_id< interface_count{
                    let dw_result = WlanQueryInterface(
                        client_handle,
                        &interface_info_slice[interface_id].InterfaceGuid,
                        wlan_intf_opcode_current_operation_mode,
                        reserved,
                        &mut data_size,
                        &mut data,
                        &mut opcode_result as *mut _,
                        
                        
                    );
                    if dw_result == ERROR_SUCCESS{
                        let set_result = WlanSetInterface(
                            client_handle,
                            &interface_info_slice[interface_id].InterfaceGuid,
                            wlan_intf_opcode_current_operation_mode,
                            std::mem::size_of_val(&mood) as DWORD,
                            &mood as *const _ as PVOID,
                            reserved,
                        );
                        if set_result == ERROR_SUCCESS {
                            println!("{}","SetInterface success".green());
                        }
                        else{
                            println!("{} {}","SetInterface error, error code:".red(),set_result)
                        }
                    }else{
                        println!("{} {}","Failed to get Curent Interface:".red(), dw_result);
                    }
                    WlanFreeMemory(interface_list as *mut std::ffi::c_void);
                }else {
                    println!("{}","Invalid Interface ID".red())
                }
            } else {
                println!("{}{}","Failed to enumerate interfaces:".red(), result);
            }

            WlanCloseHandle(client_handle, ptr::null_mut());
        } else {
            println!("{}{}","Failed to open WLAN handle:".red(), result);
        }
    }
}

