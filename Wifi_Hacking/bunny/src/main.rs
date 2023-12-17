extern crate winapi;

use std::ptr;
use winapi::shared::ntdef::NULL;
use winapi::um::wlanapi::*;
use winapi::um::winnt::HANDLE;
use winapi::um::wlanapi::WLAN_API_VERSION_2_0;
use winapi::shared::winerror::ERROR_SUCCESS;
// extern crate pnet;
#[macro_use] extern crate prettytable;

use clap::{arg, command, ArgAction, Command};
use owo_colors::OwoColorize;
use prettytable::{Table, Row, Cell};
use prettytable::format;

use std::process::Command as PCommand;
use std::io;
extern crate pcap;






// use pnet::datalink::{self, NetworkInterface,MacAddr};
// use pnet::datalink;

mod components {
    pub mod crack;
    pub mod pcapformatter;
    pub mod dump;
    // pub mod monitormood;
}
use components::crack::process_packets;
use components::dump::packet_dump;
// use components::monitormood::monitor_intrface;
// mod components {
//     pub mod pcapformatter;
// }
const BUNNY_LOGO: &str = r#"

        (\_/)
        (. .) BUNNY!
       C('')('') 0.1.0
"#;

fn main() {
    let colored_logo = BUNNY_LOGO.bright_yellow().to_string();
    let match_result = command!() // requires `cargo` feature
        .about(colored_logo)
        .arg(arg!(
            -i --interface ... "Identify Network interface"
        ).action(ArgAction::SetTrue))
        .arg(arg!(
            -t --test ... "test"
        ).action(ArgAction::SetTrue))
        .arg(arg!(
            -m --monmood ... "Enable monitor mood"
        ).action(ArgAction::SetTrue))
        .arg(arg!(
            -d --dump ... "Dump the Packets"
        ).action(ArgAction::SetTrue))
        .subcommand(
            Command::new("-C")
                .long_about("--Crack")
                .about("crack the password")
                .arg(arg!(-w --words [FILE] "path to wordlist(s) filename(s)").action(ArgAction::Set).required(true).value_name("FILE"))
                .arg(arg!(-p --pcap [FILE] "path to pcap(s) filename(s)").action(ArgAction::Set).required(true).value_name("FILE")),
        )
        .subcommand(
            Command::new("-D")
                .long_about("--Dump")
                .about("Dump Packets")
                .arg(arg!(-i --interface [int_name] "Select Inteface to dump the packets").action(ArgAction::Set).required(true).value_name("int_name"))
                .arg(arg!(-f --file [FILE] "path to pcap(s) filename(s)").action(ArgAction::Set).required(true).value_name("FILE")),
        )
        .get_matches();
    let mut table = Table::new();
    let format = format::FormatBuilder::new()
        .column_separator(' ')
        .build();
    table.set_format(format);

    table.add_row(row![
        "Inter_ID".green(),
        "      Inter_Name".green(),
        "          Inter_GUID".green(),
        "  Monitor_Mood".green()
    ]);
    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    if match_result.get_flag("interface"){
        let monresults = support_monitor_mood().unwrap();
        println!("");
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
                        table.add_row(Row::new(vec![
                            Cell::new(&format!("{:>3}", i + 1)),
                            // Cell::new(&format!(" {}",&interface.description)),
                            Cell::new(&format!(" {}",&description)),
                            Cell::new(&format!(" {:x}-{:x}-{:x}-{:x?}",&interface_info.InterfaceGuid.Data1, interface_info.InterfaceGuid.Data2, interface_info.InterfaceGuid.Data3, interface_info.InterfaceGuid.Data4)),
                            Cell::new(&format!(" {}",&monresults[i]))
                        ]));
                    }
    
                    WlanFreeMemory(interface_list as *mut _);
                    //WlanFreeMemory(p_cap as *mut std::ffi::c_void);
                } else {
                    println!("Failed to enumerate interfaces: {}", result);
                }
    
                WlanCloseHandle(client_handle, ptr::null_mut());
            } else {
                println!("Failed to open WLAN handle: {}", result);
            }
        }
        table.printstd();
        println!("");

    }
        // Access other properties of the interface here.
    if match_result.get_flag("monmood"){
        println!("nathing")
        // match monitor_interface("eth0") {
        //     Ok(()) => println!("Interface monitoring successful."),
        //     Err(err) => eprintln!("Error: {}", err),
        // }
        // println!("My number is not {}!", 4.on_red());
        // support_monitor_mood().unwrap()
    } 
    // if match_result.get_flag("crack"){
    //     process_packets();
    //     // support_monitor_mood().unwrap()
    // } 
    if match_result.get_flag("dump"){
       
        // let filename = "captured.pcap";
        // if let Err(e) = packet_dump(filename) {
        // eprintln!("Error: {:?}", e);
        packet_dump();
    } 
    if let Some(match_result) = match_result.subcommand_matches("-C") {
        // "$ myapp test" was run
        if let Some(wfile_path) = match_result.get_one::<String>("words") {
            if let Some(pfile_path) = match_result.get_one::<String>("pcap"){
                process_packets(wfile_path,pfile_path);
            }
            else{
                println!("{}",BUNNY_LOGO);
                println!("{}","You used the -p flag, but didn't provide a file path".red());
            }
        } else {
            println!("{}",BUNNY_LOGO);
            println!("{}","You used the -w flag, but didn't provide a file path".red());
        }
    }
    if let Some(match_result) = match_result.subcommand_matches("-D"){
        println!("test");
        if let Some(int_name) = match_result.get_one::<String>("interface") {
            if let Some(file_path) = match_result.get_one::<String>("file"){
               println!("{},{}",int_name,file_path)
            }
            else{
                println!("one");
                
            }
        } else {
            println!("Dump");
            
        }
    }
    // Continued program logic goes here...
}
// fn support_monitor_mood() -> io::Result<String>{
fn support_monitor_mood() -> io::Result<Vec<String>> {   
    let output = PCommand::new("netsh")
    .args(&["wlan", "show", "wirelesscapabilities"])
    .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut found = false;
    // let mut result = String::new();
    let mut result = Vec::new();
    for line in stdout.lines() {
        // if line.contains("Interface name") || line.contains("monitor") { 
        if line.contains("Network monitor mode"){
            // result.push_str(line);
            if let Some(value) = line.split(':').nth(1) {
                // let cleaned_value = value.trim();
                // result = cleaned_value.to_string();
                let cleaned_value = value.trim().to_string();
                result.push(cleaned_value);
               
            }
            // result.push('\n');
            found = true;
        }
    }
    if !found {
        // println!("No matching lines found.");
        result.push("No matching lines found.".to_string());
        // result.push_str("No matching lines found.");
        
    }
    Ok(result) 
}



