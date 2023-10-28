extern crate winapi;
extern crate pnet;
#[macro_use] extern crate prettytable;

use clap::{arg, command, ArgAction, Command};
use owo_colors::OwoColorize;
use prettytable::{Table, Row, Cell};
use prettytable::format;

use std::process::Command as PCommand;
use std::io;




// use pnet::datalink::{self, NetworkInterface,MacAddr};
use pnet::datalink;

mod components {
    pub mod crack;
    pub mod pcapformatter;
}
use components::crack::process_packets;
// mod components {
//     pub mod pcapformatter;
// }
const BUNNY_LOGO: &str = r#"

        (\_/)
        (. .) BUNNY!
       C('')('')
"#;

fn main() {
    let interfaces = datalink::interfaces();
    let match_result = command!() // requires `cargo` feature
        .about(BUNNY_LOGO)
        .arg(arg!(
            -i --interface ... "Identify Network interface"
        ).action(ArgAction::SetTrue))
        .arg(arg!(
            -t --test ... "test"
        ).action(ArgAction::SetTrue))
        .arg(arg!(
            -m --monmood ... "Enable monitor mood"
        ).action(ArgAction::SetTrue))
        // .arg(arg!(
        //     -c --crack [FILE] "crack the password"
        // ).action(ArgAction::SetTrue))
        .subcommand(
            Command::new("-C")
                .long_about("--Crack")
                .about("crack the password")
                .arg(arg!(-w --words [FILE] "path to wordlist(s) filename(s)").action(ArgAction::Set).required(true).value_name("FILE"))
                .arg(arg!(-p --pcap [FILE] "path to pcap(s) filename(s)").action(ArgAction::Set).required(true).value_name("FILE")),
        )
        .subcommand(
            Command::new("-I")
                .long_about("--Interface")
                .about("Select Interface")
                .arg(arg!(-I --Interface ... "Select Interface").action(ArgAction::SetTrue)),
        )
        .get_matches();
    let mut table = Table::new();
    let format = format::FormatBuilder::new()
        .column_separator(' ')
        .build();
    table.set_format(format);

    table.add_row(row![
        "Inter_ID",
        "Inter_Name",
        "Inter_Type",
        "Monitor_Mood"
    ]);
    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    if match_result.get_flag("interface"){
        let result = support_monitor_mood().unwrap();
        println!("");
        // for interface in interfaces {
        //     let monitor_mode_supported = supports_monitor_mode(&interface);
        //     println!("Name: {}", interface.name);
        //     println!("Description: {:?}", interface.description);
        //     println!("Monitor Mode Supported: {}", monitor_mode_supported);
        //     println!();
        // }
        for (i, interface) in interfaces.iter().enumerate() {
            let interface_type = infer_interface_type(&interface.description);
    
            // println!(
            //     "{} {} - {}",
            //     i + 1,
            //     // interface.name,
            //     interface.description,
            //     interface_type
            // );
            table.add_row(Row::new(vec![
                Cell::new(&format!("{:>3}", i + 1)),
                Cell::new(&format!(" {}",&interface.description)),
                Cell::new(&format!(" {}",&interface_type)),
                Cell::new(&format!(" {}",&result))
            ]));
        }
        table.printstd();
    }
        // Access other properties of the interface here.
    if match_result.get_flag("monmood"){
        println!("monmood");
        println!("My number is not {}!", 4.on_red());
        // support_monitor_mood().unwrap()
    } 
    // if match_result.get_flag("crack"){
    //     process_packets();
    //     // support_monitor_mood().unwrap()
    // } 
    if match_result.get_flag("test"){
        println!("test")
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

    // Continued program logic goes here...
}

fn support_monitor_mood() -> io::Result<String>{
    let output = PCommand::new("netsh")
    .args(&["wlan", "show", "wirelesscapabilities"])
    .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut found = false;
    let mut result = String::new();
    for line in stdout.lines() {
        // if line.contains("Interface name") || line.contains("monitor") {
        if line.contains("Network monitor mode"){
            // println!("{}", line);
            // result.push_str(line);
            if let Some(value) = line.split(':').nth(1) {
                let cleaned_value = value.trim();
                result = cleaned_value.to_string();
            }
            // result.push('\n');
            found = true;
        }
    }
    if !found {
        // println!("No matching lines found.");
        result.push_str("No matching lines found.");
    }
    Ok(result) 
}


fn infer_interface_type(description: &str) -> &str {
    if description.contains("Wi-Fi Direct Virtual Adapter") {
        "Local Area Connection"
    }else if description.contains("Wi-Fi") {
        "Wi-Fi"
    } else if description.contains("Family Controller") {
        "Ethernet"
    } else if description.contains("VPN") {
        "VPN"   
    } else {
        "Unknown"
    }
}
