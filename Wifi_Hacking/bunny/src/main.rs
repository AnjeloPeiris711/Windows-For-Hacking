extern crate winapi;
extern crate pnet;

use clap::{arg, command, ArgAction, Command};
use owo_colors::OwoColorize;
use pnet::datalink::{self, NetworkInterface,MacAddr};

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
            -m --monmood ... "Enable monitor mood"
        ).action(ArgAction::SetTrue))
        .subcommand(
            Command::new("-C")
                .long_about("--chek")
                .about("Chek")
                .arg(arg!(-d --debug ... "Identify Network interface").action(ArgAction::SetTrue)),
        )
        .get_matches();
    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    if match_result.get_flag("interface"){
        println!("");
        for interface in interfaces {
            let monitor_mode_supported = supports_monitor_mode(&interface);
            println!("Name: {}", interface.name);
            println!("Description: {:?}", interface.description);
            println!("Monitor Mode Supported: {}", monitor_mode_supported);
            println!();
        }
    }
        // Access other properties of the interface here.
    if match_result.get_flag("monmood"){
        println!("monmood");
        println!("My number is not {}!", 4.on_red());
    } 
    if let Some(match_result) = match_result.subcommand_matches("-C") {
        // "$ myapp test" was run
        if match_result.get_flag("debug") {
            // "$ myapp test -l" was run
            println!("Printing testing lists...");
        } else {
            println!("Not printing testing lists...");
        }
    }

    // Continued program logic goes here...
}

fn supports_monitor_mode(interface: &NetworkInterface) -> bool {
    // Check if the interface's MAC address is a broadcast address, which is often used to indicate monitor mode support
    if let Some(mac) = interface.mac {
        return mac == MacAddr::broadcast();
    }
    false
}


