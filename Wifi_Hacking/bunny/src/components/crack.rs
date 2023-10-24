extern crate ring;
use ring::{pbkdf2, hmac};
// static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA1;
use md5::{Md5, Digest};
use hex;
use std::num::NonZeroU32;

use std::thread;
use std::time::Duration;

use indicatif::{ProgressBar,ProgressStyle,MultiProgress};


pub fn process_packets(){
    //Read a file of passwords containing
    //passwords separated by a newline
    let passwordlist: Vec<String> = std::fs::read_to_string("passwd.txt")
        .expect("Failed to read file")
        .lines()
        .map(String::from)
        .collect();
    //SSID name
    let ssid = "Coherer";
    // ANonce
    let a_nonce = hex::decode("3e8e967dacd960324cac5b6aa721235bf57b949771c867989f49d04ed47c6933").expect("Failed to decode ANonce");
    // SNonce
    let s_nonce = hex::decode("cdf405ceb9d889ef3dec42609828fae546b7add7baecbb1a394eac5214b1d386").expect("Failed to decode SNonce");
    // Authenticator MAC (AP)
    let ap_mac = hex::decode("000d9382363a").expect("Failed to decode Authenticator MAC");
    // Station address: MAC of client
    let cli_mac = hex::decode("000c4182b255").expect("Failed to decode Client MAC");
    // The first MIC
    let mic1 = "a462a7029ad5ba30b6af0df391988e45";
    // The entire 802.1x frame of the second handshake message with the MIC field set to all zeros
    let data1 = hex::decode("0203007502010a00100000000000000000cdf405ceb9d889ef3dec42609828fae546b7add7baecbb1a394eac5214b1d386000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac020100000fac040100000fac020000")
    .expect("Failed to decode Data1");
    // The second MIC
    let mic2 = "7d0af6df51e99cde7a187453f0f93537";
    // The entire 802.1x frame of the third handshake message with the MIC field set to all zeros
    let data2 = hex::decode("020300af0213ca001000000000000000013e8e967dacd960324cac5b6aa721235bf57b949771c867989f49d04ed47c6933f57b949771c867989f49d04ed47c6934cf020000000000000000000000000000000000000000000000000000000000000050cfa72cde35b2c1e2319255806ab364179fd9673041b9a5939fa1a2010d2ac794e25168055f794ddc1fdfae3521f4446bfd11da98345f543df6ce199df8fe48f8cdd17adca87bf45711183c496d41aa0c")
    .expect("Failed to decode Data2");
    // The third MIC
    let mic3 = "10bba3bdfbcfde2bc537509d71f2ecd1";
    // The entire 802.1x frame of the forth handshake message with the MIC field set to all zeros
    let data3 = hex::decode("0203005f02030a0010000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    .expect("Failed to decode Data2");
    // Run an offline dictionary attack against the access point
    test_pwds(passwordlist, ssid, &a_nonce, &s_nonce, &ap_mac, &cli_mac, &data1, &data2, &data3, mic1, mic2, mic3);
}

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

// fn make_ab(a_nonce: &[u8], s_nonce: &[u8], ap_mac: &[u8], cli_mac: &[u8]) -> ([u8; 32], [u8; 32]) {
//     let mut a = [0; 32];
//     let mut b = [0; 32];

//     let a_data = b"Pairwise key expansion";

//     for i in 0..a_data.len() {
//         a[i] = a_data[i];
//     }

//     let b_data = [
//         &ap_mac[..6], &cli_mac[..6],
//         &ap_mac[6..12], &cli_mac[6..12],
//         &a_nonce, &s_nonce,
//     ];

//     for i in 0..b_data.len() {
//         for j in 0..b_data[i].len() {
//             b[i * 6 + j] = b_data[i][j];
//         }
//     }

//     (a, b)
// }
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
    let (a, b) = make_ab(a_nonce, s_nonce, ap_mac, cli_mac);
    let pb = ProgressBar::new(passwordlist.len() as u64);
    pb.set_style(ProgressStyle::with_template("{wide_msg}")
        .unwrap());
    // Loop over each password and test each one
    for password in &passwordlist {
        let (mic, _, _) = make_mic(password, ssid, &a, &b, data1, true);
        let v = hex::encode(&mic[..16]);
        pb.set_message(format!("{password}: {v}"));
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
        pb.finish();
        return;
    }
    pb.finish();
}
