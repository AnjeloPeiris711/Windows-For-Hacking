extern crate ring;
use ring::{pbkdf2,hmac,digest};
use std::num::NonZeroU32;


pub fn process_packets() {
    let ssid = "ASUS";
    let passphrase = "hacktheplanet";

    // Convert the SSID and passphrase to bytes
    let ssid_bytes = ssid.as_bytes();
    let passphrase_bytes = passphrase.as_bytes();

    // Create a buffer to store the derived PMK
    let mut pmk = [0u8; 32];
    // Perform PBKDF2-HMAC key derivation
    let iterations = NonZeroU32::new(4096).expect("NonZeroU32");
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA1,
        iterations,
        ssid_bytes,
        passphrase_bytes,
        &mut pmk,
    );

    // The PMK is a 32-byte (256-bit) key
    let formatted_pmk = format_pmk(&pmk);

    // Print the formatted PMK
    println!("PMK (formatted): {}", formatted_pmk);

}
fn format_pmk(pmk: &[u8; 32]) -> String {
    let mut formatted_pmk = String::with_capacity(3 * 32); // Space-separated, 2 characters per byte

    for byte in pmk.iter() {
        formatted_pmk.push_str(&format!("{:02X} ", byte)); // Format as uppercase hexadecimal with leading zero
    }

    formatted_pmk.pop(); // Remove the trailing space

    formatted_pmk
}