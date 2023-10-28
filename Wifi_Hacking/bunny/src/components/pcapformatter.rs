
use std::fs::File;
use pcap_file::pcap::PcapReader;

#[derive(Debug)]
pub struct PcapData {
    pub ap_mac: String,
    pub cli_mac: String,
    pub a_nonce: String,
    pub s_nonce: String,
    pub mic1: String,
    pub data1: String,
    pub mic2: String,
    pub data2: String,
    pub mic3: String,
    pub data3: String,
}

pub fn formater(
    pfile_path: &str
) -> PcapData{
    // Replace with the path to your PCAP file.
    let file_in = File::open(pfile_path).expect("Error opening file");
    let mut pcap_reader = PcapReader::new(file_in).unwrap();
    let mut packet_count = 1;
    // Nonce (a,s)
    // Authenticator MAC (ap,cli)
    // The MIC (mic 1,2,3)
    // The entire 802.1x frame of the second handshake message with the MIC field set to all zeros(modified_data 1,2,3)
    // Iterate through the packets in the file.
    let mut ap_mac = String::new();
    let mut cli_mac = String::new();
    let mut a_nonce =String::new() ;
    let mut s_nonce = String::new();
    let mut mic1 = String::new();
    let mut mic2 = String::new();
    let mut mic3 = String::new();
    let mut data1 = String::new();
    let mut data2 = String::new();
    let mut data3 = String::new();

    while let Some(pkt) = pcap_reader.next_packet() {
        let pkt = pkt.unwrap(); // Unwrap the Result
        let pap_mac = hex::encode(&pkt.data[28..34]);
        // Station address: MAC of client
        let pcli_mac = hex::encode(&pkt.data[34..40]);
        let nonce = hex::encode(&pkt.data[73..105]);
        // let s_nonce = hex::encode(&pkt.data[73..105]);
        let pmic = hex::encode(&pkt.data[137..153]);
        // let mic2 = hex::encode(&pkt.data[137..153]);
        // let mic3 = hex::encode(&pkt.data[137..153]);
        let data_end = std::cmp::min(pkt.data.len() -4, pkt.data.len());
        let data = hex::encode(&pkt.data[56..data_end]);
        let modified_data = data.replace(&pmic, "00000000000000000000000000000000");
        // let modified_data2 = data.replace(&mic2, "00000000000000000000000000000000");
        // let modified_data3 = data.replace(&mic3, "00000000000000000000000000000000");
        match packet_count {
            1 => {
                // Process the first packet
                ap_mac = pap_mac;
                cli_mac = pcli_mac;
                a_nonce = nonce;
            }
            2 => {
                // Process the second packet
                s_nonce = nonce;
                mic1 = pmic;
                data1 = modified_data;
            }
            3 =>{
                // Process the thired packet
                mic2 = pmic;
                data2 = modified_data;
            }
            4 =>{
                // Process the fourth packet
                mic3 = pmic;
                data3 = modified_data;
            }
            _ => {
                // You can add more cases for additional packets if needed.
                println!("Wrong packet");
            }
        // println!("{}", hex::encode(&pkt.data[28..34]));
        
        }
        packet_count += 1;
    }
    // println!("AP MAC: {}", ap_mac);
    // println!("Client MAC: {}", cli_mac);
    // println!("A-Nonce: {}", a_nonce);
    // println!("S-Nonce: {}", s_nonce);
    // println!("MIC1: {}", mic1);
    // println!("Modified Data1: {}", data1);
    // println!("MIC2: {}", mic2);
    // println!("Modified Data2: {}", data2);
    // println!("MIC3: {}", mic3);
    // println!("Modified Data3: {}", data3);
    PcapData {
        ap_mac,
        cli_mac,
        a_nonce,
        s_nonce,
        mic1,
        data1,
        mic2,
        data2,
        mic3,
        data3,
    }
}

    