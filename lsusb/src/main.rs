#[macro_use] extern crate prettytable;
use owo_colors::OwoColorize;
use prettytable::{Table, Row, Cell};
use prettytable::format;
use usb_ids::{self, FromId};

fn main() {
    let mut table = Table::new();
    let format = format::FormatBuilder::new()
        .column_separator(' ')
        .build();
    table.set_format(format);

    table.add_row(row![
        "Bus ID".green(),
        "  VID:PID".green(),
        "         DEVICE".green()
  
    ]);
    for device in rusb::devices().unwrap().iter() {
        let device_desc = device.device_descriptor().unwrap();

        let vendor_name = match usb_ids::Vendor::from_id(device_desc.vendor_id()) {
            Some(vendor) => vendor.name(),
             None => "Unknown vendor",
        };
        if let Some(index) = device_desc.product_string_index() {
            table.add_row(Row::new(vec![
                Cell::new(&format!(" {}-{}",index,&device.port_number())),
                Cell::new(&format!(" {:04x}:{:04x}",&device_desc.vendor_id(),&device_desc.product_id())),
                Cell::new(&format!(" {}",&vendor_name))
            ]));
        }
    }

    table.printstd();

}




