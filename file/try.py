import pyshark
import csv

# Open the pcap file for reading
cap = pyshark.FileCapture('test.pcapng', display_filter='usb.device_address==4')

# Open a CSV file for writing
with open('output.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)

    # Write the header row
    writer.writerow(['Timestamp', 'USB Address', 'Endpoint', 'Length', 'Data'])

    # Loop through each packet and extract relevant details
    for packet in cap:
        timestamp = packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f')
        usb_address = packet.usb.device_address
        endpoint = packet.usb.endpoint_address
        length = packet.length

        # Write the row to the CSV file
        writer.writerow([timestamp, usb_address, endpoint, length])
