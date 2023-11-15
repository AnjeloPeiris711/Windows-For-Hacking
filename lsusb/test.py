import win32com.client

# Initialize COM
wmi = win32com.client.GetObject('winmgmts:')
usb_devices = wmi.ExecQuery("SELECT * FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB%'")

# Function to extract the bus ID (VID & PID) from PNPDeviceID
def extract_id(pnp_device_id):
    parts = pnp_device_id.split("\\")
    for part in parts:
        if part.startswith("VID_") and "&PID_" in part:
            vid_pid = part.split("&")
            vendor_id = vid_pid[0][4:]
            product_id = vid_pid[1][4:]
            return f"{vendor_id}:{product_id}"
    return None

# Function to get more descriptive device name
def get_device_name(device):
    properties = device.Properties_
    for prop in properties:
        if prop.Name == "DeviceDesc":
            return prop.Value
    return device.Description

# Print header
print("{:<20} {:<20} {:<50}".format("BUSID", "VID:PID", "DEVICE NAME"))
print("")

# Enumerate and display USB device details with bus ID, descriptive device name, and the last part of PNPDeviceID
for device in usb_devices:
    ven_pro_ID = extract_id(device.PNPDeviceID)
    if ven_pro_ID:
        device_name = get_device_name(device)
        pnp_device_id_parts = device.PNPDeviceID.split("\\")
        bus_id = pnp_device_id_parts[-1]  # Get the last part of PNPDeviceID
        print("{:<20} {:<20} {:<50}".format(bus_id, ven_pro_ID, device_name))


