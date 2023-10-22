# import hashlib

# # Define the SSID and Wi-Fi passphrase
# ssid = "ASUS"
# passphrase = "hacktheplanet"

# # Convert the SSID and passphrase to bytes
# ssid_bytes = ssid.encode('utf-8')
# passphrase_bytes = passphrase.encode('utf-8')

# # Use PBKDF2 to derive the PMK
# pmk = hashlib.pbkdf2_hmac('sha1', passphrase_bytes, ssid_bytes, 4096, 32)

# # The PMK is a 32-byte (256-bit) key
# print("PMK (hex):", pmk.hex())
from Crypto.Cipher import AES
from hashlib import pbkdf2_hmac
from binascii import a2b_hex, b2a_hex

# Constants
SSID = "YourSSID"  # Replace with your network's SSID
PSK = "YourPSK"    # Replace with your pre-shared key
AP_MAC = a2b_hex("001122334455")  # Replace with the AP's MAC address
Client_MAC = a2b_hex("aabbccddeeff")  # Replace with the client's MAC address

ANonce = a2b_hex("00112233445566778899aabbccddeeff")
SNonce = a2b_hex("aabbccddeeff00112233445566778899")

# Derive the PMK
pmk = pbkdf2_hmac('sha1', PSK.encode(), SSID.encode(), 4096, 32)

# Concatenate and sort MAC addresses and nonces
concatenation_data = min(AP_MAC, Client_MAC) + max(AP_MAC, Client_MAC) + min(ANonce, SNonce) + max(ANonce, SNonce)

# Derive the PTK using HMAC-SHA1 as the PRF
ptk = pbkdf2_hmac('sha1', pmk, "Pairwise key expansion".encode(), 4096, 64)

# Split the PTK into individual keys
KCK = ptk[:16]
KEK = ptk[16:32]
TK = ptk[32:48]
MIC_TX = ptk[48:56]
MIC_RX = ptk[56:]

# Convert keys to hexadecimal strings
KCK_hex = b2a_hex(KCK).decode()
KEK_hex = b2a_hex(KEK).decode()
TK_hex = b2a_hex(TK).decode()
MIC_TX_hex = b2a_hex(MIC_TX).decode()
MIC_RX_hex = b2a_hex(MIC_RX).decode()

print("KCK:", KCK_hex)
print("KEK:", KEK_hex)
print("TK:", TK_hex)
print("MIC_TX:", MIC_TX_hex)
print("MIC_RX:", MIC_RX_hex)
