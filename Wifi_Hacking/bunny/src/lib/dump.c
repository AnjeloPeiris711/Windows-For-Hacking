#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <string.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <windows.h>

#ifdef _WIN32
#include <tchar.h>
BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void print_packet_info(const u_char *bssid,int rssi,int beaconCount, int dataCount, const u_char *enc, const u_char *essid);
void setCursorPosition(int x, int y) {
    COORD coord;
    coord.X = x;
    coord.Y = y;

    SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), coord);
}

void red () {
  printf("\033[1;31m");
}

void green(){
	printf("\033[0;32m");
}

void reset () {
  printf("\033[0m");
}

static int beaconCount = 0, dataCount = 0;
// Structure to represent the pair of integer array and string
struct Pair {
    u_char bssidArray[6];
    u_char essidArray[32];
};

struct Pair myArray[5] = {{0}};

int test()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif


    /* Check command line */
    
	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
    
    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }
    
    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &inum);
    
    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
		
	/* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    
    
	/* Open the adapter */
	adhandle = pcap_create(d->name,errbuf);

    if (adhandle == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
     /* Check if monitor mode can be set */
    if (pcap_can_set_rfmon(adhandle) != 1) {
        fprintf(stderr, "\nMonitor mode cannot be set on this adapter.\n");
        pcap_perror(adhandle, "pcap_can_set_rfmon error");
        pcap_close(adhandle);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    pcap_set_snaplen(adhandle, 65536);
    pcap_set_promisc(adhandle, 0);
    pcap_set_timeout(adhandle, 512);

    /* Set monitor mode */
    if (pcap_set_rfmon(adhandle, 1) != 0) {
        fprintf(stderr, "\nError setting monitor mode on this adapter.\n");
        pcap_perror(adhandle, "pcap_can_set_rfmon error");
        pcap_close(adhandle);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

	/* Open the dump file */
    if (pcap_activate(adhandle) != 0) {
        fprintf(stderr, "Error activating pcap handle: %s\n", pcap_geterr(adhandle));
        // Handle error appropriately
    } else {
    
    printf("\nlistening on %s... Press Ctrl+C to stop...\n", d->description);
	
    /* At this point, we no longer need the device list. Free it */
    pcap_freealldevs(alldevs);

    system("cls");
	setCursorPosition(0, 1);
	green();
	fprintf(stdout,"%-20s %-3s %-5s %-8s %-8s %-s\n\n", "BSSID", "RSSI", "BEACON", "#Data", "ENC", "ESSID");
	reset();
	
    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_close(adhandle);
    return 0;
}
}
/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	// This struct is the RadioTap header: https://radiotap.org
	struct radiotap_header{ // RadioTap is the standard for 802.11 reception/transmission/injection
		uint8_t it_rev; // Revision: Version of RadioTap
		uint8_t it_pad; // Padding: 0 - Aligns the fields onto natural word boundaries
		uint16_t it_len;// Length: 26 - entire length of RadioTap header
	};
	// These are placeholders for offset values:
	const u_char *bssid; // a place to put our BSSID \ these are bytes
	const u_char *essid; // a place to put our ESSID / from the packet
	const u_char *essidLen;
	const u_char *channel;
	const u_char *rssi; // received signal strength
	const u_char *enc;
	const u_char *ENC;
	const u_char *Frame;

	int offset = 0;
	struct radiotap_header *rtaphdr;
	rtaphdr = (struct radiotap_header *) packet;
	offset = rtaphdr->it_len; // 26 bytes on my machine
	if(packet[offset]==0x80){// 0x80 is 128 in dec. It is a Beacon MGMT frame // REMOVED for BPF syntax
		beaconCount++;
		bssid = &packet[offset+10]; // store the BSSID/AP MAC addr, 36 byte offset is transmitter address
		essidLen = &packet[offset+37]; // store the ESSID length // this can be used to avoid looping bytes until >0x1 as below
		essid = &packet[offset+38]; // store the ESSID/Router name too
		rssi = packet + 22; // this is hex and this value is subtracted from 256 to get -X dbm.
		enc = &packet[offset+87];
		signed int rssiDbm = rssi[0] - 256;
		channel = packet + 18; // channel in little endian format (2 bytes)
		int channelFreq = channel[1] * 256 + channel[0]; // a little bit of math, remember little endian
		// 87 byte offset contains the "channel number" as per 802.11, e.g. 2412 = "channel 11"
		char *ssid = malloc(63); // 63 byte limit
		unsigned int i = 0; // used in loop below:
		while(essid[i] > 0x1){ // uncomment these to see each byte individually:
			ssid[i] = essid[i]; // store the ESSID bytes in *ssid
			i++; // POSTFIX
		}
		ssid[i] = '\0'; // terminate the string
		//returning authentication type only for beacon frames
		if (enc[0] == 48) {
        	ENC = "WPA2";
        }
        else{
        	ENC = "WPA";
        }
    //fprintf(stdout,"%02X:%02X:%02X:%02X:%02X:%02X    %-5i %-6d %-7d %-8s %-s\n",bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],rssiDbm,beaconCount,0,ENC,ssid);
	print_packet_info(bssid,rssiDbm,beaconCount,dataCount,ENC,ssid);
    //print_packet_info(bssid,rssiDbm,);    
	}else{
    	dataCount++;
    	//print_packet_info(NULL,NULL,NULL,dataCount,NULL,NULL)
    }  
    // fprintf(stdout,"%02X:%02X:%02X:%02X:%02X:%02X    %-5i %-6d %-7d %-8s %-s\n",bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],rssiDbm,beaconCount,dataCount,ENC,ssid);
}

void print_packet_info(const u_char *bssid,int rssi,const int beaconCount, int dataCount, const u_char *enc, const u_char *essid) {
    int duplicate = 0;

    for (int i = 0; i < 5; i++) {
        if (memcmp(myArray[i].bssidArray, bssid, 6) == 0 && strncmp((char*)myArray[i].essidArray, (char*)essid, strlen((char*)essid)) == 0) {
        duplicate = 1;
        setCursorPosition(0, 2+i);
        Sleep(500);
        fprintf(stdout, "%02X:%02X:%02X:%02X:%02X:%02X    %-5i %-6d %-7d %-8s %-s\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], rssi, beaconCount, dataCount, enc, essid);
        break;
    	}
    }

    if (!duplicate) {
        int emptySlot = -1;

        for (int i = 0; i < 5; i++) {
            if (myArray[i].bssidArray[0] == 0 && myArray[i].essidArray[0] == 0) {
                emptySlot = i;
                break;
            }
        }

        memcpy(myArray[emptySlot].bssidArray, bssid, 6);
        memcpy(myArray[emptySlot].essidArray, essid, 32);

    }

}