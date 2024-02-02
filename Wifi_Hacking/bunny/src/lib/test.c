#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <windows.h>

#ifdef _WIN32
#include <tchar.h>

#define DEFAULT_FILTER "ether proto 0x888e or (type mgt subtype beacon)" // Beacon or Authentication

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
int packetCount = 0;
int test()
{
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int inum;
  int i=0;
  pcap_t *adhandle;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_dumper_t *dumpfile;
  char *filter = "eapol";

  int res;
  
  struct bpf_program fcode;
  bpf_u_int32 NetMask;
  
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

    if (filter != NULL)
    {
    // We should loop through the adapters returned by the pcap_findalldevs_ex()
    // in order to locate the correct one.
    //
    // Let's do things simpler: we suppose to be in a C class network ;-)
    NetMask=0xffffff;

    //compile the filter
    if((res = pcap_compile(adhandle, &fcode, filter, 1, NetMask)) < 0)
    {
      fprintf(stderr,"\nError compiling filter: %s\n", pcap_statustostr(res));

      pcap_close(adhandle);
      return -3;
    }

    //set the filter
    if((res = pcap_setfilter(adhandle, &fcode))<0)
    {
      fprintf(stderr,"\nError setting the filter: %s\n", pcap_statustostr(res));

      pcap_close(adhandle);
      return -4;
    }

  }

  dumpfile = pcap_dump_open(adhandle, "test.pcap");

  if(dumpfile==NULL)
  {
    fprintf(stderr,"\nError opening output file\n");
    return -1;
  }
    
    printf("\nlistening on %s... Press Ctrl+C to stop...\n", d->description);
  
    /* At this point, we no longer need the device list. Free it */
    pcap_freealldevs(alldevs);
    
    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, (unsigned char *)dumpfile);
    printf("Capture loop ended.\n");
    pcap_close(adhandle);
    return 0;
}
}
/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
  /* save the packet on the dump file */
  printf("packet count %d\n",packetCount);
  pcap_dump(dumpfile, header, pkt_data);
  packetCount++;
  if (packetCount >= 4) {
    printf("Packet capture stopped. Captured %d packets.\n", packetCount);
    Sleep(100);
    pcap_breakloop((pcap_t*)dumpfile);  // break out of the pcap_loop
  }
}



