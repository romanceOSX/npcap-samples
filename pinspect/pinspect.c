//
// LibPcap inspection cli tool
//

#include <stdio.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if_dl.h>
#include <netinet/in.h>

#include <pcap.h>

#define PRINT_PRETTY(msg)       printf("-- %s --\n", msg)
#define PRINT_ERR(msg)          printf("/// %s ///\n", msg)

void printDevicesInfo(pcap_if_t *devlist) {
    pcap_if_t *d = devlist;
    pcap_addr_t *addr = NULL;
    const char *addr_str_p = NULL;
    const char *addr_fam_str_p = NULL;
    char ip4_addr_buf_str[INET_ADDRSTRLEN];
    char ip6_addr_buf_str[INET6_ADDRSTRLEN];
    
    PRINT_PRETTY("Printing available Network devices");

    while (NULL != d) {
        printf("Dev \"%s\"\n", d->name);
        if (d->description)
            printf("\tdesc: %s\n", d->description);
        addr = d->addresses;
       
        // print addresses
        while (NULL != addr) {
            switch (addr->addr->sa_family) {
                case AF_INET:
                    addr_str_p = inet_ntop(AF_INET, &((struct sockaddr_in *)addr->addr)->sin_addr, ip4_addr_buf_str, sizeof ip4_addr_buf_str);
                    addr_fam_str_p = "ip4";
                    break;
                case AF_INET6:
                    addr_str_p = inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr->addr)->sin6_addr, ip6_addr_buf_str, sizeof ip6_addr_buf_str);
                    addr_fam_str_p = "ip6";
                    break; 
                case AF_LINK:
                    addr_str_p = link_ntoa((struct sockaddr_dl *)addr->addr);
                    addr_fam_str_p = "eth";
                    break;
                default:
                    addr_str_p = "";
                    addr_str_p = "n/a";
            }

            if (NULL != addr_str_p)
                printf("\taddr(%s): %s\n",addr_fam_str_p, addr_str_p);

            addr = addr->next;
        }

        d = d->next;
    }
}

int parseArgs(int argc, char **argv) {
    if (argc < 2) {
        PRINT_ERR("Please provide the interface to open");
        return -1;
    }
    return 0;
}

int openDevs() {
    int res = 0;
    pcap_if_t *devlist = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    // initialize libpcap
    if (PCAP_ERROR == pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf)) {
        fprintf(stderr, "%s\n", errbuf);
        return -1;
    }

    // get all devices available
    if (PCAP_ERROR == pcap_findalldevs(&devlist, errbuf)) {
        fprintf(stderr, "%s\n", errbuf);
        return -1;
    }

    // print device's info
    printDevicesInfo(devlist);

    return res;
}

int main(int argc, char *argv[])
{
    printf("-- Npcap Inspector\n");
    openDevs();
    parseArgs(argc, argv);
    return 0;
}

