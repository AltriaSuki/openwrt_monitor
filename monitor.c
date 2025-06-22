#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <errno.h>

char _ipaddr[INET6_ADDRSTRLEN];
char _macaddr[18]; // MAC address format is XX:XX:XX:XX:XX:XX

void get_ip_info(const char* ifname,char *ipaddr) {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || strcmp(ifa->ifa_name, ifname) != 0)
            continue;

        int family = ifa->ifa_addr->sa_family;

        if (family == AF_INET) {
            // IPv4
            char addr[INET_ADDRSTRLEN];
            struct sockaddr_in* sa = (struct sockaddr_in*)ifa->ifa_addr;
            inet_ntop(AF_INET, &(sa->sin_addr), addr, sizeof(addr));
            strcpy(ipaddr, addr);
        } else if (family == AF_INET6) {
            // IPv6
            char addr[INET6_ADDRSTRLEN];
            struct sockaddr_in6* sa6 = (struct sockaddr_in6*)ifa->ifa_addr;
            inet_ntop(AF_INET6, &(sa6->sin6_addr), addr, sizeof(addr));
            strcpy(ipaddr, addr);
        }
    }

    freeifaddrs(ifaddr);
}


void get_mac_info(const char* ifname, char *macaddr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        return;
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
        sprintf( macaddr,"%02x:%02x:%02x:%02x:%02x:%02x\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        perror("ioctl");
    }

    close(fd);
}


void handle_ethernet_packet(const u_char*pkt_data,int pkt_len){
    struct ethhdr *eth_header = (struct ethhdr *)pkt_data;
    char src_mac[18], dst_mac[18];
    snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_header->h_source[0], eth_header->h_source[1],
             eth_header->h_source[2], eth_header->h_source[3],
             eth_header->h_source[4], eth_header->h_source[5]);
    snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_header->h_dest[0], eth_header->h_dest[1],
             eth_header->h_dest[2], eth_header->h_dest[3],
             eth_header->h_dest[4], eth_header->h_dest[5]);
}

void handle_raw_ip_packet(const u_char*pkt_data,int pkt_len){
    struct iphdr *ip_header = (struct iphdr *)pkt_data;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_header->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip_header->daddr, dst_ip, sizeof(dst_ip));

    printf("Source IP: %s\n", src_ip);
    printf("Destination IP: %s\n", dst_ip);
    if(strcmp(src_ip,_ipaddr)==0){
        //说明是本机发出的包
        printf("%s    =>    %s\n",src_ip, dst_ip);
    }else{
        //说明是本机接收的包
        printf("%s    <=    %s\n",src_ip, dst_ip);
    }
}

void handle_packet(const u_char*pkt_data, int pkt_len,int linktype) {
    switch (linktype) {
        case DLT_EN10MB:
            handle_ethernet_packet(pkt_data, pkt_len);
            break;
        case DLT_RAW:
            handle_raw_ip_packet(pkt_data, pkt_len);
            break;
        default:
            fprintf(stderr, "Unsupported link type: %d\n", linktype);
            return;
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    int *linktype = (int*)user;
    handle_packet(packet, header->len, *linktype);
}


int main(int argc, char *argv[]){
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;//待修改为可以输入的dev,现在是hardcoded为"wlp43s0"
    printf("Enter the network interface name: ");
    scanf("%s", dev);
    int snaplen = 65535;
    int promisc = 1;
    int to_ms = 1000;
    pcap_t *handle = pcap_open_live(dev,snaplen,promisc,to_ms,errbuf);
    if(handle == NULL) {
        perror("pcap_open_live");
        fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
        return 1;
    }
    int linktype = pcap_datalink(handle);
    printf("Link type: %s\n", pcap_datalink_val_to_name(linktype));

    get_ip_info(dev, _ipaddr);
    get_mac_info(dev, _macaddr);
    printf("IP Address: %s\n", _ipaddr);
    printf("MAC Address: %s\n", _macaddr);
    pcap_loop(handle, -1, packet_handler, (u_char*)&linktype);

}