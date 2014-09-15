//
//  main.c
//  DataNetworksProject1
//
//  Created by Joel Maupin on 8/27/14.
//  Copyright (c) 2014 ___JOELMAUPIN___. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

/*
    Calculate the byte size of a file.
    WARNING this function has no error handling and will crash your program if the file is not opened.
    Params: 
        fp - The file pointer to a file.
 
    Return:
        long representation of the number of bytes in the parameter file.
 */
long fsize(FILE *fp){
    long prev=ftell(fp);
    fseek(fp, 0L, SEEK_END);
    long sz=ftell(fp);
    fseek(fp,prev,SEEK_SET); //go back to beginning
    return sz;
}

struct ipv4_addr {
    uint8_t first;
    uint8_t second;
    uint8_t third;
    uint8_t fourth;
};

struct custom_ip_header {
    uint8_t version:4;
    uint8_t ihl:4;
    uint8_t type;
    uint16_t tot_len;
    uint16_t identification;
    uint16_t fragmentation;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    struct ipv4_addr source;
    struct ipv4_addr destination;
};

struct custom_ip_header readIPInfo(FILE *fp)
{
    uint8_t buffer[3000];
    fread(buffer, 20, 1, fp);
    // cast all of the buffer info over the ip header struct
    // this performs
    struct custom_ip_header *ip_header = (struct custom_ip_header*) buffer;
    //struct custom_ip_header *result = (struct custom_ip_header*) buffer;
    
    return *ip_header;
}

void printIPInfo(struct custom_ip_header header)
{
    printf("IP:\t----- IP Header -----\n");
    printf("IP:\t \n");
    printf("IP:\t Version = %u\n", header.version);
    printf("IP:\t Header Length = %u\n",header.ihl );
    printf("IP:\t Type of Service = 0x%02x \n", header.type);
    printf("IP:\t\t xxx. .... = 0 (precedence)\n");
    printf("IP:\t\t ...0 .... = normal delay\n");
    printf("IP:\t\t .... 0... = normal throughput\n");
    printf("IP:\t\t .... .0.. = normal reliability\n");
    printf("IP:\t Total Length = %u bytes\n", ntohs(header.tot_len));
    printf("IP:\t Identification = %u\n", ntohs(header.identification));
    printf("IP:\t Flags .%d%d. ....\n", header.fragmentation & 0x2000, header.fragmentation &0x4000);
    printf("IP:\t\t .1.. .... = do not fragment\n");
    printf("IP:\t\t ..0. .... = last fragment\n");
    printf("IP:\t Fragment Offset = %u \n", header.fragmentation);
    printf("IP:\t Time to live = %u seconds/hops\n", header.ttl);
    printf("IP:\t Protocol  = %u \n", header.protocol);
    printf("IP:\t Header Checksum = %04x \n", header.header_checksum);
    struct ipv4_addr source = header.source;
    struct ipv4_addr dest = header.destination;
    
    printf("IP:\t Source Address = %u.%u.%u.%u\n", source.first, source.second, source.third, source.fourth);
    printf("IP:\t Destination Address = %u.%u.%u.%u\n", dest.first, dest.second, dest.third, dest.fourth);
    printf("IP:\t No options\n");
    printf("IP:\t\n\n");
    
}

void dataDump(char* filename)
{
    // open the file and perform a data dump
    unsigned char buffer[9000];
    FILE *fp = fopen(filename, "r+");
    int file_len = (int) fsize(fp);
    //read all of the data into the buffer
    fread(buffer, file_len, 1, fp);
    for(int i = 0; i < file_len; ++i){
        //printf("hello");
        if (i % 2 == 1) {
            printf("%x ", buffer[i]);

        } else if( i % 10 == 9){
            printf("%x\n", buffer[i]);
        } else {
            printf("%x ", buffer[i]);

        }
    }
    fclose(fp);
    
    //loop over buffer printing out some interesting information
}

/*
 return the number of bytes read
 
 */
unsigned int readAllIPData(FILE *fp, unsigned long frame_len)
{
    //get the total length of the framefrom frame_len
    unsigned int byte_count = 0;
    //call a function to also read the IP packet info in the MAC information
    struct custom_ip_header ip_header = readIPInfo(fp);
    //read and print out the info
    //TODO format this properly
    //also skip over any of the extra data
    unsigned long extra = ntohs(ip_header.tot_len) - 20 + 16;
    byte_count = ntohs(ip_header.tot_len) + 16;
    //also add in the seperator (thats the 12)
    char buffer[extra];
    if(extra > 0){
        fread(buffer, extra, 1, fp);
    }
    
    printIPInfo(ip_header);
    //try printing out the buffer
    for(int i = 0; i < sizeof(buffer); ++i){
        printf("%u", buffer[i]);
    }
    printf("\n");
    return byte_count;
    
}

/*
    Method for reading the Ethernet Frame.
    Parameters:
        filename     The string of the file
 */
void readEthernetInfo(char* filename)
{
    FILE *fp = fopen(filename, "r+");
    int byte_count = 0;
    long total_len = fsize(fp);
    while (byte_count < total_len){
    
        unsigned char preamble[7];
        unsigned char sfd;
        unsigned char destination[6];
        unsigned char source[6];
        unsigned short type;
        unsigned short type1;
        
        //get the total file size
        unsigned long bytelen = fsize(fp);
        
        //read info from the file
        fread(preamble, sizeof(preamble), 1, fp);
        fread(&sfd, sizeof(sfd), 1, fp);
        fread(destination, sizeof(destination), 1, fp);
        fread(source, sizeof(source), 1, fp);
        fread(&type, sizeof(type), 1, fp);
        type1 = ntohs(type);
        sfd = ntohs(sfd);
        //determine the ethertype string to print
        char *etherString = "UNKNOWN";
        char *typeString = (char*)&type;
        if(strcmp(typeString, "0800") == 0)
            etherString = "IP";
        if(strcmp(typeString, "0806") == 0)
            etherString = "ARP";
        
        printf("ETHER: ------ ETHER HEADER ------\n");
        printf("ETHER: \n");
        printf("ETHER: Packet Size : %lu bytes\n", bytelen);
        printf("ETHER: Destination : %02x-%02x-%02x-%02x-%02x-%02x   Type : Individual Global \n",
               destination[0], destination[1], destination[2], destination[3], destination[4], destination[5]);
        printf("ETHER: Source : %02x-%02x-%02x-%02x-%02x-%02x   Type : Individual Global \n",
               source[0], source[1], source[2], source[3], source[4], source[5]);
        printf("ETHER: Ethertype    : %04x (%s) \n", type1, etherString);
        printf("ETHER: \n\n");
        byte_count = byte_count + readAllIPData(fp, bytelen) + 22;
        
        // do some sort of loop to read in all of the IP packets
        
    }
    //print the ip info
    //close the file
    fclose(fp);
}

int main(int argc, const char * argv[])
{
    char *filename = "/Users/joelmaupin/Documents/xcode/DataNetworksProject1/data/stream_in_session.bin";
    readEthernetInfo(filename);
    dataDump(filename);
    return 0;
    
}



