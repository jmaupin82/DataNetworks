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


struct custom_ip_header {
    uint8_t version:4;
    uint8_t ihl:4;
    uint8_t type:8;
    uint16_t length:16;
    uint8_t tot_len:8;
    uint16_t identification:16;
    uint16_t fragmentation:16;
    uint8_t ttl:8;
    uint8_t protocol:8;
    uint16_t header_checksum:16;
    uint32_t source:32;
    uint32_t destination:32;
    uint32_t options:24;
    uint8_t padding:8;
};

struct custom_ip_header readIPInfo(FILE *fp)
{
    uint8_t buffer[3000];
    fread(buffer, 24, 1, fp);
    // cast all of the buffer info over the ip header struct
    // this performs
    struct custom_ip_header *result = (struct custom_ip_header*) buffer;
//    fread(result.version, 4, 1, fp);
//    fread(result.ihl, 4, 1, fp);
//    fread(result.type, 8, 1, fp);
//    fread(result.tot_len, 16, 1, fp);
    
    return *result;
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
    printf("IP:\t Total Length = %u bytes\n", header.tot_len);
    printf("IP:\t Identification = %u\n", header.identification);
    printf("IP:\t Flags   \n");
    printf("IP:\t\t .1.. .... = do not fragment\n");
    printf("IP:\t\t ..0. .... = last fragment\n");
    printf("IP:\t Fragment Offset = %u \n", header.fragmentation);
    printf("IP:\t Time to live = %u seconds/hops\n", header.ttl);
    printf("IP:\t Protocol  = %u \n", header.protocol);
    printf("IP:\t Header Checksum = %04x \n", header.header_checksum);
    printf("IP:\t Source Address = %u\n", header.source);
    printf("IP:\t Destination Address = %u\n", header.destination);
    printf("IP:\t No options\n");
    
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
        if (i % 2 == 1) {
            printf("%u\t", buffer[i]);

        } else if( i % 10 == 9){
            printf("%u\n", buffer[i]);
        } else {
            printf("%u", buffer[i]);

        }
    }
    fclose(fp);
    
    //loop over buffer printing out some interesting information
}
/*
    Method for reading the Ethernet Frame. 
    Parameters:
        filename     The string of the file
 */
void readEthernetInfo(char* filename)
{
    FILE *fp = fopen(filename, "r+");
    unsigned char preamble[7];
    unsigned char sfd;
    unsigned char destination[6];
    unsigned char source[6];
    unsigned char type;
    unsigned char type1;
    char *stringType;
    
    //get the total file size
    unsigned long bytelen = fsize(fp);
    
    //read info from the file
    fread(preamble, sizeof(preamble), 1, fp);
    fread(&sfd, sizeof(sfd), 1, fp);
    fread(destination, sizeof(destination), 1, fp);
    fread(source, sizeof(source), 1, fp);
    fread(&type, sizeof(type), 1, fp);
    type1 = ntohs(type);
    sprintf(stringType,"%04x", type);
    sfd = ntohs(sfd);

    //determine the ethertype string to print
    char *etherString = "UNKNOWN";
    if(strcmp(stringType, "0800") == 0)
        etherString = "IP";
    if(strcmp(stringType, "0806") == 0)
        etherString = "ARP";
    
    printf("ETHER: ------ ETHER HEADER ------\n");
    printf("ETHER: \n");
    printf("ETHER: Packet Size : %lu bytes\n", bytelen);
    printf("ETHER: Destination : %02x-%02x-%02x-%02x-%02x-%02x   Type : Individual Global \n",
           destination[0], destination[1], destination[2], destination[3], destination[4], destination[5]);
    printf("ETHER: Source : %02x-%02x-%02x-%02x-%02x-%02x   Type : Individual Global \n",
           source[0], source[1], source[2], source[3], source[4], source[5]);
    printf("ETHER: Ethertype    : %04x (%s) \n", type, etherString);
    printf("ETHER: \n\n");
    
    
    // do some sort of loop to read in all of the IP packets
    
    //call a function to also read the IP packet info in the MAC information
    struct custom_ip_header ip = readIPInfo(fp);
    //print the ip info
    printIPInfo(ip);
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



