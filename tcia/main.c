#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <TCIMsg.h>

#define TIME_WAITING_TS 10
#define TCIA_PORT 13001

int main()
{
    bool connected_ts = false;
    int count_for_ts = 0;

    int sock_udp;
    struct sockaddr_in addr, client_addr;
    unsigned char recv_buffer[1024];
    unsigned char send_buffer[1024];
    int recv_len;
    int addr_len;

    if ((sock_udp = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket ");
        return 1;
    }

    memset(&addr, 0x00, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(TCIA_PORT);

    if (bind(sock_udp, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind ");
        return 1;
    }
    
    addr_len = sizeof(client_addr);

    while (true) {

        printf("Waiting for messages...\n");

        recv_len = recvfrom(sock_udp, recv_buffer, 1024, 0, (struct sockaddr*)&client_addr, &addr_len);

        printf("recv_len : %d\n", recv_len);

        if (recv_len < 0) {
            perror("recvfrom ");
            return 1;
        }

        printf("ip : %s\n", inet_ntoa(client_addr.sin_addr));
        printf("received data : ");
        for (int i = 0; i < recv_len; i++) {
            printf("%02x ", recv_buffer[i]);
        }

        //TCIMsg_t* tci_msg;

        //const asn_dec_rval_t rval = oer_decode(0, &asn_DEF_TCIMsg, &tci_msg, recv_buffer, recv_len);        

        printf("\n\n");

        //printf("version : %ld\n", tci_msg->version);
        //printf("time : %ld\n", tci_msg->time);
        //printf("frame : \n", tci_msg->frame.choice);

        printf("\n\n");

		//sendto(sock_udp, recv_buffer, strlen(recv_buffer), 0, (struct sockaddr*)&client_addr, sizeof(client_addr));
    }    


    while (TIME_WAITING_TS > count_for_ts) {
        sleep(1);
        count_for_ts++;
        printf("Waiting for TS : %d Second(s)\n", count_for_ts);
    }
    
    while (connected_ts) {
        printf("Not Reserved!");
    }

    if (!connected_ts) {
        printf("Try again to connect TS with SUT\n");
    }

    return 0;
}