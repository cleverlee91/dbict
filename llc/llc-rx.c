// Included Headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <math.h>
#include <stdbool.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <semaphore.h>
#include <pcap.h>

// UDP Header
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// ASN Header
#include <TCIMsg.h>

// Defined Constants
#define D_LOCAL D_ALL
#define LLC_RX_MAX_FRAME_SIZE 2100
#define TCIA_PORT 13001
#define TCI_VER 1
#define IEEE80211_ADDR_LEN 6
#define MAX_PACKET 160383

// LLC Header
#include <linux/cohda/llc/llc.h>
#include <linux/cohda/llc/llc-api.h>
#include "llc-plugin.h"
#include "debug-levels.h"

TCIMsg_t *_tci_msg;
TCI16093_t _dot3;
TCI80211_t _dot11;
TCI16094_t _dot4;
TCI29451_t _j2945;

Time64_t *_time64;

Dot3Indication_t  _dot3Ind;
Dot11Indication_t _dot11Ind;

asn_enc_rval_t er;

unsigned char send_buffer[1024];
struct sockaddr_in addr, client_addr;
int sock_udp;

// Defined Types
typedef struct LLCRx
{
    struct {
        int Argc;
        char **ppArgv;
    } Args;
    struct MKx *pMKx;
    int Fd;
    bool PrintMeta;
    bool PrintPayload;
    uint8_t Msg[sizeof(tMKxRxPacket) + LLC_RX_MAX_FRAME_SIZE];
    bool Exit;
} tLLCRx;
static int LLC_RxCmdInit (void);
static void LLC_RxCmdExit (void);
static int LLC_RxCmd (struct PluginCmd *pCmd, int Argc, char **ppArgv);
static int LLC_RxMain (int Argc, char **ppArgv);
void setTimeStamp(Time64_t *time64);

PLUGIN("rx", LLC_RxCmdInit, LLC_RxCmdExit);
static struct PluginCmd RxCmd = {
    .pName = "rx",
    .pHelp = (" Not Reserved !!!\n\n"),
    .Func = LLC_RxCmd,
};
static struct LLCRx _Dev = {
    .pMKx = NULL,
    .Exit = false,
};
static struct LLCRx *pDev = &(_Dev);

struct ieee80211_qosframe {
    uint8_t i_fc[2];
    uint8_t i_dur[2];
    uint8_t i_addr1[IEEE80211_ADDR_LEN];
    uint8_t i_addr2[IEEE80211_ADDR_LEN];
    uint8_t i_addr3[IEEE80211_ADDR_LEN];
    uint8_t i_seq[2];
    uint8_t i_qos[2];
};
struct wsm_waveInfo {
    uint8_t wsm_waveEleID;
    uint8_t wsm_waveEleLen;
    // uint8_t wsm_waveEleContents[];
};
struct wsmp_nHeader {
    uint8_t wsmp_general;
    uint8_t wsmp_countExt;
    // struct wsm_waveInfo _wsm_waveInfo[];
    uint8_t wsmp_tpid;
};
struct wsmp_tHeader {
    // uint8_t wsmp_psid[];
    // uint8_t wsmp_len[]; // 61p
};
struct wsm_llcdataframe {
    struct wsmp_nHeader _wsmp_nHeader;
    struct wsmp_tHeader _wsmp_tHeader;
    // uint8_t wsm_data[];
};
struct wsm_macdataframe {
    uint8_t wsm_llc[2];
    struct wsm_llcdataframe _wsm_llcdataframe;
};
struct ieee80211_qosframe *dot11pkHdr;

// Fucntions Definitions
static int LLC_RxCmdInit (void) {
    return Plugin_CmdRegister(&RxCmd);
}
static void LLC_RxCmdExit (void) {
    Plugin_CmdRegister(&RxCmd);
}
static int LLC_RxCmd (struct PluginCmd *pCmd, int Argc, char **ppArgv) {
    int Res;
    Res = LLC_RxMain(Argc, ppArgv);
    return Res;
}
static int LLC_RxUsage (void) {
    Plugin_CmdRegister(&RxCmd);
    return -EINVAL;
}
static void LLC_RxSignal (int SigNum) {
    d_printf(D_TST, NULL, "Signal %d!\n", SigNum);
    pDev->Exit = true;

    (void) MKx_Recv(NULL);
}
static void LLC_PrintPower(tMKxPower Power) {
    if (Power == MKX_POWER_RX_DISABLED) {
        printf(" ----- " );
    } else {
        printf("%4.1f", (float) Power/2.0);
    }
}

static void LLC_RxPrint (struct LLCRx *pDev, tMKxRxPacket *pMsg) {
    unsigned int i;
    if (pDev->PrintMeta == true) {
        printf("%c %01d %4d %2d %01d ",
            pMsg->RxPacketData.RadioID + 'A',
            pMsg->RxPacketData.ChannelID,
            pMsg->RxPacketData.RxFrameLength,
            pMsg->RxPacketData.MCS,
            pMsg->RxPacketData.FCSPass);
        LLC_PrintPower(pMsg->RxPacketData.RxPowerAnt1);
        LLC_PrintPower(pMsg->RxPacketData.RxPowerAnt2);
        LLC_PrintPower(pMsg->RxPacketData.RxNoiseAnt1);
        LLC_PrintPower(pMsg->RxPacketData.RxNoiseAnt2);
        printf("%7d ", pMsg->RxPacketData.RxFreqOffset);
        printf("0x%016" PRIx64 " ", pMsg->RxPacketData.RxTSF);
    }

    if (pDev->PrintPayload == true) {
        for (i = 0; i < pMsg->RxPacketData.RxFrameLength; i++) {
            printf("%02x", pMsg->RxPacketData.RxFrame[i]);
        }
    }

    printf("\n");
}
static tMKxStatus LLC_RxAlloc (struct MKx *pMKx, int BufLen, uint8_t **ppBuf, void **ppPriv) {
    int Res = MKXSTATUS_FAILURE_INTERNAL_ERROR;
    //d_fnstart(D_API, NULL, "(pMKx %p BufLen %d, ppBuf %p, ppPriv %p)\n", pMKx, BufLen, ppbuf, ppPriv);
    *ppBuf = malloc(BufLen);
    if (*ppBuf != NULL)
        Res = MKXSTATUS_SUCCESS;
    //d_fnend(D_API, NULL, "(pMKx %p bufLen %d, ppBuf %p, ppPriv %p) = %d\n", pMKx, BufLen, ppBuf, ppPriv, Res);
    return Res;
}
static tMKxStatus LLC_RxInd (struct MKx *pMKx, tMKxRxPacket *pMsg, void *pPriv) {
    int Res = 0;

    uint8_t *packet;
    _tci_msg = calloc(1, sizeof(TCIMsg_t));
    _time64 = calloc(1, sizeof(Time64_t));

    setTimeStamp(_time64);

    _tci_msg->version = TCI_VER;
    _tci_msg->time = *_time64;

    int packet_len = pMsg->RxPacketData.RxFrameLength;
    packet = calloc(1, packet_len);
    memcpy(packet, pMsg->RxPacketData.RxFrame, packet_len);

    dot11pkHdr = (struct ieee80211_qosframe *)packet;

    printf("\n\n");
    printf("!!! LLC Rx Data RECV !!!\n\n");
    printf("received data(dot11) : \n");
    for (int i = 0; i < sizeof(struct ieee80211_qosframe); i++)
    {
        printf("%02x ", packet[i]);
    }
    printf("\n\n");
    printf("received data(dot3) : \n");
    for (int i = sizeof(struct ieee80211_qosframe); i < packet_len; i++)
    {
        printf("%02x ", packet[i]);
    }
    printf("\n\n");

    packet += sizeof(struct ieee80211_qosframe);
    uint8_t *wsm_llc = calloc(1, 2);
    wsm_llc = (uint8_t *) packet;
    packet += 2;

    printf("%02x %02x\n", wsm_llc[0], wsm_llc[1]);

    xer_fprint(stdout, &asn_DEF_TCIMsg, _tci_msg);
    printf("\n\n");
    er = oer_encode_to_buffer(&asn_DEF_TCIMsg, 0, _tci_msg, send_buffer, sizeof(send_buffer));
    sendto(sock_udp, send_buffer, er.encoded, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
    return Res;
}

int LLC_RxInit (struct LLCRx *pDev) {
    int Res;
    pDev->Exit = false;
    signal(SIGINT, LLC_RxSignal);
    signal(SIGTERM, LLC_RxSignal);
    signal(SIGQUIT, LLC_RxSignal);
    signal(SIGHUP, LLC_RxSignal);
    signal(SIGPIPE, LLC_RxSignal);

    Res = MKx_Init(Plugin_DevId(), &(pDev->pMKx));
    if (Res < 0)
        goto Error;
    pDev->Fd = MKx_Fd(pDev->pMKx);

    pDev->pMKx->API.Callbacks.RxInd = LLC_RxInd;
    pDev->pMKx->API.Callbacks.RxAlloc = LLC_RxAlloc;
    pDev->pMKx->pPriv = (void *)pDev;

Error:
    if (Res != 0)
        LLC_RxUsage();
    return Res;
}
int LLC_RxExit (struct LLCRx *pDev) {
    int Res;
    (void) MKx_Recv(NULL);
    if (pDev->pMKx != NULL)
        MKx_Exit(pDev->pMKx);
    Res = 0;
    return Res;
}
static int LLC_RxMain (int Argc, char **ppArgv) {
    int Res;
#define RX_IF_MKX (0)
#define RX_IF_CNT (RX_IF_MKX + 1)
    struct pollfd FDs[RX_IF_CNT] = { {-1, } };
    pDev->Args.Argc = Argc;
    pDev->Args.ppArgv = ppArgv;

    Res = LLC_RxInit(pDev);
    if (Res < 0)
        goto Error;
    
    sock_udp =socket(AF_INET, SOCK_DGRAM, 0);
    memset(&addr, 0x00, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(TCIA_PORT);

    bind(sock_udp, (struct sockaddr *)&addr, sizeof(addr));
    int addr_len = sizeof(client_addr);

    FDs[RX_IF_MKX].fd = pDev->Fd;
    if (FDs[RX_IF_MKX].fd < 0)
        goto Error;

    pDev->PrintMeta = true;
    pDev->PrintPayload = false;

    int ArgIndex = 1;
    while (ArgIndex < pDev->Args.Argc) {
        char *pArgv = pDev->Args.ppArgv[ArgIndex];
        if (strcmp("-m", pArgv) == 0) {
            pDev->PrintMeta = true;
        } else if (strcmp("-p", pArgv) == 0) {
            pDev->PrintPayload = true;
        }
        ArgIndex++;
    }
    if (pDev->Args.Argc == 1) {
        pDev->PrintPayload = true;
    } else {
        pDev->PrintPayload = false;
    }

    const int POLL_INPUT = (POLLIN | POLLPRI);
    const int POLL_ERROR = (POLLERR | POLLHUP | POLLNVAL);
    FDs[RX_IF_MKX].events = POLL_INPUT;

    while (pDev->Exit == false) {
        int Data = poll(FDs, RX_IF_CNT, 1000);
        if (Data < 0) {
            Res = -errno;
            pDev->Exit = true;
        } else if (Data == 0) {
            continue;
        }

        if (FDs[RX_IF_MKX].revents & POLL_ERROR) {

        }

        if (FDs[RX_IF_MKX].revents & POLL_INPUT) {
            Res = MKx_Recv(pDev->pMKx);
        }
    }

Error:
    LLC_RxExit(pDev);
    if (FDs[RX_IF_MKX].fd >= 0)
        FDs[RX_IF_MKX].fd = -1;

    return Res;
}
void setTimeStamp(Time64_t *time64) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long long time_mil = tv.tv_sec * 1000LL + tv.tv_usec / 1000;
    asn_imax2INTEGER(time64, time_mil);
}
