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

TCIMsg_t *tci_msg;
TCIMsg_t *_tci_msg;
TCI16093_t _dot3;
TCI80211_t _dot11;
TCI16094_t _dot4;
TCI29451_t _j2945;

Time64_t *_time64;

Dot3Indication_t  _dot3Ind;
Dot11Indication_t _dot11Ind;
Indication_t _commonInd;

StartWsmRx_t _startWsmRx;
EventParams_t _eventParams;
WsmParameters_t _wsmParameters;
Pdu_t _pdu;
Psid_t *_psid;

asn_dec_rval_t dec_rval;
asn_enc_rval_t enc_rval;

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
struct ieee80211_qosframe *dot11pkHdr;

// Fucntions Definitions
static int LLC_RxCmdInit (void) {
    FILE *fp;
    fp = fopen("startRx", "r");
    fseek(fp, 0, SEEK_END);
    int size = ftell(fp);
    uint8_t *test = calloc(1, size);
    rewind(fp);
    fread(test, size, 1, fp);
    fclose(fp);
    dec_rval = oer_decode(0, &asn_DEF_TCIMsg, (void **)&tci_msg, test, size);
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
    *ppBuf = malloc(BufLen);
    if (*ppBuf != NULL)
        Res = MKXSTATUS_SUCCESS;
    return Res;
}
static tMKxStatus LLC_RxInd (struct MKx *pMKx, tMKxRxPacket *pMsg, void *pPriv) {
    
    int Res = 0;

    uint8_t *packet;
    int packet_len = pMsg->RxPacketData.RxFrameLength;
    int start_dot11frame = 0;
    int start_dot3frame = 0;
    int start_dot2data = 0;
    // start_dot3payload, start_ipv6payload
    packet = calloc(1, packet_len);
    memcpy(packet, pMsg->RxPacketData.RxFrame, packet_len);

    printf("\n\n");
    printf("!!! LLC Rx Data RECV !!!\n\n");

    printf("recieved len : %d\n", packet_len);
    printf("recieved data : ");

    for (int i = 0; i < pMsg->RxPacketData.RxFrameLength; i++)
    {
        printf("%02x ", pMsg->RxPacketData.RxFrame[i]);
    }

    printf("\n\n");

    dot11pkHdr = (struct ieee80211_qosframe *)packet;

    packet += sizeof(struct ieee80211_qosframe);
    packet_len -= sizeof(struct ieee80211_qosframe);

    start_dot3frame = pMsg->RxPacketData.RxFrameLength - packet_len;

    uint8_t *wsm_llc = calloc(1, 2);
    uint8_t *wsmp_general = calloc(1, 1);
    uint8_t *wsmp_countExt = calloc(1, 1);
    uint8_t *wsmp_psid;
    uint8_t *wsmp_tpid = calloc(1, 1);
    uint8_t *wsmp_wsmLen;

    uint8_t *ext_test = calloc(1, 1);

    wsm_llc = (uint8_t *) packet;
    packet += 2;
    packet_len -= 2;

    wsmp_general = (uint8_t *) packet;
    packet += 1;
    packet_len -= 1;

    if (*wsmp_general == 0x0b) {
        wsmp_countExt = (uint8_t *)packet;
        packet += 1;
        packet_len -= 1;

        uint8_t cnt_waveInfo = *wsmp_countExt;
        uint8_t **pp_wsm_waveEleContents = NULL;

        for (int i = 0; i < cnt_waveInfo; i++) {
            uint8_t *wsm_waveEleContent = calloc(1, packet[1]);
            switch(packet[0]) {
                case 0x0f:

                    break;
                case 0x0e:
                    break;
                case 0x04:
                    break;
            }
            wsm_waveEleContent = (uint8_t *) (packet + 2);
            pp_wsm_waveEleContents = (uint8_t **) wsm_waveEleContent;
            packet_len = packet_len - packet[1] - 2;
            packet = packet + packet[1] + 2;
            pp_wsm_waveEleContents++;
        }
    }

    wsmp_tpid = (uint8_t *)packet;
    packet++;
    packet_len -= 1;

    ext_test = (uint8_t *)packet;
    int psid_len = 0;

    if(*ext_test / 16 < 8) {
        wsmp_psid = calloc(1, 1);
        wsmp_psid = (uint8_t *) packet;
        psid_len = 1;
        packet += psid_len;
        packet_len -= psid_len;
    } else if (*ext_test / 16 < 11) {
        wsmp_psid = calloc(1, 2);
        wsmp_psid = (uint8_t *)packet;
        psid_len = 2;
        packet += psid_len;
        packet_len -= psid_len;
    } else if (*ext_test / 16 < 14) {
        wsmp_psid = calloc(1, 3);
        wsmp_psid = (uint8_t *)packet;
        psid_len = 3;
        packet += psid_len;
        packet_len -= psid_len;
    } else {
        wsmp_psid = calloc(1, 4);
        wsmp_psid = (uint8_t *)packet;
        psid_len = 4;
        packet += psid_len;
        packet_len -= psid_len;
    }

    ext_test = (uint8_t *)packet;

    if(*ext_test > 0x7f) {
        wsmp_wsmLen = calloc(1, 2);
        wsmp_wsmLen = (uint8_t *) packet;
        packet += 2;
        packet_len -= 2;
    } else {
        wsmp_wsmLen = calloc(1, 1);
        wsmp_wsmLen = (uint8_t *)packet;
        packet += 1;
        packet_len -= 1;
    }

    start_dot2data = pMsg->RxPacketData.RxFrameLength - packet_len;

    _tci_msg = calloc(1, sizeof(TCIMsg_t));
    _time64 = calloc(1, sizeof(Time64_t));

    setTimeStamp(_time64);

    _tci_msg->version = TCI_VER;
    _tci_msg->time = *_time64;

    switch (tci_msg->frame.present) {

        case Frame_PR_d16093:
            break;

        case Frame_PR_d80211:
            _startWsmRx = tci_msg->frame.choice.d80211.choice.request.value.choice.StartWsmRx;

            int buf_size = _startWsmRx.eventHandling.eventFlag->size;
            int bit_unused = _startWsmRx.eventHandling.eventFlag->bits_unused;
            int bit_leng = buf_size * 8 - bit_unused;
            long rxFlag = 0;
            long tmpFlag = 0;
            
            for (int i = 0; i < buf_size; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    if ((*(_startWsmRx.eventHandling.rxFlag->buf + i) << j) & 128)
                    {
                        tmpFlag = bit_leng - ((buf_size - i) * 8 - j - bit_unused);
                        if (tmpFlag < 3)
                            rxFlag |= (1 << tmpFlag);
                        else
                            printf("\n\n!!!! out of rxFlag !!!!\n\n");
                    }
                }
            }

            buf_size = _startWsmRx.eventHandling.eventFlag->size;
            bit_unused = _startWsmRx.eventHandling.eventFlag->bits_unused;
            bit_leng = buf_size * 8 - bit_unused;
            long eventFlag = 0;
            
            for (int i = 0; i < buf_size; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    if ((*(_startWsmRx.eventHandling.eventFlag->buf + i) << j) & 128)
                    {
                        eventFlag = bit_leng - ((buf_size - i) * 8 - j - bit_unused);
                        if (eventFlag < 5)
                        {
                            asn_long2INTEGER(&_dot11Ind.event, eventFlag + 1);
                        }
                        else
                            printf("\n\n!!!! out of eventFlag !!!!\n\n");
                    }
                }
            }

            long _eventParamsChoice = 0;
            asn_INTEGER2long(_startWsmRx.eventHandling.eventParamsChoice, &_eventParamsChoice);

            switch (_eventParamsChoice) {

                case EventParamsChoice_service:
                    _eventParams.present = EventParams_PR_service;
                    break;

                case EventParamsChoice_wsm:
                    _eventParams.present = EventParams_PR_wsm;
                    _psid = (Psid_t *) _startWsmRx.psid;
                    _wsmParameters.psid = *_psid;
                    _wsmParameters.radio = _startWsmRx.radio;
                    _wsmParameters.wsmpVersion = 3;
                    _wsmParameters.channelIdentifier = _startWsmRx.channelIdentifier;
                    _wsmParameters.dataRate = pMsg->RxPacketData.MCS;
                    //
                    _wsmParameters.receivePowerLevel = pMsg->RxPacketData.RxPowerAnt2;
                    //
                    _wsmParameters.sourceMACAddr.buf = dot11pkHdr->i_addr2;
                    _wsmParameters.sourceMACAddr.size = IEEE80211_ADDR_LEN;
                    _eventParams.choice.wsm = _wsmParameters;
                    break;

                case EventParamsChoice_ip:
                    _eventParams.present = EventParams_PR_ip;
                    break;

                case EventParamsChoice_d80211frame:
                    _eventParams.present = EventParams_PR_d80211frame;
                    break;

                case EventParamsChoice_security:
                    _eventParams.present = EventParams_PR_security;
                    break;
            }

            long _forwardPdu = 0;
            asn_INTEGER2long(_startWsmRx.eventHandling.forwardPdu, &_forwardPdu);

            printf("\n\n!!!! %ld !!!!\n\n", _forwardPdu);

            if (rxFlag & 2) {
                if (rxFlag & 1) {
                    switch (_forwardPdu) {
                        case PduType_reserved:
                            asn_long2INTEGER(&_dot11Ind.pdu->pduType, _forwardPdu);
                            _pdu.pduData.size = pMsg->RxPacketData.RxFrameLength - start_dot11frame;
                            _pdu.pduData.buf = pMsg->RxPacketData.RxFrame + start_dot11frame;
                            break;
                        case PduType_d80211frame:
                            asn_long2INTEGER(&_dot11Ind.pdu->pduType, _forwardPdu);
                            _pdu.pduData.size = pMsg->RxPacketData.RxFrameLength - start_dot3frame;
                            printf("#1\n");
                            _pdu.pduData.buf = pMsg->RxPacketData.RxFrame + start_dot3frame;
                            break;
                        case PduType_d16093frame:
                            asn_long2INTEGER(&_dot11Ind.pdu->pduType, _forwardPdu);
                            _pdu.pduData.size = pMsg->RxPacketData.RxFrameLength - start_dot2data;
                            _pdu.pduData.buf = pMsg->RxPacketData.RxFrame + start_dot2data;
                        default:
                            printf("\n\n!!!! out of pduType !!!!\n\n");
                            break;
                    }
                }
            }

            _dot11Ind.pdu = &_pdu;

            _dot11Ind.eventParams = &_eventParams;
            _dot11Ind.radio = _startWsmRx.radio;
            _dot11.present = TCI80211_PR_indication;
            _dot11.choice.indication = _dot11Ind;
            _tci_msg->frame.present = Frame_PR_d80211;
            _tci_msg->frame.choice.d80211 = _dot11;
            break;

        case Frame_PR_d16094:
            break;

        case Frame_PR_sutCtrl:
            break;

        case Frame_PR_d29451:
            break;

        case Frame_PR_NOTHING:
            break;
    }

    printf("--- Send TCI Indication...\n\n");

    xer_fprint(stdout, &asn_DEF_TCIMsg, _tci_msg);
    printf("\n\n");

    enc_rval = oer_encode_to_buffer(&asn_DEF_TCIMsg, 0, _tci_msg, send_buffer, sizeof(send_buffer));
    sendto(sock_udp, send_buffer, enc_rval.encoded, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
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
