//------ standard header ------
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <pthread.h>

//-------- UDP header --------
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//-------- ASN header --------
#include <TCIMsg.h>
#include <Time64.h>
#include <Frame.h>

//------- CONST define -------
#define TCIA_PORT 13001
#define TCI_VER 1

void *ThreadUDPMain(void *arg);
void *ThreadRxMain(void *arg);
void *ThreadTxMain(void *arg);
void setTimeStamp(Time64_t* time64);

pthread_t threads[2];

int main()
{    
    
    pthread_create(&threads[0], NULL, ThreadUDPMain, NULL);

    while (1)
    {   
        sleep(5);
        printf("Waiting for messages...\n");
    }

    return 0;
}

void *ThreadUDPMain(void *arg)
{
    pthread_detach(pthread_self());

    struct sockaddr_in addr, client_addr;
    unsigned char recv_buffer[1024];
    unsigned char send_buffer[1024];

    TCIMsg_t *tci_msg = calloc(1, sizeof(TCIMsg_t));
    TCIMsg_t *_tci_msg = calloc(1, sizeof(TCIMsg_t));
    
    TCI16093_t _dot3;
    TCI80211_t _11p;
    TCI16094_t _dot4;
    TCI29451_t _j2945;
    TCISutControl_t _sutCtrl;

    Response_t _response;
    ResultCode_t _resultCode;

    asn_dec_rval_t dec_rval;

    Time64_t *_time64 = calloc(1, sizeof(Time64_t));
    long long time_mil;

    int sock_udp = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&addr, 0x00, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(TCIA_PORT);

    bind(sock_udp, (struct sockaddr *)&addr, sizeof(addr));

    int addr_len = sizeof(client_addr);

    while (1)
    {
        int recv_len = recvfrom(sock_udp, recv_buffer, 1024, 0, (struct sockaddr *)&client_addr, &addr_len);

        printf("--------- UDP TCI Message ---------\n\n");

        printf("recv_len : %d\n", recv_len);
        printf("ip : %s\n", inet_ntoa(client_addr.sin_addr));
        printf("received data : ");
        for (int i = 0; i < recv_len; i++)
        {
            printf("%02x ", recv_buffer[i]);
        }

        dec_rval = oer_decode(0, &asn_DEF_TCIMsg, (void **)&tci_msg, recv_buffer, recv_len);

        printf("\n\n");
        xer_fprint(stdout, &asn_DEF_TCIMsg, tci_msg);
        printf("\n\n");

        enum Frame_PR _framePresent = tci_msg->frame.present;
        enum ResultCode _enumResultCode = ResultCode_rcSuccess;
        enum Dot11Request__value_PR _enumDot11Request;

        setTimeStamp(_time64);
        asn_long2INTEGER(&_resultCode, _enumResultCode);

        switch (_framePresent) {

            case Frame_PR_d16093 :
                printf("!!! DOT3 Request RECV !!!\n\n");

                _response.msgID = tci_msg->frame.choice.d16093.choice.request.messageId;
                _response.resultCode = _resultCode;

                _dot3.present = 2;
                _dot3.choice.response = _response;

                _tci_msg->version = TCI_VER;
                _tci_msg->time = *_time64;
                _tci_msg->frame.present = _framePresent;
                _tci_msg->frame.choice.d16093 = _dot3;

                break;

            case Frame_PR_d80211 :
                printf("!!! 802.11p Request RECV !!!\n\n");

                _response.msgID = tci_msg->frame.choice.d80211.choice.request.messageId;
                _response.resultCode = _resultCode;

                _11p.present = 2;
                _11p.choice.response = _response;

                _tci_msg->version = TCI_VER;
                _tci_msg->time = *_time64;
                _tci_msg->frame.present = _framePresent;
                _tci_msg->frame.choice.d80211 = _11p;

                _enumDot11Request = _response.msgID;
                switch (_enumDot11Request) {
                    case Dot11Request__value_PR_SetInitialState:
                        printf("--- Set Initial State...\n\n");
                        break;
                    case Dot11Request__value_PR_Dot11SetWsmTxInfo:
                        printf("--- Set WSM Tx Info...\n\n");
                        system("/opt/cohda/bin/llc chconfig -s");
                        break;
                    case Dot11Request__value_PR_Dot11StartWsmTx:
                        printf("--- Start WSM Tx...\n\n");
                        pthread_create(&threads[1], NULL, ThreadTxMain, NULL);
                        break;
                    case Dot11Request__value_PR_StopWsmTx:
                        printf("--- Stop WSM Tx...\n\n");
                        system("kill -9 $(pgrep llc)");
                        // pthread_cancel(threads[1]);
                        break;
                    case Dot11Request__value_PR_StartWsmRx:
                        printf("--- Start WSM Rx...\n\n");
                        pthread_create(&threads[1], NULL, ThreadRxMain, NULL);
                        break;
                    case Dot11Request__value_PR_StopWsmRx:
                        printf("--- Stop WSM Rx...\n\n");
                        system("kill -9 $(pgrep llc)");
                        break;
                    case Dot11Request__value_PR_NOTHING:
                    default:
                        break;
                }

                break;

            case Frame_PR_d16094 :
                printf("!!! DOT4 Request RECV !!!\n\n");

                _response.msgID = tci_msg->frame.choice.d16094.choice.request.messageId;
                _response.resultCode = _resultCode;

                _dot4.present = 2;
                _dot4.choice.response = _response;

                _tci_msg->version = TCI_VER;
                _tci_msg->time = *_time64;
                _tci_msg->frame.present = _framePresent;
                _tci_msg->frame.choice.d16094 = _dot4;
                
            case Frame_PR_d80211 :
                printf("!!! 802.11p Request RECV !!!\n\n");

                _response.msgID = tci_msg->frame.choice.d80211.choice.request.messageId;
                _response.resultCode = _resultCode;

                _11p.present = 2;
                _11p.choice.response = _response;

                _tci_msg->version = TCI_VER;
                _tci_msg->time = *_time64;
                _tci_msg->frame.present = _framePresent;
                _tci_msg->frame.choice.d80211 = _11p;

                _enumDot4Request = _response.msgID;
                switch (_enumDot4Request) {
                    case Dot4Request__value_PR_SetInitialState:
                        printf("--- Set Initial State...\n\n");
                        break;
                    case Dot4Request__value_PR_Dot11SetWsmTxInfo:
                        printf("--- Set WSM Tx Info...\n\n");
                        system("/opt/cohda/bin/llc chconfig -s");
                        break;
                    case Dot4Request__value_PR_Dot11StartWsmTx:
                        printf("--- Start WSM Tx...\n\n");
                        pthread_create(&threads[1], NULL, ThreadTxMain, NULL);
                        break;
                    case Dot4Request__value_PR_StopWsmTx:
                        printf("--- Stop WSM Tx...\n\n");
                        system("kill -9 $(pgrep llc)");
                        // pthread_cancel(threads[1]);
                        break;
                    case Dot4Request__value_PR_StartWsmRx:
                        printf("--- Start WSM Rx...\n\n");
                        pthread_create(&threads[1], NULL, ThreadRxMain, NULL);
                        break;
                    case Dot4Request__value_PR_StopWsmRx:
                        printf("--- Stop WSM Rx...\n\n");
                        system("kill -9 $(pgrep llc)");
                        break;
                    case Dot4Request__value_PR_NOTHING:
                    default:
                        break;
                }

                break;

            case Frame_PR_d29451 :
                printf("!!! J2945 Request RECV !!!\n\n");

                _response.msgID = tci_msg->frame.choice.d29451.choice.request.messageId;
                _response.resultCode = _resultCode;

                _j2945.present = 2;
                _j2945.choice.response = _response;

                _tci_msg->version = TCI_VER;
                _tci_msg->time = *_time64;
                _tci_msg->frame.present = _framePresent;
                _tci_msg->frame.choice.d29451 = _j2945;

                break;

            case Frame_PR_sutCtrl :
                printf("!!! sutCtrl Request RECV !!!\n\n");

                _response.msgID = tci_msg->frame.choice.sutCtrl.choice.request.messageId;
                _response.resultCode = _resultCode;

                _sutCtrl.present = 2;
                _sutCtrl.choice.response = _response;

                _tci_msg->version = TCI_VER;
                _tci_msg->time = *_time64;
                _tci_msg->frame.present = _framePresent;
                _tci_msg->frame.choice.sutCtrl = _sutCtrl;

                break;

            case Frame_PR_NOTHING:
            default:
                break;
        }

        xer_fprint(stdout, &asn_DEF_TCIMsg, _tci_msg);
        printf("\n\n");

        asn_enc_rval_t er = oer_encode_to_buffer(&asn_DEF_TCIMsg, 0, _tci_msg, send_buffer, sizeof(send_buffer));

        printf("encoded len : %d\n", er.encoded);
        printf("encoded data : ");

        for (int j = 0; j < er.encoded; j++)
        {            
            printf("%02x ", send_buffer[j]);
        }

        printf("\n\n");

        sendto(sock_udp, send_buffer, er.encoded, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));

        ASN_STRUCT_RESET(asn_DEF_TCIMsg, tci_msg);
    }

    return 0;
}

void *ThreadRxMain(void *arg) {
    pthread_detach(pthread_self());
    system("/opt/cohda/bin/llc rx");
}

void *ThreadTxMain(void *arg)
{
    pthread_detach(pthread_self());
    system("/opt/cohda/bin/llc test-tx -p 60");
}

void setTimeStamp(Time64_t *time64) {

    struct timeval tv;

    gettimeofday(&tv, NULL);
    long long time_mil = tv.tv_sec * 1000LL + tv.tv_usec / 1000;

    asn_imax2INTEGER(time64, time_mil);
}
