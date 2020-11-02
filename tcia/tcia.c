//------ standard header --------
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <pthread.h>

//-------- UDP header ----------
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

long radio = 0;
long timeSlot = 0;
long channelNumber = 0;
long dataRate = 0;
long txPower = 0;
long psid = 0;
long repeatRate = 0;
long priority = 0;
uint8_t *payload = NULL;

TCIMsg_t *tci_msg;
TCIMsg_t *_tci_msg;

TCI16093_t _dot3;
TCI80211_t _11p;
TCI16094_t _dot4;
TCI29451_t _j2945;
TCISutControl_t _sutCtrl;

Response_t _response;
ResultCode_t _resultCode;

SetWsmTxInfo_t _setWsmTxInfo;
StartWsmTx_t _startWsmTx;
Radio_t _radio;

asn_dec_rval_t dec_rval;

Time64_t *_time64;
long long time_mil;

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

    tci_msg = calloc(1, sizeof(TCIMsg_t));
    _tci_msg = calloc(1, sizeof(TCIMsg_t));

    _time64 = calloc(1, sizeof(Time64_t));

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
        enum Dot3Request__value_PR _enumDot3Request;
        enum Dot4Request__value_PR _enumDot4Request;

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

                _enumDot3Request = _response.msgID;
                switch (_enumDot3Request) {
                    case Dot3Request__value_PR_SetInitialState:
                        printf("--- Set Initial State...\n\n");
                        break;
                    case Dot3Request__value_PR_Dot3SetWsmTxInfo:
                        printf("--- Set WSM Tx Info...\n\n");

                        _setWsmTxInfo = tci_msg->frame.choice.d16093.choice.request.value.choice.Dot3SetWsmTxInfo;

                        asn_INTEGER2long(&_setWsmTxInfo.radio.radio, &radio);
                        asn_INTEGER2long(&_setWsmTxInfo.timeslot, &timeSlot);
                        channelNumber = _setWsmTxInfo.channelIdentifier;
                        dataRate = _setWsmTxInfo.dataRate;
                        txPower = _setWsmTxInfo.transmitPowerLevel;
                        priority = _setWsmTxInfo.userPriority;

                        /* code insert */
                        char instruction[100] = {0};
                        sprintf(instruction, "%s%s", instruction, "/opt/cohda/bin/llc chconfig -s");
                        sprintf(instruction, "%s%s", instruction, " -c");
                        sprintf(instruction, "%s%ld", instruction, channelNumber);
                        if (timeSlot == 2)
                            sprintf(instruction, "%s%s", instruction, " -wSCH");
                        else
                            sprintf(instruction, "%s%s", instruction, " -wCCH");

                        printf("%s\n", instruction);

                        system(instruction);
                        break;
                    case Dot3Request__value_PR_Dot3StartWsmTx:
                        printf("--- Start WSM Tx...\n\n");
                        pthread_create(&threads[1], NULL, ThreadTxMain, &_framePresent);
                        break;
                    case Dot3Request__value_PR_StopWsmTx:
                        printf("--- Stop WSM Tx...\n\n");
                        system("kill -9 $(pgrep llc)");
                        // pthread_cancel(threads[1]);
                        break;
                    case Dot3Request__value_PR_StartWsmRx:
                        printf("--- Start WSM Rx...\n\n");
                        FILE *fp = fopen("startRx", "w");
                        fwrite(recv_buffer, 1, recv_len, fp);
                        fclose(fp);
                        pthread_create(&threads[1], NULL, ThreadRxMain, NULL);
                        break;
                    case Dot3Request__value_PR_StopWsmRx:
                        printf("--- Stop WSM Rx...\n\n");
                        system("kill -9 $(pgrep llc)");
                        break;
                    case Dot3Request__value_PR_NOTHING:
                    default:
                        break;
                }

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

                        _setWsmTxInfo = tci_msg->frame.choice.d80211.choice.request.value.choice.Dot11SetWsmTxInfo;

                        asn_INTEGER2long(&_setWsmTxInfo.radio.radio, &radio);
                        asn_INTEGER2long(&_setWsmTxInfo.timeslot, &timeSlot);
                        channelNumber = _setWsmTxInfo.channelIdentifier;
                        dataRate = _setWsmTxInfo.dataRate;
                        txPower = _setWsmTxInfo.transmitPowerLevel;
                        priority = _setWsmTxInfo.userPriority;

                        /* code insert */
                        char instruction[100] = {0};
                        sprintf(instruction, "%s%s", instruction, "/opt/cohda/bin/llc chconfig -s");
                        sprintf(instruction, "%s%s", instruction, " -c");
                        sprintf(instruction, "%s%ld", instruction, channelNumber);
                        if (timeSlot == 2)
                            sprintf(instruction, "%s%s", instruction, " -wSCH");
                        else
                            sprintf(instruction, "%s%s", instruction, " -wCCH");

                        printf("%s\n",instruction);
                        
                        system(instruction);
                        break;
                    case Dot11Request__value_PR_Dot11StartWsmTx:
                        printf("--- Start WSM Tx...\n\n");
                        pthread_create(&threads[1], NULL, ThreadTxMain, &_framePresent);
                        break;
                    case Dot11Request__value_PR_StopWsmTx:
                        printf("--- Stop WSM Tx...\n\n");
                        system("kill -9 $(pgrep llc)");
                        // pthread_cancel(threads[1]);
                        break;
                    case Dot11Request__value_PR_StartWsmRx:
                        printf("--- Start WSM Rx...\n\n");
                        FILE *fp = fopen("startRx", "w");
                        fwrite(recv_buffer, 1, recv_len, fp);
                        fclose(fp);
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

                _enumDot4Request = _response.msgID;
                switch (_enumDot4Request) {
                    case Dot4Request__value_PR_SetInitialState:
                        printf("--- Set Initial State...\n\n");
                        break;
                    case Dot4Request__value_PR_Dot4SetWsmTxInfo:
                        printf("--- Set WSM Tx Info...\n\n");
                        system("/opt/cohda/bin/llc chconfig -s");
                        break;
                    case Dot4Request__value_PR_Dot4StartWsmTx:
                        printf("--- Start WSM Tx...\n\n");
                        pthread_create(&threads[1], NULL, ThreadTxMain, &_framePresent);
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

            case Frame_PR_d29451:
                printf("!!! D2945 Request RECV !!!\n\n");
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

    int *test;
    test = arg;

    switch(*test){
        case Frame_PR_d16093:
            _startWsmTx = tci_msg->frame.choice.d16093.choice.request.value.choice.Dot3StartWsmTx;
            break;
        case Frame_PR_d80211:
            _startWsmTx = tci_msg->frame.choice.d80211.choice.request.value.choice.Dot11StartWsmTx;
            break;
        case Frame_PR_d16094:
            _startWsmTx = tci_msg->frame.choice.d16094.choice.request.value.choice.Dot4StartWsmTx;
            break;
        case Frame_PR_d29451:
            break;
    }

    asn_INTEGER2long(&_startWsmTx.radio.radio, &radio);
    switch(_startWsmTx.psid.present) {
        case 2:
            if(_startWsmTx.psid.choice.extension.present == 1)
                psid = _startWsmTx.psid.choice.extension.choice.content;
            else if (_startWsmTx.psid.choice.extension.present == 2)
                psid = _startWsmTx.psid.choice.extension.choice.extension.choice.content;
            break;
        case 1:
            psid = _startWsmTx.psid.choice.content;
            break;
        case 0:
            break;
    }
    repeatRate = _startWsmTx.repeatRate;
    payload = calloc(1, _startWsmTx.payload->size);
    memcpy(payload, _startWsmTx.payload->buf, _startWsmTx.payload->size);

    /* code insert */
    char instruction[100] = {0};
    sprintf(instruction, "%s%s", instruction, "/opt/cohda/bin/llc test-tx");
    sprintf(instruction, "%s%s", instruction, " -c");
    sprintf(instruction, "%s%ld", instruction, channelNumber);
    sprintf(instruction, "%s%s", instruction, " -p");
    sprintf(instruction, "%s%ld", instruction, txPower*2);
    sprintf(instruction, "%s%s", instruction, " -E");
    for (int i = 0; i < _startWsmTx.payload->size; i++) {
        sprintf(instruction, "%s%02x", instruction, payload[i]);
    }
    sprintf(instruction, "%s%s", instruction, " -B");
    sprintf(instruction, "%s%ld", instruction, psid);
    sprintf(instruction, "%s%s", instruction, " -r");
    sprintf(instruction, "%s%f", instruction, (float)repeatRate/5);
    printf("\n\n!!! %d !!!\n\n", _setWsmTxInfo.infoElementsIncluded->buf[0]);
    printf("\n\n!!! %d !!!\n\n", _setWsmTxInfo.infoElementsIncluded->buf[1]);
    printf("\n\n!!! %d !!!\n\n", _setWsmTxInfo.infoElementsIncluded->buf[2]);
    // if (_setWsmTxInfo.infoElementsIncluded->buf[1]) {
    //     sprintf(instruction, "%s%s", instruction, " -A -F -G -H");
    // }

    printf("%s\n", instruction);

    system(instruction);
}

void setTimeStamp(Time64_t *time64) {

    struct timeval tv;

    gettimeofday(&tv, NULL);
    long long time_mil = tv.tv_sec * 1000LL + tv.tv_usec / 1000;

    asn_imax2INTEGER(time64, time_mil);
}
