/**
 * @addtogroup mk2mac_test MK2 MLME_IF test application(s)
 * @{
 *
 * @file
 * test-common: Common function library for use in test-tx, test-rx suite
 */

//------------------------------------------------------------------------------
// Copyright (c) 2010 Cohda Wireless Pty Ltd
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Included headers
//------------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <poll.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <assert.h>

#include <string.h>

#include <sys/time.h> // for rate control
#include <sys/socket.h>
#include <netinet/in.h> // ntohs
#include <linux/cohda/llc/llc-api.h>
#include "test-common.h"
#include "mkxtest.h"
#include "TxOpts.h"

#define D_LOCAL D_WARN
#include "debug-levels.h"

//------------------------------------------------------------------------------
// Macros & Constants
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// Functions
//------------------------------------------------------------------------------

void MACAddr_fprintf (FILE *fp, const uint8_t * pAddr)
{
  fprintf(fp, "%02x:%02x:%02x:%02x:%02x:%02x ", pAddr[0], pAddr[1], pAddr[2],
          pAddr[3], pAddr[4], pAddr[5]);
}

/*
 * @brief print the ethernet header from a Rx buffer
 * @param fp open file pointer
 * @param pEthHdr pointer to buffer from network containing ethernet header
 * @return none
 * Print headings if input data pointer is NULL
 */
void EthHdr_fprintf (FILE *fp, const struct ethhdr * pEthHdr)
{
  if (pEthHdr == NULL)
  {
    // Dest MAC Address
    fprintf(fp, "%17s ", "Dest MAC Addr");

    // Source MAC Address
    fprintf(fp, "%17s ", "Src MAC Addr");

    // Ether Type
    fprintf(fp, "%6s ", "EthTyp");
  }
  else
  {

    // Dest MAC Address
    MACAddr_fprintf(fp, pEthHdr->h_dest);

    // Source MAC Address
    MACAddr_fprintf(fp, pEthHdr->h_source);

    // Ether Type
    fprintf(fp, "0x%04x ", ntohs(pEthHdr->h_proto));
  }
}

/*
 * @brief print the 802.11 QoS header from a Rx buffer
 * @param fp open file pointer
 * @param pEthHdr pointer to buffer from network containing ethernet header
 * @return none
 * Print headings if input data pointer is NULL
 */
void QoSHdr_fprintf (FILE *fp, struct IEEE80211QoSHeader * pQoSHdr)
{
  if (pQoSHdr == NULL)
  {
    // Dest MAC Address
    fprintf(fp, "%17s ", "Dest MAC Addr");

    // Source MAC Address
    fprintf(fp, "%17s ", "Src MAC Addr");
  }
  else
  {

    // Dest MAC Address
    MACAddr_fprintf(fp, pQoSHdr->Address1);

    // Source MAC Address
    MACAddr_fprintf(fp, pQoSHdr->Address2);
  }
}

/*
 * Print headings if input data pointer is NULL
 */
void Dot11Hdr_fprintf (FILE *fp, struct IEEE80211MACHdr * pDot11Hdr)
{
  if (pDot11Hdr == NULL)
  {
    /// Frame control info
    fprintf(fp, "%6s ", "FrmCtl");
    /// Duration ID, for data frames = duration of frames
    fprintf(fp, "%6s ", "DurnID");
    /// SA Source address
    fprintf(fp, "%17s ", "Address 1");
    /// DA Destination address
    fprintf(fp, "%17s ", "Address 2");
    /// BSSID Receiving station address (destination wireless station)
    fprintf(fp, "%17s ", "Address 3");
    /// Sequence control info
    fprintf(fp, "%6s ", "SeqCtl");

  }
  else
  {
    /// Frame control info
    fprintf(fp, "0x%04x ", ntohs(pDot11Hdr->FrameControl));
    /// Duration ID, for data frames = duration of frames
    fprintf(fp, "0x%04x ", ntohs(pDot11Hdr->DurationId));
    /// SA Source address
    MACAddr_fprintf(fp, pDot11Hdr->Address1);
    /// DA Destination address
    MACAddr_fprintf(fp, pDot11Hdr->Address2);
    /// BSSID Receiving station address (destination wireless station)
    MACAddr_fprintf(fp, pDot11Hdr->Address3);
    /// Sequence control info
    fprintf(fp, "0x%04x ", ntohs(pDot11Hdr->SeqControl));
  }
}

//-----------------------------------------------------------------------------
//  Function: GetMacFromString
//  Author(s): John Buetefuer
//-----------------------------------------------------------------------------
//
//  Description:
//    Converts string MAC address into buffer of 6 bytes
//  Inputs:
//    MacAddr,     pointer to 6 byte buffer to store result
//    MacAddrStr, The string containing the MAC address
//  Outputs:
//    returns 1 on success, 0 on failure (invalid format)
//    MacAddr, is updated with the 6 MAC address bytes, only on success.
//-----------------------------------------------------------------------------
int GetMacFromString (uint8_t * MacAddr, const char * MacAddrStr)
{
  int Num = 0;
  uint8_t Mac[6];

  Num = sscanf(MacAddrStr, " %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx ", &(Mac[0]),
               &(Mac[1]), &(Mac[2]), &(Mac[3]), &(Mac[4]), &(Mac[5]));
  if (Num != 6)
    return 0;
  else
  {
    // Success, copy mac address to result buffer
    MacAddr[0] = Mac[0];
    MacAddr[1] = Mac[1];
    MacAddr[2] = Mac[2];
    MacAddr[3] = Mac[3];
    MacAddr[4] = Mac[4];
    MacAddr[5] = Mac[5];
    return 1;
  }
}

/**
 * @brief print the payload portion of a packet to file
 * @param fp open file pointer
 * @param pPayload data to dump
 * @param PayloadLen length of data to dump
 * @param DumpPayload should the actual Bytes be dumped or just the length
 * @return none
 *
 */
void Payload_fprintf (FILE * fp,
                      unsigned char *pPayload,
                      int PayloadLen,
                      bool DumpPayload)
{
  // Dump headings if pointer is Null
  if (pPayload == NULL)
  {
    fprintf(fp, "%4s ", "Leng");

  }
  else
  {

    fprintf(fp, "%04d ", PayloadLen);

    // Optional Payload
    if (DumpPayload)
    {
      int i;
      if (fp == stdout)
      {
        //arrange in columns with addressing
        fprintf(fp, "\n");
        for (i = 0; i < PayloadLen; i++)
        {
          // print a address at the head of each line
          if ((i % 16) == 0)
            fprintf(fp, "0x%04x: ", i);

          fprintf(fp, "%02x ", pPayload[i]);

          // end of line
          if (((i + 1) % 16) == 0)
            fprintf(fp, "\n");
        }
      }
      else
      {
        // all in line
        for (i = 0; i < PayloadLen; i++)
          fprintf(fp, "%02x ", pPayload[i]);
      } // to stdout?
    } // should the bytes also be dumped?
  } // NULL input pointer for heading print?
}

/**
 * @brief fill a preallocated buffer with values according to a mode
 * @param pPayload Buffer to write into.
 * @param PayloadLen length of data to generate (must be >= 5)
 * @param SeqNum Sequence Number to be written to first 4 bytes
 * @param PayloadMode Random, SeqNum, Incrementing or Byte, written to 5th byte
 * @param PayloadByte Byte to be written in Byte mode. Not used in other modes.
 * @return none
 *
 * SeqNum and Random Modes leave up to 3 bytes at end of packet == 0.
 */

int getNum(char ch)
{
    int num=0;
    if(ch>='0' && ch<='9')
    {
        num=ch-0x30;
    }
    else
    {
        switch(ch)
        {
            case 'A': case 'a': num=10; break;
            case 'B': case 'b': num=11; break;
            case 'C': case 'c': num=12; break;
            case 'D': case 'd': num=13; break;
            case 'E': case 'e': num=14; break;
            case 'F': case 'f': num=15; break;
            default: num=0;
        }
    }
    return num;
}

//function : hex2int
//this function will return integer value against
//hexValue - which is in string format

//unsigned int hex2int(unsigned char hex[])
//{
//    unsigned int x=0;
//    x=(getNum(hex[0]))*16+(getNum(hex[1]));
//}

int dot3_gen (unsigned char *pPayload,
                  int PayloadLen,
                  uint32_t SeqNum,
                  tPayloadMode PayloadMode,
                  uint8_t PayloadByte, bool wsmp_n_extension_ind, int channelnumber, int datarate,
				  int transmittedpower, int psid, bool wsa_ind, bool wsa_extension_ind,char content[500],bool channelnumber_ind,bool datarate_ind,bool txpower_ind)
{
  //int contentnum[1000]={0};
  int mbps=9;
  int contentcount =0;
  memset(pPayload, 0, strlen(content));


  //LLC header
  pPayload[0]=0x88;
  pPayload[1]=0xdc;
  //WSMP N header
  int subtype=0;//0000....[2]
  //int wsmp_n_extension_ind=1;//....0...[2]
  int wsmp_version=3;//.....000[2]
  int wsmp_n_extension_count=0;//

  //change MCS to real datarate(MB/s for dot3 header)
  switch(datarate){
  case 11:
	  mbps=3;
	  break;
  case 15:
	  mbps=4;
	  break;
  case 10:
	  mbps=6;
	  break;
  case 14:
	  mbps=9;
	  break;
  case 19:
	  mbps=12;
	  break;
  case 13:
	  mbps=18;
	  break;
  case 18:
	  mbps=24;
	  break;
  case 12:
	  mbps=27;
	  break;
  default:
	  mbps=12;
	  break;
  }

  //int datarate=6;
  //int transmittedpower=0x94;//20dbm
  unsigned char pchannelnumber[3] = {15,1,channelnumber};
  unsigned char pdatarate[3] = {16,1,mbps};
  unsigned char ptransmittedpower[3] = {4,1,(transmittedpower/2)+128};
  //WSMP T header
  int tpid=0;//8 always 0.
  //psid=0x87;//8~32 0xff......
  //int length=0x00;

  //stream
  unsigned char stream[250] ={0};
  //WSA
  //int wsa_ind=0;
  int wsa_version=3;
  int wsa_option_ind=0b1110;//IE,SInfo,CInfo,WRA.
  int wsa_id=0;
  int wsa_content_count=1;
  //dot2 header
  unsigned char dot2_unsecured[2] = {0x03,0x80};

  contentcount=3;
  if(wsmp_n_extension_ind == 1)
  {
	  pPayload[contentcount]=wsmp_n_extension_count;
	  contentcount++;
  }
  if(channelnumber_ind==true)
  {
	  pPayload[contentcount]=pchannelnumber[0];
	  pPayload[contentcount+1]=pchannelnumber[1];
	  pPayload[contentcount+2]=pchannelnumber[2];
	  wsmp_n_extension_count++;
	  contentcount=contentcount+3;
  }
  if(datarate_ind==true)
  {
	  pPayload[contentcount]=pdatarate[0];
	  pPayload[contentcount+1]=pdatarate[1];
	  pPayload[contentcount+2]=pdatarate[2];
	  contentcount=contentcount+3;
	  wsmp_n_extension_count++;
  }
  if(txpower_ind==true)
  {
	  pPayload[contentcount]=ptransmittedpower[0];
	  pPayload[contentcount+1]=ptransmittedpower[1];
	  pPayload[contentcount+2]=ptransmittedpower[2];
	  contentcount=contentcount+3;
	  wsmp_n_extension_count++;
  }
  pPayload[2]=subtype*16+wsmp_n_extension_ind*8+wsmp_version;
  printf("\nn extension ind: %d\nrate:%d\ntxpower:%d\npsid:%d\n",wsmp_n_extension_ind,datarate,transmittedpower,psid);

  pPayload[contentcount]=tpid;
  contentcount++;
  if(psid<0x80)
  {
	  pPayload[contentcount]=127;
	  contentcount=contentcount+1;
  }else if(psid<0x4080)
  {
	  pPayload[contentcount+1]=0xff;
	  pPayload[contentcount]=0xbf;
	  contentcount=contentcount+2;
  }else if(psid<0x204080)
  {
	  pPayload[contentcount+2]=0xff;
	  pPayload[contentcount+1]=0xff;
	  pPayload[contentcount]=0xdf;
	  contentcount=contentcount+3;
  }else
  {
	  pPayload[contentcount+3]=0xff;
	  pPayload[contentcount+2]=0xff;
	  pPayload[contentcount+1]=0xff;
	  pPayload[contentcount]=0xef;
	  contentcount=contentcount+4;
  }

  //input wsm length.
  pPayload[contentcount]=(strlen(content)/2)+3;
  contentcount++;


  pPayload[contentcount]=dot2_unsecured[0];
  pPayload[contentcount+1]= dot2_unsecured[1];
  pPayload[contentcount+2]=strlen(content)/2;
  contentcount=contentcount+3;
  if(wsa_ind==1)
  {
	  printf("wsa running...\n");
	  pPayload[contentcount]=wsa_version*16+wsa_option_ind*8+wsa_id+wsa_content_count;
	  contentcount++;
  }
  if(wsa_extension_ind==1)
  {
	  printf("wsa extension running...\n");
  }


  //if payload with -E option
  for (int i=0;i<strlen(content)/2;i++)
  {
	  stream[i]=getNum(content[i*2])*16+getNum(content[i*2+1]);
  }
  for(int z=0;z<strlen(content)/2;z++)
  {
	  pPayload[contentcount]=stream[z];
	  printf("%d",pPayload[contentcount]);
	  contentcount++;
  }




  // set whole to zero (catches ends of 32 bit writers)

  //for (i = 0; i<contentcount; i++)
  //  {
  //    contentnum[i]=getNum(content[i]);
  //  }
  //for (i = 0; i<contentcount/2; i++)
  //  {
  //    pPayload[i]=(contentnum[i*2])*16+contentnum[i*2+1];
  //    printf("pPayload[i]:: %d\n",pPayload[i]);
  //  }

  return contentcount;
}

int Payload_gen (unsigned char *pPayload,
                  int PayloadLen,
                  uint32_t SeqNum,
                  tPayloadMode PayloadMode,
                  uint8_t PayloadByte)
{
  int i;
  int contentnum[1000]={0};
  char *content="helloworld!";
  uint32_t * pPayload32; // 32 bit pointer into payload
  unsigned short xsubi[3] =
    { 0, 0, 0 }; // registers for rand48


  // barf if pointer is Null or payload not large enough to hold SeqNum and Mode
  d_assert(pPayload != NULL);
  d_assert(PayloadLen >= 5);

  // set whole to zero (catches ends of 32 bit writers)
  memset(pPayload, 0, strlen(content));

  pPayload32 = (uint32_t *) pPayload; // used to write in 4 Byte chunks

  // Populate the Payload according to the Value (Mode) specified on input
  switch (PayloadMode)
  {
    case PAYLOADMODE_RANDOM: // PRBS seeded with Sequence Number
      xsubi[0] = (unsigned short) SeqNum;
      xsubi[1] = (unsigned short) (SeqNum >> 16);
      xsubi[2] = 0;
      for (i = 0; i < (PayloadLen >> 2); i++)
        pPayload32[i] = nrand48(xsubi);
      break;
    case PAYLOADMODE_INCREMENT: // incrementing
      for (i = 0; i < PayloadLen; i++)
        pPayload[i] = (unsigned char) (i);
      break;
    case PAYLOADMODE_SEQNUM: // repeat four byte pattern
      for (i = 0; i < (PayloadLen >> 2); i++)
        pPayload32[i] = htonl(SeqNum);
      break;
    /*case PAYLOADMODE_BYTE: // set value from value of PayloadValue
      for (i = 0; i < PayloadLen; i++)
        pPayload[i] = PayloadByte;
      break;*/
    case PAYLOADMODE_BYTE: // set value from value of PayloadValue
      printf("payload byte \n");
      for (i = 0; i<strlen(content); i++)
    	{
    	  contentnum[i]=getNum(content[i]);
    	}
      for (i = 0; i<strlen(content)/2; i++)
    	{
    	  pPayload[i]=(contentnum[i*2])*16+contentnum[i*2+1];
    	  printf("pPayload[i]:: %d\n",pPayload[i]);
    	}

      return strlen(content)/2;
      break;
    case PAYLOADMODE_TIME: // timestamp (followed by incrementing)
    {
      struct timeval tv;
      struct timezone tz;
      gettimeofday(&tv, &tz);

      for (i = 0; i < PayloadLen; i++)
        pPayload[i] = (unsigned char) (i);

      pPayload32[2] = (int)tv.tv_sec;
      pPayload32[3] = (int)tv.tv_usec;
    }
    break;
    default: // set value from value of PayloadValue
      // we don't have dot4 etc to filter out invalid packets so lots of what we
      // receive looks invalid so get rid of this print as it is too noisy
      //if (PayloadLen >= 5)
      //  printf("Unknown payload Mode %d. Not writing to Buffer\n", PayloadMode);
      return 0;
      break;
  } // population mode for payload

  // Overwrite the first 32 bits with the Sequence Number of this Packet
  //pPayload32[0] = htonl(SeqNum);

  // Overwrite 5th Byte with Payload mode (so that Rx knows automatically)
  //pPayload[4] = PayloadMode;
  return 0;
}

/**
 * @brief Print a Channel Profile Object
 * @param pTxCHOpts pointer to Tx Channel Options Object
 * @param IndentStr each line pre-fixed with this string
 */
void MK2ChanProfile_Print (tMK2ChanProfile * pChanProfile, char *IndentStr)
{

  d_assert(pChanProfile != NULL);
  /// Channel Number
  printf("%s", IndentStr);
  printf("ChannelNumber:  %d\n", pChanProfile->ChannelNumber);
  /// Indicate the default data rate that should be used (max if TRC)
  printf("%s", IndentStr);
  printf("DefaultMCS:     %d\n", pChanProfile->DefaultMCS);
  /// Indicate the default transmit power that should be used (max if TPC)
  printf("%s", IndentStr);
  printf("DefaultTxPower: %d\n", pChanProfile->DefaultTxPower);
  /// Indicate if transmit rate control should be used by default
  printf("%s", IndentStr);
  printf("DefaultTRC:     %d\n", pChanProfile->DefaultTRC);
  /// Indicate if transmit power control should be used by default
  printf("%s", IndentStr);
  printf("DefaultTPC:     %d\n", pChanProfile->DefaultTPC);
  /// Indicate if channel is 10 MHz or 20 MHz
  printf("%s", IndentStr);
  printf("Bandwidth:      %d\n", pChanProfile->Bandwidth);
  /// Dual Radio transmit control (inactive in single radio configurations)
  printf("%s", IndentStr);
  printf("DualTxControl:  %d\n", pChanProfile->DualTxControl);
  /// Channel Utilisation measurement period (in TU units. 1 TU = 1.024 ms)
  printf("%s", IndentStr);
  printf("ChannelUtilisationPeriod: %d\n",
         pChanProfile->ChannelUtilisationPeriod);
  /// Antenna(s) to transmit on
  printf("%s", IndentStr);
  printf("TxAntenna:      %d\n", pChanProfile->TxAntenna);
  /// Antenna(s) to receive on
  printf("%s", IndentStr);
  printf("RxAntenna:      %d\n", pChanProfile->RxAntenna);
  // MAC address
  printf("%s", IndentStr);
  printf("MAC Address:    %02x:%02x:%02x:%02x:%02x:%02x\n", pChanProfile->MACAddr[0],
         pChanProfile->MACAddr[1], pChanProfile->MACAddr[2],
         pChanProfile->MACAddr[3], pChanProfile->MACAddr[4],
         pChanProfile->MACAddr[5]);

}

/**
 * @brief Print a tMKxChanConfig
 * @param pRadioCfg pointer to Channel Config Object
 * @param IndentStr each line pre-fixed with this string
 */
void MKxChanConfig_Print (const struct MKxChanConfig *pCfg, char *IndentStr)
{

  uint64_t MAC;
  d_assert(pCfg != NULL);
  /// Channel Number
  printf("%s", IndentStr);
  printf("ChannelNumber:  %d\n", (pCfg->PHY.ChannelFreq-5000)/5);
  /// Indicate the default data rate that should be used (max if TRC)
  printf("%s", IndentStr);
  printf("DefaultMCS:     %d\n", pCfg->PHY.DefaultMCS);
  /// Indicate the default transmit power that should be used (max if TPC)
  printf("%s", IndentStr);
  printf("DefaultTxPower: %d\n", pCfg->PHY.DefaultTxPower);
  /// Indicate if transmit rate control should be used by default
  printf("%s", IndentStr);
  printf("DefaultTRC:     NA\n");
  /// Indicate if transmit power control should be used by default
  printf("%s", IndentStr);
  printf("DefaultTPC:     NA\n");
  /// Indicate if channel is 10 MHz or 20 MHz
  printf("%s", IndentStr);
  printf("Bandwidth:      %d\n", pCfg->PHY.Bandwidth);
  /// Dual Radio transmit control (inactive in single radio configurations)
  printf("%s", IndentStr);
  printf("DualTxControl:  %d\n", pCfg->MAC.DualTxControl);
  /// Channel Utilisation measurement period (in TU units. 1 TU = 1.024 ms)
  printf("%s", IndentStr);
  printf("ChannelUtilisationPeriod: %d\n", pCfg->LLC.IntervalDuration/1000);
  /// Antenna(s) to transmit on
  printf("%s", IndentStr);
  printf("TxAntenna:      %d\n", pCfg->PHY.TxAntenna);
  /// Antenna(s) to receive on
  printf("%s", IndentStr);
  printf("RxAntenna:      %d\n", pCfg->PHY.RxAntenna);
  // MAC address
  printf("%s", IndentStr);
  printf("MAC Address:    ");
  MAC = pCfg->MAC.AMSTable[5].Addr;
  MACAddr_fprintf(stdout, (uint8_t *)&MAC);
  printf("\n");
}

#ifndef __QNX__
/**
 * @brief build a short opts char array from a long opts structure
 * see getopt()
 * @param pLongOpts Null terminate long options array
 * @param pShortOpts char array pointer to write short opts to
 *
 */
void copyopts (struct option * pLongOpts, char * pShortOpts)
{
  // copy the long option vals into the short option
  // One Colon == Required Argument
  // Two Colons == Optional Arg
  // assume null entry at end of table
  int i = 0;

  for (i = 0; pLongOpts[i].name != NULL; i++)
  {

    // Copy char from LongOpts Structure
    *pShortOpts++ = pLongOpts[i].val;

    // Optional Args?
    if (pLongOpts[i].has_arg == required_argument)
      *pShortOpts++ = ':';

    // Double Colon for optional arg
    if (pLongOpts[i].has_arg == optional_argument)
    {
      *pShortOpts++ = ':';
      *pShortOpts++ = ':';
    }
  }
  // Null terminate!
  *pShortOpts++ = '\0';
}
#endif
/**
 * @}
 */
