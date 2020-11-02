#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <math.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>

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

int main()
{
  unsigned char *test;
  int contentcount=0;
  test="ddeeff88dc0b040f01ac10012404018a1701000020100380";
  unsigned char input[1000] ={0};
  
  //header parameter.
  int n_extension_count=0;
  int channel=172;
  int rate=12;
  int txpower=132;
  int tpid=0;
  int psid_len=1;
  unsigned int psid_p=0;  
  int wsm_length=0;
  char wsm_payload[1000]={0};
  
  for (int i=0;i<strlen(test)/2;i++)
  {
	  input[i]=getNum(test[i*2])*16+getNum(test[i*2+1]);
  }
  
  for (int j=0;j<strlen(test)/2;j++)
  {
	  if(input[j]==0x88 && input[j+1]==0xdc)
		  {
		  contentcount=j+2;
		  break;
		  }
  }
//  if(input[contentcount]==0x0b)
//  {
//	  n_extension_count = input[contentcount+1];
//	  contentcount=contentcount+2;
//	  printf("N-extension count: %d \n\n",n_extension_count);
//	  for(int l=0; l<n_extension_count ;l++)
//	  {
//		  printf("formoon come");
//		  if(input[contentcount]==15)
//		  {
//			  channel=input[contentcount+2];
//			  contentcount=contentcount+3;
//		  }
//		  else if(input[contentcount]==16)
//		  {
//			  rate=input[contentcount+2];
//			  contentcount=contentcount+3;
//		  }
//		  else if(input[contentcount]==4)
//		  {
//			  txpower=input[contentcount+2];
//			  contentcount=contentcount+3;
//		  }
//		  else 
//		  {
//			  contentcount=contentcount+3;
//		  }
//		  contentcount=contentcount+3;
//	  }
//  }

  

  //forchannelLoad
  if(n_extension_count>3)  contentcount=contentcount+3;
  
  tpid=input[contentcount];
  contentcount++;
  

  //psid = (p-encoded value)
  if(input[contentcount>=0x80])
  {
	  psid_p=input[contentcount];
	  contentcount=contentcount+1;
  }else if(input[contentcount>=0xb0])
  {
	  psid_p=input[contentcount]+input[contentcount]<<8;
	  contentcount=contentcount+2;
  }else if(input[contentcount>=0xc0])
  {
	  psid_p=input[contentcount]+input[contentcount+1]<<8+input[contentcount+2]<<16;
	  contentcount=contentcount+3;
  }else if(input[contentcount>=0xe0])
  {
	  psid_p=input[contentcount]+input[contentcount+1]<<8+input[contentcount+2]<<16+input[contentcount+3]<<24;
	  contentcount=contentcount+4;
  }
  wsm_length=input[contentcount];
  contentcount++;
  for(int k=0;k<strlen(test)/2-contentcount;k++)
  {
	  wsm_payload[k]=input[contentcount+k];
  }

  printf("channel: %d,%d,%d,%d,%d,%d\n%s\n\n",channel,rate,txpower,tpid,psid_p,wsm_length,wsm_payload);
  
  
  int psid_hex=0x81;
  //psid_p to psid_hex
  if(psid_hex<0x80)//1byte(p
  {
	  printf("under 0x80 \n\n");
	  psid_p=psid_hex;
  }else if(psid_hex<0x4080)//2byte(p
  {
	  printf("under 0x4080 \n\n");
	  if(psid_hex<0x100)
	  {
		  psid_p=psid_hex-0x80+0x8000;
	  }else
	  {
		  psid_p=psid_hex+0x7f80;
		  
	  }
  }else if(psid_hex<0x204080)//3byte(p
  {
	  psid_p=psid_hex+0xc00000-0x4080;
  }else if(psid_hex<0x10204080)//4byte(p
  {
	  psid_p=psid_hex+0xe0000000-0x204080;
  }
  printf("\n\nfinal psid is:  %02x\n\n",psid_p);

  //psid_p to psid_hex
  if(psid_p<0x80)//1byte(p
  {
	  psid_hex=psid_p;
  }else if(psid_p<0xc00000)//2byte(p
  {
	  psid_hex=psid_p-0x8000+0x80;
  }else if(psid_p<0xe0000000)//3byte(p
  {
	  psid_hex=psid_p-0xc00000+0x4080;
  }else
  {
	  psid_hex=psid_p-0xe0000000+0x204080;
  }
  
  printf("\n\nreturned psid is:  %02x\n\n",psid_hex);
  
  
  
  
  char instruction[100]={0};

  sprintf(instruction,"%s%s",instruction,"llc chconfig -s");
  sprintf(instruction,"%s%s",instruction," -c");
  sprintf(instruction,"%s%d",instruction,channel);
  sprintf(instruction,"%s%s",instruction," -m");
  sprintf(instruction,"%s%d",instruction,rate);
  sprintf(instruction,"%s%s",instruction," -p");
  sprintf(instruction,"%s%d",instruction,txpower);
  sprintf(instruction,"%s%s",instruction," -C");
  sprintf(instruction,"%s%d",instruction,psid_p);
  sprintf(instruction,"%s%s",instruction," -E");
  sprintf(instruction,"%s%s",instruction,wsm_payload);
  
  
  
  
  
  
  
  return 0;
}
