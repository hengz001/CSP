#include "tcpSvr.h"

#define	EM	(0x19)

void hsmCmdHandle(int sockfd)
{
	int len,rc,ilen,tlen,elen,cmd_rc,olen,prt_cmd;
	UCHAR *p , *q ,*r;
	unsigned char msg_trailer[128];

	struct combuf_t
	{
		unsigned char *i_buf;
		unsigned char *o_buf;
	} combuf;

	int  proto = TCP_MODE_TRANSPARENT;
	int  bufSize = HsmGetTcpBufSize();
	int msghdr_len = HsmTcpGetMsgHdrLen();
	int charset = HsmTcpGetCharSet();

	if((combuf.i_buf = (UCHAR *)malloc(sizeof(byte)*bufSize)) == NULL){
		return;
	}
	if((combuf.o_buf = (UCHAR *)malloc(sizeof(byte)*bufSize)) == NULL){
		return;
	}

	for(;;){
		olen = 0;
		len = bufSize;
		if((rc=comTcpReceive(sockfd, &combuf.i_buf[0],&len,0)) !=0 ){
			goto out;
		}

		ilen = hex2short(&combuf.i_buf[0]);

//		HexDumpBuffer(stdout,combuf.i_buf,2+ilen);
//		printf("\n-----------------------------------------------------\n");

		if(len != ilen + LEN_CMDLEN)
		{
			if(ilen > bufSize){
				continue;
			}
			len = ilen+LEN_CMDLEN;
		}
		*(combuf.i_buf + len) = 0;
		//
		if(ilen<LEN_CMDLEN+msghdr_len){
			goto out;
		}
		//
		p = combuf.i_buf + LEN_CMDLEN + msghdr_len;
		//
		q = combuf.o_buf + LEN_CMDLEN + msghdr_len;
		//
		r = NULL;
		if(hsmTcpTailerSupported())
		{
			r = (UCHAR *)FindMessageTrailer(p,len-(LEN_CMDLEN + msghdr_len),EM,charset);
			if(r != NULL){
				tlen = len - (r - combuf.i_buf);
				if(tlen>sizeof(msg_trailer)) tlen = sizeof(msg_trailer);
				if(tlen > 0)
				{
					memcpy(msg_trailer,r,tlen);
				}
			}

		}
		if(r==NULL){
			r = combuf.i_buf + len;
			tlen = 0;
		}
		elen = r - (p + LEN_CMDLEN);
		if(charset == CHARSET_IBM1388){

		}else if(charset==CHARSET_EBCDIC){

			int cnvlen = r-p;
			if(cnvlen <= 0){
				goto out;
			}
			if(isExpCmd(p,charset))
			{
				PreproExpCmd(proto,p,cnvlen,charset);
			}else{
				EbcdicToAscii(p,p,cnvlen);
			}
			elen = cnvlen - LEN_CMDCODE;
		}

		//
		memcpy(combuf.o_buf+LEN_CMDLEN,combuf.i_buf+LEN_CMDLEN,msghdr_len+LEN_CMDCODE);
		//主机命令处理
		cmd_rc = hsmCmdInterpret(charset,proto,p,elen,q,&olen,&prt_cmd);
		*(q+1) += 1;
		if(charset == CHARSET_IBM1388){
		}else if(charset==CHARSET_EBCDIC){
			AsciiToEbcdic(q, q, olen);
			olen += msghdr_len;
		}else{
			olen += msghdr_len + LEN_CMDCODE;
		}

		if(tlen > 0){
			memcpy(combuf.o_buf+LEN_CMDLEN,msg_trailer,tlen);
			olen += tlen;
		}
		short2hex(olen,combuf.o_buf);
		olen += LEN_CMDLEN;

//		HexDumpBuffer(stdout,combuf.o_buf,olen);
//		printf("\n-----------------------------------------------------\n");
		//
		if((rc = comTcpSend(sockfd, combuf.o_buf, &olen, HSM_TCP_SENDTIMER)) != 0)
		{
			goto out;
		}

		//
		if(phsmShm->hsmcfg.response_mode == RESPONSE_BEFORE_PRINT &&
				prt_cmd && isPrintFlagSet() && (cmd_rc == 0) && (rc == 0))
		{

		}
	}
	out:
		free(combuf.i_buf);
		free(combuf.o_buf);
	return ;
}
