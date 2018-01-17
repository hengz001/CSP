#include "stdafx.h"
#include "sjl22_api.h"

//NC
int testHSM(int comid, int msghdlen, char * msghd, char *chkvalue, char *version)
{
	char	*cmd, *p;
	int 	cmdlen, rsplen;
	char	rsp[MAX_MSGDATA + 1];

	int	ret;

	if (comid < 0)
		return -1;

	cmd = (char *)malloc(msghdlen 	/* Message head */
		+ 2		/* Command */
		+ 1);		/* 0x00 */

	if (cmd == NULL) return (-1);


	p = cmd;

	/* Messages head */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;


	/* COMMAND CODE 'NC' */
	*p++ = 'N';
	*p++ = 'C';


	*p = 0x00;

	cmdlen = p - cmd;

	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	free(cmd);

	if (ret < 0)
	{
		return (ret);
	}

	p = rsp;


	/* length:  2      hdln     2        2         16         18          x * 8
	// output: len + msghead + 'ND' +  errcode + chechvalue + SN       + version
	// offset: 0     2         2+hdln  4+hdln    6+hdln       22+hdln    40+hdln
   */


	if (chkvalue != NULL) {

		if (memcmp(chkvalue, p, 16)) {
			return -7;
		}
	}

	if (version != NULL) {
		memcpy(version, p + 34, rsplen - 34);
	}


	return 0;
}

/*SJL22 command "SD"*/
int encpasswd(int comid, int msghdlen, char * msghd, int passwdlen, char *passwd, char * epin)
{
	char	*cmd, *p;
	int 	cmdlen, rsplen;
	char	rsp[MAX_MSGDATA + 1];

	int	ret;

	if (comid < 0)
		return -1;

	if (passwdlen > MAX_PIN_SIZE)
	{
		return(-106);
	}

	cmd = (char *)malloc(msghdlen 	/* Message head */
		+ 2		/* Command */
		+ 4              /* passwdlen */
		+ passwdlen      /* passwd */
		+ 1);		/* 0x00 */

	if (cmd == NULL) return (-1);


	p = cmd;

	/* Messages head */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;


	/* COMMAND CODE 'SD' */
	*p++ = 'S';
	*p++ = 'D';

	sprintf((char *)p, "%04d", passwdlen);
	p += 4;

	memcpy(p, passwd, passwdlen);
	p += passwdlen;

	*p = 0x00;

	cmdlen = p - cmd;

	/*        //TraceMessage("sjl22.log", cmd, cmdlen);
	*/        ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);
	/*        //TraceMessage("sjl22.log", rsp, rsplen);
	*/
	free(cmd);

	if (ret < 0)
	{
		return (ret);
	}

	p = rsp;

	memcpy(epin, p, 16);

	p += 16;

	return 0;
}

/*SJL22 command "EH"*/
int genrsakey(int comid, int msghdlen, char *msghd,
	int key_usage,
	int mode_flag,
	int key_length,
	int public_key_encoding,
	int public_exponent_len,
	UCHAR *public_exponent,
	int index,
	int authenDataLen,
	UCHAR *authenData,
	UCHAR *public_key,
	int * public_key_len,
	UCHAR *mac,
	UCHAR *private_key,
	int *private_key_len,
	UCHAR * n, int * nlen,
	UCHAR * e, int * elen,
	UCHAR * d, int * dlen,
	UCHAR * prime1, int * prime1len,
	UCHAR * prime2, int * prime2len,
	UCHAR * dp, int * dplen,
	UCHAR * dq, int * dqlen,
	UCHAR * qinv, int * qinvlen
)
{
	UCHAR	*cmd, *p;
	int 	cmdlen, rsplen;
	UCHAR	rsp[MAX_MSGDATA + 1];
	int	ret;
	int     bytenums;

	/* Get public key exponent length from bits to bytes
*/	GetByteNum(public_exponent_len, &bytenums);

	if (bytenums <= 0)
	{
		return (-99);
	}
	/* If no authentication data provided
*/	if (authenDataLen < 0)
{
	authenDataLen = 0;
}

	if (authenDataLen > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (key_usage != 0 && key_usage != 1 && key_usage != 2 && key_usage != 3)
	{
		return (-99);
	}

	cmd = (UCHAR *)malloc(
		msghdlen +		/* Message head */
		2 + 		/* Command */
		1 + 		/* Key usage */
		1 + 		/* Mode flag */
		4 + 		/* Key length */
		2 + 		/* Public key encoding */
		4 + 		/* Public exponent length */
		bytenums + 		/* Public exponent */
		1 +		/* Terminator,value";" */
		authenDataLen +		/* Authentication data */
		1 +		/* Terminator,value";" */
		2 +		/* Private Key Location */
		1);

	if (cmd == NULL)	return (-1);


	p = cmd;


	/* Messages head */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	// COMMAND CODE 'EH'
	*/
	*p++ = 'E';
	*p++ = 'H';

	/* Key usage */
	*p++ = key_usage + '0';

	/* Mode flag */
	*p++ = mode_flag + '0';


	/* Key length :modulus length in bits */
	sprintf((char *)p, "%04d", key_length);
	p += 4;

	/* Public Key encoding */
	sprintf((char *)p, "%02d", public_key_encoding);
	p += 2;

	/* Public exponent length */
	sprintf((char *)p, "%04d", public_exponent_len);

	p += 4;

	/* Public exponent */
	memcpy(p, public_exponent, bytenums);
	p += bytenums;

	/* Terminator */
	*p++ = ';';


	/* Authentication data option */
	if (authenDataLen > 0)
	{
		memcpy(p, authenData, authenDataLen);
		p += authenDataLen;
	}

	/* Key index option */
	if (index >= 0 && index != 99)
	{
		/* Terminator */
		*p++ = ';';


		/* Private key Location */
		sprintf((char *)p, "%02d", index);
		p += 2;
	}


	*p = 0x00;

	cmdlen = p - cmd;



	/*        //TraceMessage("sjl22.log", cmd, cmdlen);
	*/
	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	/*        //TraceMessage("sjl22.log", rsp, rsplen);
	*/

	free(cmd);

	if (ret < 0)
	{

		return (ret);
	}


	p = rsp;

	/* Get the MAC of the Public key */
	memcpy(mac, p, 4);
	p += 4;

	/* Get Public key length */
	if (GetDerByteNum(p, (long *)public_key_len) < 0)
	{
		return (-197);
	}
	if (*public_key_len <= 0)
	{
		return (-197);
	}

	/* Get the Public key acording to the Public key length */
	memcpy(public_key, p, *public_key_len);
	p += *public_key_len;



	/* The output Private Key with the format "04" and "05" */
	if ((*private_key_len = dec2int((unsigned char*)p, 4)) < 0)
	{
		return -198;
	}
	p += 4;

	memcpy(private_key, p, *private_key_len);
	p += *private_key_len;

	if (3 == key_usage) {
		/* n */
		if ((*nlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(n, p, *nlen);
		p += *nlen;


		/* e */
		if ((*elen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(e, p, *elen);
		p += *elen;

		/* d */
		if ((*dlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(d, p, *dlen);
		p += *dlen;


		/* p */
		if ((*prime1len = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(prime1, p, *prime1len);
		p += *prime1len;


		/* q */
		if ((*prime2len = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(prime2, p, *prime2len);
		p += *prime2len;


		/* dp */
		if ((*dplen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(dp, p, *dplen);
		p += *dplen;


		/* dq */
		if ((*dqlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(dq, p, *dqlen);
		p += *dqlen;



		/* qinv */
		if ((*qinvlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(qinv, p, *qinvlen);
		p += *qinvlen;


	}

	return 0;

}

/*SJL22 command "SM"*/
int gensm2key(int comid, int msghdlen, char *msghd, int algflag,
	int key_usage,
	int compflag,
	int key_length,
	int index,
	int Plen,
	UCHAR *Pbuf,
	int Alen,
	UCHAR *Abuf,
	int Blen,
	UCHAR *Bbuf,
	int Gxlen,
	UCHAR *Gxbuf,
	int Gylen,
	UCHAR *Gybuf,
	int Nlen,
	UCHAR *Nbuf,
	UCHAR *public_key,
	int * public_key_len,
	UCHAR *private_key,
	int *private_key_len,
	UCHAR *derpubkey,
	int * derpubkeylen
)
{
	UCHAR	*cmd, *p;
	int 	cmdlen, rsplen;
	UCHAR	rsp[MAX_MSGDATA + 1];

	int	ret;



	if (key_usage != 0 && key_usage != 1 && key_usage != 2 && key_usage != 3)
	{
		return (-99);
	}

	cmd = (UCHAR *)malloc(
		msghdlen +		/* Message head */
		2 + 		/* Command */
		2 +             /* alg flag */
		1 + 		/* Key usage */
		2 + 		/* comp flag */
		4 + 		/* Key length */
		4 + 		/* Plen */
		Plen + 		/* P */
		4 + 		/* Plen */
		Alen + 		/* P */
		4 + 		/* Plen */
		Blen + 		/* P */
		4 + 		/* Plen */
		Gxlen + 		/* P */
		4 + 		/* Plen */
		Gylen + 		/* P */
		4 + 		/* Plen */
		Nlen + 		/* P */
		2 +		/* Private Key Location */
		1);

	if (cmd == NULL)	return (-1);


	p = cmd;


	/* Messages head */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	// COMMAND CODE 'SM'
	*/
	*p++ = 'S';
	*p++ = 'M';

	sprintf((char *)p, "%02d", algflag);
	p += 2;

	/* Key usage */
	*p++ = key_usage + '0';

	sprintf((char *)p, "%02d", compflag);
	p += 2;


	/* Key length :modulus length in bits */
	sprintf((char *)p, "%04d", 256);
	p += 4;

	sprintf((char *)p, "%02d", index);
	p += 2;


	*p = 0x00;

	cmdlen = p - cmd;



	/*        //TraceMessage("sjl22.log", cmd, cmdlen);
	*/
	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	/*        //TraceMessage("sjl22.log", rsp, rsplen);
	*/

	//        free(cmd);

	if (ret < 0)
	{
		////TraceMessage("sjl22.log", cmd, cmdlen);
		////TraceMessage("sjl22.log", rsp, rsplen);
		free(cmd);

		return (ret);
	}


	p = rsp;


	/* The output Private Key with the format "04" and "05" */
	if ((*public_key_len = dec2int((unsigned char*)p, 4)) < 0)
	{
		//TraceMessage("sjl22.log", cmd, cmdlen);
		//TraceMessage("sjl22.log", rsp, rsplen);
		free(cmd);
		return -198;
	}
	p += 4;

	/* Get the Public key acording to the Public key length */
	memcpy(public_key, p, *public_key_len);
	p += *public_key_len;



	/* The output Private Key with the format "04" and "05" */
	if ((*private_key_len = dec2int((unsigned char*)p, 4)) < 0)
	{
		//TraceMessage("sjl22.log", cmd, cmdlen);
		//TraceMessage("sjl22.log", rsp, rsplen);
		free(cmd);
		return -198;
	}
	p += 4;

	memcpy(private_key, p, *private_key_len);
	p += *private_key_len;

	/* The output Private Key with the format "04" and "05" */
	if ((*derpubkeylen = dec2int((unsigned char*)p, 4)) < 0)
	{
		//TraceMessage("sjl22.log", cmd, cmdlen);
		//TraceMessage("sjl22.log", rsp, rsplen);
		free(cmd);
		return -198;
	}
	p += 4;

	free(cmd);
	/* Get the Public key acording to the Public key length */
	memcpy(derpubkey, p, *derpubkeylen);
	p += *derpubkeylen;

	return 0;

}

/*SJL22 command "EW"*/
int rsaprisign(int comid, int msghdlen, char *msghd, int hash_id, int sign_id,
	int pad_mode,
	int mgfHash,
	int OAEP_parm_len,
	UCHAR *OAEP_parm,
	int pssRule,
	int trailerField,
	int data_length,
	UCHAR *data,
	int index,
	int private_key_len,
	UCHAR *private_key,
	UCHAR *sign,
	int *sign_length
)
{

	char	*cmd, *p;
	int 	cmdlen, rsplen;
	char	rsp[MAX_MSGDATA + 1];

	int     i_index;

	int	ret;


	if (index < 0 && private_key_len <= 0)
	{
		return -199;
	}


	if (index < 0 || index == 99)
	{
		i_index = 99;
	}
	else
	{
		i_index = index;
		private_key_len = 0;
	}


	switch (hash_id)
	{
	case HASH_MD2:
	case HASH_SHA1:
	case HASH_MD5:
	case HASH_ISO10118_2:
	case HASH_NOHASH:
	case HASH_MD4:
	case HASH_SHA224:
	case HASH_SHA256:
	case HASH_SHA384:
	case HASH_SHA512:
	case HASH_RIPEMD128:
	case HASH_RIPEMD160:
	case HASH_RIPEMD256:
	case HASH_RIPEMD320:
	case HASH_SM3:
		break;
	default:
		return (-198);
	}


	if (OAEP_parm_len < 0)
	{
		OAEP_parm_len = 0;
	}

	if (data_length > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (private_key_len > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (OAEP_parm_len > LEN_MAX_BLOCK)
	{
		return(-106);
	}


	cmd = (char *)malloc(msghdlen + 	/* Message head */
		2 + 		/* Command */
		2 + 		/* Hash identify */
		2 + 		/* Signature identifier */
		2 + 		/* Pad Mode */
		OAEP_parm_len + 11 +		/* OAEP */
		2 +		/* PSS trailer field */
		4 + 		/* Data length */
		data_length + 		/* Private Key output format */
		1 + 		/* Delimiter */
		2 + 		/* Private key flag */
		4 + 		/* Private length */
		private_key_len + 		/* Private key */
		1);		/* 0x00 */


	if (cmd == NULL) return (-1);

	p = cmd;

	/* Messages head */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	//COMMAND CODE 'EW'
	*/
	*p++ = 'E';
	*p++ = 'W';


	/* Hash identifier */
	sprintf((char *)p, "%02d", hash_id);
	p += 2;

	/* Signature identifier */
	sprintf((char *)p, "%02d", sign_id);
	p += 2;

	/* Pad mode identify */
	sprintf((char *)p, "%02d", pad_mode);
	p += 2;

	/* OAEP
*/        if (pad_mode == 2)
{
	rsaFormParmBlockOAEP((unsigned char **)&p, 1, mgfHash, OAEP_parm_len, OAEP_parm);
}
	/* PSS
*/        else if (pad_mode == 3)
{
	rsaFormParmBlockPSS((unsigned char **)&p, 1, mgfHash, pssRule, trailerField);
}


	/* Length of message data to be signed (in bytes) */
	sprintf((char *)p, "%04d", data_length);
	p += 4;

	/* Data to be signed */
	memcpy(p, data, data_length);
	p += data_length;


	/* Delimiter */
	*p++ = ';';


	/* Private key flag */
	sprintf((char *)p, "%02d", i_index);
	p += 2;


	if (i_index == 99)
	{
		/* Private key length */
		sprintf((char *)p, "%04d", private_key_len);
		p += 4;

		/* Private key */
		memcpy(p, private_key, private_key_len);
		p += private_key_len;
	}


	*p = 0x00;

	cmdlen = p - cmd;

	//	//TraceMessage("sjl22.log", cmd, cmdlen);


	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	//	//TraceMessage("sjl22.log", rsp, rsplen);

	free(cmd);

	if (ret < 0)
	{
		return (ret);
	}

	p = rsp;


	/* Get Signature length */
	if ((*sign_length = dec2int((unsigned char*)p, 4)) < 0)
	{
		return -198;
	}
	p += 4;



	/* Get the Signature */
	memcpy(sign, p, *sign_length);
	p += *sign_length;
	*(sign + (*sign_length)) = 0x00;

	return 0;

}

/*SJL22 command "EY"*/
int rsapubverify(int comid, int msghdlen, char *msghd, int hash_id, int sign_id,
	int pad_mode,
	int mgfHash,
	int OAEP_parm_len,
	UCHAR *OAEP_parm,
	int pssRule,
	int trailerField,
	int sign_length,
	UCHAR *sign,
	int data_len,
	UCHAR *data,
	int index,
	UCHAR *mac,
	UCHAR *public_key,
	int public_key_len,
	int authenDataLen,
	UCHAR *authenData
)
{

	char	*cmd, *p;
	int 	cmdlen, rsplen;
	int     len = 65;
	char	rsp[MAX_MSGDATA + 1];

	int	ret;


	if (((index < 0) || (index == 99)) && (sign_id == SIG_ALGO_RSA))
	{
		GetDerByteNum(public_key, (long *)&len);
		if (len != public_key_len)	return (-99);
	}
	else
	{
		authenDataLen = 0;
	}
	if (authenDataLen < 0)
	{
		authenDataLen = 0;
	}

	switch (hash_id)
	{
	case HASH_MD2:
	case HASH_SHA1:
	case HASH_MD5:
	case HASH_ISO10118_2:
	case HASH_NOHASH:
	case HASH_MD4:
	case HASH_SHA224:
	case HASH_SHA256:
	case HASH_SHA384:
	case HASH_SHA512:
	case HASH_RIPEMD128:
	case HASH_RIPEMD160:
	case HASH_RIPEMD256:
	case HASH_RIPEMD320:
	case HASH_SM3:
		break;
	default:
		return (-198);
	}
	if (OAEP_parm_len < 0)
	{
		OAEP_parm_len = 0;
	}

	if (sign_length > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (data_len > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (OAEP_parm_len > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (authenDataLen > LEN_MAX_BLOCK)
	{
		return(-106);
	}


	cmd = (char *)malloc(msghdlen + 	/* Message head */
		2 + 		/* Command */
		2 +		/* Hash identifier */
		2 +		/* Signature Identifier */
		2 + 		/* Pad Mode identify */
		OAEP_parm_len + 11 +		/* OAEP */
		2 +		/* PSS trailer field */
		4 + 		/* Signature length */
		sign_length +		/* Signature */
		1 + 		/* Delimiter */
		4 + 		/* data length */
		data_len +		/* data */
		1 + 		/* Delimiter */
		4 + 		/* Public MAC */
		public_key_len + 		/* Public exponent */
		authenDataLen +		/* Authentication data */
		1);


	if (cmd == NULL) return (-1);

	p = cmd;

	/* Messages head */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	//COMMAND CODE 'EY'
	*/
	*p++ = 'E';
	*p++ = 'Y';


	/* Hash identifier */
	sprintf((char *)p, "%02d", hash_id);
	p += 2;

	/* Signature identifier */
	sprintf((char *)p, "%02d", sign_id);
	p += 2;

	/* Pad mode identify */
	sprintf((char *)p, "%02d", pad_mode);
	p += 2;

	if (pad_mode == 2)
	{
		rsaFormParmBlockOAEP((unsigned char **)&p, 1, mgfHash, OAEP_parm_len, OAEP_parm);
	}
	else if (pad_mode == 3)
	{
		rsaFormParmBlockPSS((unsigned char **)&p, 1, mgfHash, pssRule, trailerField);
	}

	/* Signature Length */
	sprintf((char *)p, "%04d", sign_length);
	p += 4;

	/* Signature */
	memcpy(p, sign, sign_length);
	p += sign_length;

	*p++ = ';';

	/* Signature Data Length */
	sprintf((char *)p, "%04d", data_len);
	p += 4;

	/* Signature Data */
	memcpy(p, data, data_len);
	p += data_len;

	*p++ = ';';

	if ((index < 0) || (index == 99))
	{
		/* MAC */
		if (sign_id == SIG_ALGO_RSA) {
			memset(p, 0x00, 4);
			p += 4;
			/* Public key */
			memcpy(p, public_key, len);
			p += len;
			/* Authentication data option */
			if (authenDataLen > 0)
			{
				memcpy(p, authenData, authenDataLen);
				p += authenDataLen;
			}
		}
		else {
			sprintf((char *)p, "%04d", public_key_len);
			p += 4;

			/* Public key */
			memcpy(p, public_key, public_key_len);
			p += public_key_len;
		}




	}
	else
	{
		/* Flag */
		*p++ = 'T';

		sprintf((char *)p, "%02d", index);
		p += 2;
	}


	*p = 0x00;

	cmdlen = p - cmd;

	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);



	free(cmd);

	if (ret < 0)
	{

		return (ret);
	}

	return 0;

}

/* RSA Private key operation - EP */
int rsaprikeyoper(
	int comid,
	int msghdlen, char * msghd,
	int sig_alg,
	int enc_flag,
	int pad_mode,
	int mgfHash,
	int OAEP_parm_len,
	UCHAR *OAEP_parm,
	int data_length,
	UCHAR *data,
	int index,
	int private_key_len,
	UCHAR *private_key,
	UCHAR *sign,
	int *sign_length
)
{
	char    *cmd, *p;
	int     cmdlen, rsplen;
	char	rsp[MAX_MSGDATA + 1];

	int 	ret;

	int     i_index;


	if (enc_flag != 0 && enc_flag != 1)
	{
		return (-105);
	}
	if (index < 0 && private_key_len <= 0)
	{
		return (-115);
	}
	if (index < 0 || index == 99)
	{
		i_index = 99;
	}
	else
	{
		private_key_len = 0;
		i_index = index;
	}

	if (OAEP_parm_len < 0)
	{
		OAEP_parm_len = 0;
	}

	if (data_length > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (private_key_len > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (OAEP_parm_len > LEN_MAX_BLOCK)
	{
		return(-106);
	}



	cmd = (char *)malloc(
		msghdlen +		/* Message head */
		2 + 		/* Command */
		2 + 		/* Encryption identifier */
		1 +		/* Encryption flag */
		2 + 		/* Pad Mode */
		OAEP_parm_len + 11 +		/* OAEP */
		4 + 		/* Data length */
		data_length + 		/* Private Key output format */
		1 + 		/* Delimiter */
		2 + 		/* Private key flag */
		4 + 		/* Private length */
		private_key_len + 		/* Private key */
		1);

	if (cmd == NULL)	return (-1);

	p = cmd;

	/* Messages head */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	// COMMAND CODE 'EP'
	*/
	*p++ = 'E';
	*p++ = 'P';

	/* Encryption identifier */
	sprintf((char *)p, "%02d", sig_alg);
	p += 2;

	/* Encryption flag: 0 - Encrypt, 1 - Decrypt */
	*p++ = enc_flag + '0';

	/* Pad mode identify */
	sprintf((char *)p, "%02d", pad_mode);
	p += 2;

	if (pad_mode == 2)
	{
		rsaFormParmBlockOAEP((unsigned char **)&p, 1, mgfHash, OAEP_parm_len, OAEP_parm);
	}

	/* Length of message data to be signed (in bytes) */
	sprintf((char *)p, "%04d", data_length);
	p += 4;

	/* Data to be signed */
	memcpy(p, data, data_length);
	p += data_length;


	/* Delimiter */
	*p++ = ';';

	/* Private key flag */
	sprintf((char *)p, "%02d", i_index);
	p += 2;

	if (i_index == 99)
	{
		/* Private key length */
		sprintf((char *)p, "%04d", private_key_len);
		p += 4;

		/* Private key */
		memcpy(p, private_key, private_key_len);
		p += private_key_len;
	}



	*p = 0x00;

	cmdlen = p - cmd;

	/*        //TraceMessage("sjl22.log", cmd, cmdlen);
	*/	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	/*        //TraceMessage("sjl22.log", rsp, rsplen);
	*/        free(cmd);

	if (ret < 0)
	{

		return (ret);
	}



	p = rsp;


	/* Get Signature length */
	if ((*sign_length = dec2int((unsigned char*)p, 4)) < 0)
	{
		return -198;
	}
	p += 4;

	/* Get the Signature */
	memcpy(sign, p, *sign_length);
	p += *sign_length;

	return 0;
}

/* RSA Public key operation - ER */
int rsapubkeyoper(
	int comid,
	int msghdlen, char * msghd,
	int sig_alg,
	int dec_flag,
	int pad_mode,
	int mgfHash,
	int OAEP_parm_len,
	UCHAR *OAEP_parm,
	int sign_length,
	UCHAR *sign,
	int index,
	UCHAR *mac,
	UCHAR *public_key,
	int public_key_len,
	int authenDataLen,
	UCHAR *authenData,
	UCHAR *data,
	int *data_len
)
{
	char    *cmd, *p;
	int     cmdlen, rsplen, len = 0;
	char	rsp[MAX_MSGDATA + 1];

	int 	ret;


	if (dec_flag != 0 && dec_flag != 1)
	{
		return (-105);
	}

	if (OAEP_parm_len < 0)
	{
		OAEP_parm_len = 0;
	}




	if (((index < 0) || (index == 99)) && (sig_alg == SIG_ALGO_RSA))
	{
		GetDerByteNum(public_key, (long *)&len);
		if (len != public_key_len)	return (-99);
	}
	else
	{
		authenDataLen = 0;
	}

	if (authenDataLen < 0)
	{
		authenDataLen = 0;
	}

	if (sign_length > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (authenDataLen > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (OAEP_parm_len > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	cmd = (char *)malloc(
		msghdlen +		/* Message head */
		2 + 		/* Command */
		2 +		/* Signature Identifier */
		1 + 		/* Decryption flag */
		2 + 		/* Pad Mode */
		OAEP_parm_len + 11 +		/* OAEP */
		4 + 		/* Signature length */
		sign_length +		/* Signature */
		1 + 		/* Delimiter */
		4 + 		/* Public MAC */
		public_key_len + 		/* Public exponent */
		authenDataLen +		/* Authentication data */
		1);		/* 0x00 */

	if (cmd == NULL)
	{
		return (-1);
	}

	p = cmd;


	/* Messages head */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;


	/*
	// COMMAND CODE 'ER'
	*/
	*p++ = 'E';
	*p++ = 'R';

	/* Signature identifier */
	sprintf((char *)p, "%02d", sig_alg);
	p += 2;

	/* Decryption flag: 0 - Decrypt, 1 - Encrypt */
	*p++ = (dec_flag + 1) % 2 + '0';

	/* Pad mode identify */
	sprintf((char *)p, "%02d", pad_mode);
	p += 2;

	if (pad_mode == 2)
	{
		rsaFormParmBlockOAEP((unsigned char **)&p, 1, mgfHash, OAEP_parm_len, OAEP_parm);
	}

	/* Signature Length */
	sprintf((char *)p, "%04d", sign_length);

	p += 4;

	/* Signature */
	memcpy(p, sign, sign_length);
	p += sign_length;

	*p++ = ';';

	if ((index >= 0) && (index != 99))
	{
		*p++ = 'T';

		/* Key index */
		sprintf((char *)p, "%02d", index);
		p += 2;
	}
	else
	{
		/* MAC */
/*		memcpy(p, mac, 4);
 *///                memset(p, 0x00, 4);
 // 		p += 4;
 // 
 // 		/* Public key */
 // 		memcpy(p, public_key, len);
 // 		p += len;


		if (sig_alg == SIG_ALGO_RSA) {
			memset(p, 0x00, 4);
			p += 4;
			/* Public key */
			memcpy(p, public_key, len);
			p += len;
			/* Authentication data */
			if (authenDataLen > 0)
			{
				memcpy(p, authenData, authenDataLen);
				p += authenDataLen;
			}
		}
		else {
			sprintf((char *)p, "%04d", public_key_len);
			p += 4;

			/* Public key */
			memcpy(p, public_key, public_key_len);
			p += public_key_len;
		}


	}


	*p = 0x00;

	cmdlen = p - cmd;

	/*        //TraceMessage("sjl22.log", cmd, cmdlen);
	*/	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	/*        //TraceMessage("sjl22.log", rsp, rsplen);
	*/
	free(cmd);

	if (ret < 0)
	{
		return (ret);
	}



	p = rsp;

	/* Get Data length */
	if ((*data_len = dec2int((unsigned char*)p, 4)) < 0)
	{
		return -198;
	}
	p += 4;

	/* Get the message data  */
	memcpy(data, p, *data_len);
	p += *data_len;

	return 0;
}

/* Import RSA key pair - EL */
int importrsakey(
	int comid,
	int msghdlen, char * msghd,
	int algo,
	int key_usage,
	int import_mode,
	int componentID,
	int outputFlag,
	int modulus_len,
	int dec_mode,
	int ifm,
	int keyTypeMode,
	int keyType,
	int keyLen,
	UCHAR *keyLmk,
	UCHAR *iv,
	int component1_len,
	UCHAR *component1,
	int component2_len,
	UCHAR *component2,
	int public_key_encoding,
	int public_exponent_len,
	UCHAR *public_exponent,
	int index,
	int authenDataLen,
	UCHAR *authenData,
	UCHAR *public_key,
	int * public_key_len,
	UCHAR *mac,
	UCHAR *private_key,
	int *private_key_len,
	UCHAR * n, int * nlen,
	UCHAR * e, int * elen,
	UCHAR * d, int * dlen,
	UCHAR * prime1, int * prime1len,
	UCHAR * prime2, int * prime2len,
	UCHAR * dp, int * dplen,
	UCHAR * dq, int * dqlen,
	UCHAR * qinv, int * qinvlen
)

{
	char    *cmd, *p;
	int     cmdlen, rsplen;
	int     bytenums;
	char	rsp[MAX_MSGDATA + 1];

	int 	ret;

	int     ivLen = 0;
	int     keylen = 0;


	GetByteNum(public_exponent_len, &bytenums);

	if (bytenums <= 0)
	{
		return (-195);
	}
	if (authenDataLen < 0)
	{
		authenDataLen = 0;
	}
	if (authenDataLen > LEN_MAX_BLOCK)
	{
		return(-106);
	}
	if (key_usage != 0 && key_usage != 1 && key_usage != 2 && key_usage != 3)
	{
		return (-196);
	}
	if (import_mode != 0 && import_mode != 2 && import_mode != 3 && import_mode != 4)
	{
		return (-197);
	}
	if (componentID != 0 && componentID != 1 && componentID != 2)
	{
		return (-198);
	}
	if (outputFlag != 0 && outputFlag != 1)
	{
		return (-199);
	}
	if (import_mode)
	{
		/* WK encrypted under the LMK*/
		keylen = GetKeyLen((char *)keyLmk);

		if (dec_mode != 0 && dec_mode != 1)
		{
			return (-115);
		}
		if (dec_mode == 1)
		{
			if ((ivLen = GetIvLength(algo)) < 0)
			{
				return (ivLen);
			}
		}
	}
	switch (ifm)
	{
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
		break;
	default:
		return (-115);
	}
	if (keyTypeMode != 0 && keyTypeMode != 1)
	{
		return (-115);
	}

	if (component1_len > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (component2_len > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	cmd = (char *)malloc(
		msghdlen +		/* Message head */
		2 + 		/* Command */
		3 +		/* Algorithm identification block */
		1 + 		/* Key usage */
		1 +		/* Import mode */
		1 + 		/* Component identifier */
		1 +		/* Output flag */
		4 + 		/* Modulus length */
		(import_mode ? 1 : 0) +		/* Decryption mode */
		(import_mode ? 1 : 0) +		/* Import Pad format mode */
		(import_mode ? 1 : 0) +		/* Key type mode */
		(import_mode ? 4 : 0) +		/* Key type */
		(import_mode ? 1 : 0) +		/* Key length */
		keylen +		/* Key under LMK */
		ivLen * 4 +		/* Key initial vector */
		4 +		/* Component #1 length */
		component1_len +		/* Component #1	*/
		4 +		/* Component #2 length */
		component2_len +		/* Component #2	*/
		2 + 		/* Public key encoding */
		4 + 		/* Public exponent length */
		bytenums + 		/* Public exponent */
		1 +		/* Terminator,value";" */
		authenDataLen +		/* Authentication data */
		1 +		/* Terminator,value";" */
		2 +		/* Private Key Location */
		1);

	if (cmd == NULL)	return (-1);


	p = cmd;


	/* Message header */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	// COMMAND CODE 'EL'
	*/
	*p++ = 'E';
	*p++ = 'L';

	/* Algorithm identification block */
	*p++ = 'P';
	*p++ = algo + '0';
	*p++ = algo + '0';


	/* Key usage */
	*p++ = key_usage + '0';

	/* Import Mode flag: 0 - Clear, 2 - Encrypted by GVI, 3 - THALES ZMK, 4 - JK index */
	*p++ = import_mode + '0';

	/* Component identifier */
	*p++ = componentID + '0';

	/* Output flag */
	*p++ = outputFlag + '0';


	/* Key length :modulus length in bits */
	sprintf((char *)p, "%04d", modulus_len);
	p += 4;

	/* Ecnrypted components mode */
	if (import_mode == 3)
	{
		/* Decryption mode */
		*p++ = dec_mode + '0';

		/* Import Pad format mode */
		*p++ = ifm + '0';


		/* Decryption key type */
		if (keyTypeMode)
		{
			sprintf((char *)p, "%04d", keyType);
			p += 4;
		}
		else
		{
			sprintf((char *)p, "%03d", keyType);
			p += 3;
		}

		/* Decryption key length */
		*p++ = keyLen + '0';


		/* Decryption key under LMK */
		memcpy(p, keyLmk, keylen);
		p += keylen;

		if (dec_mode)
		{
			memcpy(p, iv, ivLen);
			p += ivLen;
		}
	}
	/* Component #1 length */
	sprintf((char *)p, "%04d", component1_len);
	p += 4;

	/* Component #1 */
	memcpy(p, component1, component1_len);
	p += component1_len;

	/* Component #2 length */
	sprintf((char *)p, "%04d", component2_len);
	p += 4;

	/* Component #1 */
	memcpy(p, component2, component2_len);
	p += component2_len;

	/* Public Key encoding */
	sprintf((char *)p, "%02d", public_key_encoding);
	p += 2;

	/* Public exponent length */
	sprintf((char *)p, "%04d", public_exponent_len);
	p += 4;

	/* Public exponent */
	memcpy(p, public_exponent, bytenums);
	p += bytenums;

	/* Terminator */
	*p++ = ';';

	/* Authentication data option */
	if (authenDataLen > 0)
	{
		memcpy(p, authenData, authenDataLen);
		p += authenDataLen;
	}

	/* Key index option */
	if (index >= 0 && index != 99)
	{
		/* Terminator */
		*p++ = ';';


		/* Private key Location */
		sprintf((char *)p, "%02d", index);
		p += 2;
	}

	*p = 0x00;

	cmdlen = p - cmd;

	/*        //TraceMessage("sjl22.log", cmd, cmdlen);
	*/
	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	/*        //TraceMessage("sjl22.log", rsp, rsplen);
	*/
	free(cmd);

	if (ret < 0)
	{
		return (ret);
	}


	p = rsp;

	/* Get the MAC of the Public key */
	memcpy(mac, p, 4);
	p += 4;

	/* Get Public key length */
	if (GetDerByteNum((unsigned char *)p, (long *)public_key_len) < 0)
	{
		return (-197);
	}
	if (*public_key_len <= 0)
	{
		return (-197);
	}

	/* Get the Public key acording to the Public key length */
	memcpy(public_key, p, *public_key_len);
	p += *public_key_len;

	/* The output Private Key with the format "04" and "05" */
	if ((*private_key_len = dec2int((unsigned char*)p, 4)) < 0)
	{
		return -198;
	}
	p += 4;

	memcpy(private_key, p, *private_key_len);
	p += *private_key_len;


	if (3 == key_usage) {
		/* n */
		if ((*nlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(n, p, *nlen);
		p += *nlen;


		/* e */
		if ((*elen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(e, p, *elen);
		p += *elen;

		/* d */
		if ((*dlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(d, p, *dlen);
		p += *dlen;


		/* p */
		if ((*prime1len = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(prime1, p, *prime1len);
		p += *prime1len;


		/* q */
		if ((*prime2len = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(prime2, p, *prime2len);
		p += *prime2len;


		/* dp */
		if ((*dplen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(dp, p, *dplen);
		p += *dplen;


		/* dq */
		if ((*dqlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(dq, p, *dqlen);
		p += *dqlen;



		/* qinv */
		if ((*qinvlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(qinv, p, *qinvlen);
		p += *qinvlen;


	}

	return 0;
}

/*SJL22 command "EX"*/
int exportrsakey(
	int comid,
	int msghdlen, char * msghd,
	int algo,
	int dec_mode,
	int enc_mode,
	int ofm,
	/*
					char * deckeyType,	// Decryption Key type
					int deckeyLen,		// Decryption key length
					char *deckeyLmk,	// Decryption Key encrypted under LMK
					char *decIv,		// Decryption key initial vector*/
	UCHAR * enckeyType,
	int enckeyLen,
	UCHAR *enckeyLmk,
	UCHAR *encIv,
	int index,
	int data_len,
	UCHAR *data,
	UCHAR *n,
	int *nlen,
	UCHAR *e,
	int *elen,
	UCHAR *d,
	int *dlen,
	UCHAR *p1,
	int *plen,
	UCHAR *q1,
	int *qlen,
	UCHAR *d1,
	int *d1len,
	UCHAR *d2,
	int *d2len,
	UCHAR *inv,
	int *invlen
)
{
	char    *cmd, *p;
	int     cmdlen, rsplen;
	char    rsp[MAX_MSGDATA + 1];


	int 	ret;


	int     i_index;


	if (enckeyLen > 49)
	{
		return(-106);
	}

	if (data_len > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (index < 0 && data_len <= 0)
	{
		return -199;
	}
	if ((index < 0) || (index == 99))
	{
		i_index = 99;
	}
	else
	{
		i_index = index;
		data_len = 0;
	}


	/*	if(dec_mode != 0 && dec_mode != 1 && dec_mode != 3)
	*/        if (dec_mode != 3 && dec_mode != 4)
	{
		return -101;
	}

	if (enc_mode != 0 && enc_mode != 1)
	{
		return -102;
	}



	/* Encrypt Key Length */
	if (enckeyLen != 8 && enckeyLen != 16 && enckeyLen != 24)
	{
		return (-198);
	}



	cmd = (char *)malloc(
		msghdlen + 		/* Message head */
		2 + 		/* Command */
		3 +		/* Algorithm identifier - Pxx */
		1 + 		/* Decrypt Mode: 0 - ECB, 1 - CBC, 3 - RSA, 4 - SM2 */
		1 + 		/* Encrypt Mode: 0 - ECB, 1 - CBC */
		1 + 		/* Output format mode */
		1 + 		/* Key type mode: 0 - Normal, 1 - compatiable with THALES RSA */
		4 + 		/* Decryption Key Type */
		1 + 		/* Decrypt Key Length */
		49 + 		/* Decryption Key */
		48 + 		/* Decryption IV */
		4 + 		/* Decryption Key Type */
		1 + 		/* Encrypt Key Length */
		49 + 		/* Encryption Key */
		48 + 		/* Encryption IV */
		4 + 		/* Sensitive Data length */
		data_len + 		/* Sensitive Data  */
		1);		/* 0x00 */

	if (cmd == NULL)
	{
		return (-1);
	}

	p = cmd;

	/* Messages head */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	// COMMAND CODE 'EX'
	*/
	*p++ = 'E';
	*p++ = 'X';

	/* Algorithm identification block */
	*p++ = 'P';
	//	sprintf((char *)p, "%02d", algo);
	//	p += 2;
	*p++ = '0' + algo;
	*p++ = '0' + algo;



	/* Decrypt/Encrypt Mode */
	*p++ = dec_mode + '0';
	*p++ = enc_mode + '0';

	/* Output format mode */
	*p++ = ofm + '0';



	/* Encryption Key Type */

/*		sprintf((char *)p, "%03d", enckeyType);
*/        memcpy(p, enckeyType, 3);
	p += 3;


	/* Encrypt Key Length */
	*p++ = (enckeyLen / 8) - 1 + '0';

	if (enckeyLen == 16) {
		*p++ = 'X';
	}
	if (enckeyLen == 24) {
		*p++ = 'Y';
	}


	/*	memcpy(p, enckeyLmk, keylen);
	*/        UnpackBCD(enckeyLmk, p, enckeyLen * 2);
	p += enckeyLen * 2;

	/* Encryption IV */
	if (enc_mode)
	{
		/*		memcpy(p, encIv, 8);
		//		p += 8;
		*/
		if (algo == ALGO_DESTDES) {
			UnpackBCD(encIv, p, 16);
			p += 16;
		}
		else {
			UnpackBCD(encIv, p, 32);
			p += 32;

		}
	}

	if (dec_mode == 3 || dec_mode == 4)
	{
		sprintf((char *)p, "%02d", i_index);
		p += 2;

		if (i_index == 99)
		{
			/* Sensitive Data Length */
			sprintf((char *)p, "%04d", data_len);
			p += 4;

			/* Sensitive Data */
			memcpy(p, data, data_len);
			p += data_len;
		}
	}
	else
	{
		/* Sensitive Data Length */
		sprintf((char *)p, "%04d", data_len);
		p += 4;

		/* Sensitive Data */
		memcpy(p, data, data_len);
		p += data_len;
	}

	*p = 0x00;

	cmdlen = p - cmd;

	/*        //TraceMessage("sjl22.log", cmd, cmdlen);
	*/	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	/*        //TraceMessage("sjl22.log", rsp, rsplen);
	*/        free(cmd);

	if (ret < 0)
	{
		return (ret);
	}


	p = rsp;

	if ((*nlen = dec2int((unsigned char*)p, 4)) < 0)
	{
		return -98;
	}
	p += 4;

	/* Encrypted Sensitive Data or RSA private exponent N */
	memcpy(n, p, *nlen);
	p += *nlen;

	if (dec_mode == 3)
	{
		if ((*elen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -98;
		}
		p += 4;

		/* Encrypted Sensitive Data */
		memcpy(e, p, *elen);
		p += *elen;

		if ((*dlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -98;
		}
		p += 4;

		/* Encrypted Sensitive Data */
		memcpy(d, p, *dlen);
		p += *dlen;

		if ((*plen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -98;
		}
		p += 4;

		/* Encrypted Sensitive Data */
		memcpy(p1, p, *plen);
		p += *plen;

		if ((*qlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -98;
		}
		p += 4;

		/* Encrypted Sensitive Data */
		memcpy(q1, p, *qlen);
		p += *qlen;

		if ((*d1len = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -98;
		}
		p += 4;

		/* Encrypted Sensitive Data */
		memcpy(d1, p, *d1len);
		p += *d1len;

		if ((*d2len = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -98;
		}
		p += 4;

		/* Encrypted Sensitive Data */
		memcpy(d2, p, *d2len);
		p += *d2len;

		if ((*invlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -98;
		}
		p += 4;

		/* Encrypted Sensitive Data */
		memcpy(inv, p, *invlen);
		p += *invlen;

	}
	if (dec_mode == 4) {
		if ((*dlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -98;
		}
		p += 4;

		/* Encrypted Sensitive Data */
		memcpy(d, p, *dlen);
		p += *dlen;
	}

	return 0;
}

/* Import DES key Use Racal Command GI */
int importrsadeskey(
	int comid,
	int msghdlen, char * msghd,
	int algo,
	int sig_alg,
	int pad_mode,
	int mgfHash,
	int OAEP_parm_len,
	UCHAR *OAEP_parm,
	int keyBlockType,
	int keyBlockTemplateLen,
	UCHAR *keyBlockTemplate,
	int keyOffset,
	int chkLen,
	int chkOffset,
	int keyTypeMode,
	UCHAR * keyType,
	int data_length,
	UCHAR *data,
	int index,
	int private_key_len,
	UCHAR *private_key,
	UCHAR lmkSchem,
	int cvFlag,
	UCHAR *iv,
	UCHAR *cv,
	UCHAR *wkLmk,
	int * keylen
)
{
	char    *cmd, *p;
	int     cmdlen, rsplen;
	char    rsp[MAX_MSGDATA + 1];

	int     ivLen = 8;
	int     cvLen;
	int     keyBlockLen = 0;
	int     keyBlock_Type = 1;

	int 	ret;
	int     i_index;


	/* Get IV length
//	if((ivLen = GetIvLength(algo)) < 0)
//	{
//		return (ivLen);
//	}
*/
	if (data_length > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (private_key_len > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	switch (pad_mode)
	{
	case 1:
	case 2:
	case 4:
		break;
	default:
		return (-1);
	}

	if (index < 0 && private_key_len <= 0)
	{
		return -99;
	}
	if ((index < 0) || (index == 99))
	{
		i_index = 99;
	}
	else
	{
		i_index = index;
		private_key_len = 0;
	}

	cvLen = GetCvLength((char)cvFlag);

	if (OAEP_parm_len < 0)
	{
		OAEP_parm_len = 0;
	}
	if (keyBlockType == 1 || keyBlockType == 2 || keyBlockType == 3)
	{
		keyBlock_Type = keyBlockType;
	}
	if (chkLen < 0 || chkLen > 8)
	{
		return (-2);
	}
	if (keyBlock_Type == 2)
	{
		/* 4bytes template length + template + delimeter +
		// 4bytes Key offset + 1byte Check length + 4bytes check value offset
*/		keyBlockLen = 4 + keyBlockTemplateLen + 1 + 4 + 1 + 4;
	}

	if (keyBlockLen > LEN_MAX_BLOCK)
	{
		return(-106);
	}


	cmd = (char *)malloc(
		msghdlen +		/* Message head */
		2 + 		/* Command */
		3 +		/* Algorithm identifier - Pxx */
		2 +		/* Encryption identifier */
		2 + 		/* Pad Mode identifier */
		2 +
		2 +
		2 +
		OAEP_parm_len + 11 +		/* OAEP */
		1 +
		4 + 		/* Des key type */
		4 + 		/* Data length */
		data_length + 		/* Private Key output format */
		1 + 		/* Delimiter */
		2 + 		/* Private key flag */
		4 + 		/* Private length */
		private_key_len + 		/* Private key */
		1 +		/* ; */
		3 +		/* 0U0 */
		1 +		/* Delimeter '=' */
		2 +		/* Key block type */
		keyBlockLen +		/* Key block length */
		ivLen * 4 +
		1);		/* 0x00 */

	if (cmd == NULL)	return (-1);

	p = cmd;


	/* Messages head */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	// RACAL COMMAND CODE 'GI'
	*/
	*p++ = 'G';
	*p++ = 'I';

	/* Algorithm */
	*p++ = 'P';
	//	sprintf((char *)p, "%02d", algo);
	//	p += 2;
	*p++ = '0' + algo;
	*p++ = '0' + algo;


	/* Encryption identifier */
	sprintf((char *)p, "%02d", sig_alg);
	p += 2;

	/* Pad mode identify */
	sprintf((char *)p, "%02d", pad_mode);
	p += 2;

	if (pad_mode == 2)
	{
		rsaFormParmBlockOAEP((unsigned char **)&p, 1, mgfHash, OAEP_parm_len, OAEP_parm);
	}

	/* DES key type */
	if (keyTypeMode == 1)
	{
		/*                sprintf((char *)p, "%04d", keyType);
		*/                memcpy(p, keyType, 4);
	p += 4;
	}
	else
	{
		/*		sprintf((char *)p, "%03d", keyType);
		*/                memcpy(p, keyType, 3);
	p += 3;
	}

	/* Length of encrypted DES Key data */
	sprintf((char *)p, "%04d", data_length);
	p += 4;

	/* Data to be decrypted */
	memcpy(p, data, data_length);
	p += data_length;


	/* Delimiter */
	*p++ = ';';

	/* Private key flag */
	sprintf((char *)p, "%02d", i_index);
	p += 2;

	if (i_index == 99)
	{
		/* Private key length */
		sprintf((char *)p, "%04d", private_key_len);
		p += 4;

		/* Private key */
		memcpy(p, private_key, private_key_len);
		p += private_key_len;
	}
	/* Delimiter */
	*p++ = ';';

	/* ZMK scheme */
	*p++ = lmkSchem;

	/* LMK scheme */
	*p++ = lmkSchem;

	/* CV flag */
	*p++ = cvFlag + '0';

	/* Delimeter '=' */
	*p++ = '=';


	/* Key block type */
	sprintf((char *)p, "%02d", keyBlock_Type);
	p += 2;

	/* If kyeBlock_Type = 2, there is a key block option
*/	if (keyBlock_Type == 2)
{
	/* Key block template length */
	sprintf((char *)p, "%04d", keyBlockTemplateLen);
	p += 4;

	/* Key block template */
	memcpy(p, keyBlockTemplate, keyBlockTemplateLen);
	p += keyBlockTemplateLen;

	/* Delimeter ';' */
	*p++ = ';';

	/* Key offset within the key block */
	sprintf((char *)p, "%04d", keyOffset);
	p += 4;

	/* Check value length */
	*p++ = chkLen + '0';

	/* Check value offset within the key block */
	sprintf((char *)p, "%04d", chkOffset);
	p += 4;
}

	*p = 0x00;

	cmdlen = p - cmd;

	/*        //TraceMessage("sjl22.log", cmd, cmdlen);
	*/
	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);
	/*        //TraceMessage("sjl22.log", rsp, rsplen);
	*/
	free(cmd);

	if (ret < 0)
	{

		return (ret);
	}



	p = rsp;

	switch (keyBlockType)
	{
	case 1:	/* Standard key type
//		memcpy(iv, p, ivLen);
*/                UnpackBCD((unsigned char*)p, (char *)iv, ivLen * 2);
		p += ivLen * 2;
		break;

	default:
		break;
	}

	/* WK encrypted under the LMK*/
/*	keylen = GetKeyLen(p);
*/
	if (*p == 'X') {
		*keylen = 16;
		p++;
	}
	if (*p == 'Y') {
		*keylen = 24;
		p++;
	}


	/*	memcpy(wkLmk, p, keylen);
	*/        PackBCD(p, wkLmk, (*keylen) * 2);
	p += (*keylen) * 2;

	*(wkLmk + *keylen) = 0;



	PackBCD(p, cv, cvLen);
	p += cvLen;




	return 0;
}

/* Racal RSA command GK - Export DES Key */
int exportrsadeskey(
	int comid,
	int msghdlen, char * msghd,
	int algo,
	int sig_alg,
	int pad_mode,
	int mgfHash,
	int OAEP_parm_len,
	UCHAR *OAEP_parm,
	int keyBlockType,
	int keyBlockTemplateLen,
	UCHAR *keyBlockTemplate,
	int keyOffset,
	int chkLen,
	int chkOffset,
	int keyLen,
	int keyTypeMode,
	UCHAR * keyType,
	UCHAR *wkLmk,
	int index,
	UCHAR *mac,
	UCHAR *public_key,
	int public_key_len,
	int authenDataLen,
	UCHAR *authenData,
	UCHAR *iv,
	UCHAR *cv,
	UCHAR *data,
	int *data_length
)

{
	char    *cmd, *p;
	int     cmdlen, rsplen;
	int     len = 0;
	int     keylen = 0;
	char    rsp[MAX_MSGDATA + 1];

	int     ivLen = 8;

	int 	ret;
	int     keyBlockLen = 0;
	int     keyBlock_Type = 1;


	if (keyLen > 49)
	{
		return(-106);
	}

	if (authenDataLen > LEN_MAX_BLOCK)
	{
		return(-106);
	}
	/* WK encrypted under the LMK*/
/*	keylen = GetKeyLen(wkLmk);
//printf("1\n");
*/	if (index < 0 && sig_alg == SIG_ALGO_RSA)
{
	GetDerByteNum(public_key, (long *)&len);
	if (len != public_key_len)	return (-99);
}
	switch (pad_mode)
	{
	case 1:
	case 2:
	case 4:
		break;
	default:
		return (-1);
	}
	if (OAEP_parm_len < 0)
	{
		OAEP_parm_len = 0;
	}
	if (keyBlockType == 1 || keyBlockType == 2 || keyBlockType == 3)
	{
		keyBlock_Type = keyBlockType;
	}
	if (chkLen < 0 || chkLen > 8)
	{
		return (-2);
	}
	if (keyBlock_Type == 2)
	{
		/* 4bytes template length + template + delimeter +
		// 4bytes Key offset + 1byte Check length + 4bytes check value offset
*/		keyBlockLen = 4 + keyBlockTemplateLen + 1 + 4 + 1 + 4;
	}



	cmd = (char *)malloc(
		msghdlen +		/* Message head */
		2 + 		/* Command */
		3 +		/* Algorithm identifier - Pxx */
		2 +		/* Encryption identifier */
		2 + 		/* Pad Mode identify */
		OAEP_parm_len + 11 +		/* OAEP */
		4 + 		/* Des key type */
		1 +		/* Des key length */
		keyLen * 2 + 1 + 		/* key under LMK */
		1 + 		/* optional 'T' */
		ivLen * 4 +		/* IV */
		16 + 		/* DES key check value */
		1 +		/* Public key index identifier 'T' */
		2 +		/* Public key index */
		4 + 		/* Public MAC */
		len + 		/* Public key */
		authenDataLen +		/* Authentication data */
		1 +		/* Delimeter ';' */
		2 +		/* Key block type */
		keyBlockLen +		/* Key block length */
		1);

	if (cmd == NULL)	return (-1);

	p = cmd;


	/* Messages head */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	// RACAL COMMAND CODE 'GK'
	*/
	*p++ = 'G';
	*p++ = 'K';

	/* Algorithm */
	*p++ = 'P';
	//	sprintf((char *)p, "%02d", algo);
	//	p += 2;
	*p++ = '0' + algo;
	*p++ = '0' + algo;

	/* Encryption identifier */
	sprintf((char *)p, "%02d", sig_alg);
	p += 2;

	/* Pad mode identify */
	sprintf((char *)p, "%02d", pad_mode);
	p += 2;

	if (pad_mode == 2)
	{
		rsaFormParmBlockOAEP((unsigned char **)&p, 1, mgfHash, OAEP_parm_len, OAEP_parm);
	}

	/* DES key type */
	if (keyTypeMode == 1)
	{
		memcpy(p, keyType, 4);
		p += 4;
	}
	else
	{
		memcpy(p, keyType, 3);
		p += 3;
	}

	/* DES key length */
	*p++ = (keyLen / 8) - 1 + '0';


	/* WK encrypted under the LMK*/
/*	memcpy(p, wkLmk, keylen);
//	p += keylen;
*/
	if (keyLen == 16) {
		*p++ = 'X';
	}
	if (keyLen == 24) {
		*p++ = 'Y';
	}

	UnpackBCD(wkLmk, p, keyLen * 2);
	p += keyLen * 2;

#if	0
	switch (pad_mode)
	{
	case 1:
	case 2:
		/* IV */
		*p++ = 'T';
		/*		memcpy(p, iv, ivLen);
		*/                UnpackBCD((unsigned char *)iv, p, ivLen * 2);
		p += ivLen * 2;
		break;
	default:
		break;
	}
#endif

	/* CV */
/*	memcpy(p, cv, 16);
*/        memset(p, '0', 16);
	p += 16;

	/* Public key index */
	if (index >= 0)
	{
		*p++ = 'T';
		sprintf((char *)p, "%02d", index);
		p += 2;
	}
	else
	{
		/* MAC */
/*		memcpy(p, mac, 4);
*/
		if (sig_alg == SIG_ALGO_RSA) {
			memset(p, 0x00, 4);
			p += 4;

			/* Public key */
			memcpy(p, public_key, len);
			p += len;

			/* Authentication data */
			if (authenDataLen > 0)
			{
				memcpy(p, authenData, authenDataLen);
				p += authenDataLen;
			}
		}
		else {
			sprintf((char *)p, "%04d", public_key_len);
			p += 4;
			memcpy(p, public_key, public_key_len);
			p += public_key_len;
		}
	}
	/* Delimeter ';' */
	*p++ = ';';

	/* Key block type */
	sprintf((char *)p, "%02d", keyBlock_Type);
	p += 2;

	if (keyBlock_Type == 2)
	{
		/* Key block template length */
		sprintf((char *)p, "%04d", keyBlockTemplateLen);
		p += 4;

		/* Key block template */
		memcpy(p, keyBlockTemplate, keyBlockTemplateLen);
		p += keyBlockTemplateLen;

		/* Delimeter ';' */
		*p++ = ';';

		/* Key offset within the key block */
		sprintf((char *)p, "%04d", keyOffset);
		p += 4;

		/* Check value length */
		*p++ = chkLen + '0';

		/* Check value offset within the key block */
		sprintf((char *)p, "%04d", chkOffset);
		p += 4;
	}

	*p = 0x00;

	cmdlen = p - cmd;

	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	free(cmd);

	if (ret < 0)
	{
		return (ret);
	}



	p = rsp;

	switch (keyBlockType)
	{
	case 1:

		/*		memcpy(iv, p, ivLen);
		*/
		PackBCD(p, iv, ivLen * 2);
		p += ivLen * 2;
		break;

	default:
		break;
	}

	if ((len = dec2int((unsigned char*)p, 4)) < 0)
	{
		return -98;
	}
	p += 4;

	memcpy(data, p, len);
	p += len;
	*data_length = len;

	return 0;
}

/* Generate Random Number - RN */
int genrandom(
	int comid,
	int msghdlen, char * msghd,
	int rndLen,
	unsigned char *rnd
)

{
	char    *cmd, *p;
	int     cmdlen, rsplen;

	char    rsp[MAX_MSGDATA + 1];

	int 	ret;


	if (rndLen <= 0)
	{
		return (-115);
	}

	if (rndLen > LEN_MAX_BLOCK)
	{
		return(-106);
	}


	cmd = (char *)malloc(
		msghdlen +		/* Message head */
		2 + 		/* Command */
		5 + 		/* Random number length */
/*		    	   rndLen +		/ * Random number */
1);

	if (cmd == NULL)	return (-1);


	p = cmd;


	/* Message header */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	// COMMAND CODE 'RN'
	*/
	*p++ = 'R';
	*p++ = 'N';

	/* Random number length in bytes */
	sprintf((char *)p, "%05d", rndLen);
	p += 5;


	*p = 0x00;

	cmdlen = p - cmd;


	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	free(cmd);

	if (ret < 0)
	{
		return (ret);
	}



	p = rsp;


	memcpy(rnd, p, rndLen);
	p += rndLen;

	return 0;
}

/* Hash the data "GM"*/
int genhash(
	int comid,
	int msghdlen, char * msghd,
	int hash_id,
	int data_len,
	UCHAR *data,
	UCHAR *hash_value
)
{
	char    *cmd, *p;
	int     cmdlen, rsplen;
	char    rsp[MAX_MSGDATA + 1];

	int     ret;

	if (data_len > LEN_MAX_BLOCK)
	{
		return(-106);
	}


	switch (hash_id)
	{
	case HASH_MD2:
	case HASH_SHA1:
	case HASH_MD5:
	case HASH_ISO10118_2:
	case HASH_NOHASH:
	case HASH_MD4:
	case HASH_SHA224:
	case HASH_SHA256:
	case HASH_SHA384:
	case HASH_SHA512:
	case HASH_RIPEMD128:
	case HASH_RIPEMD160:
	case HASH_RIPEMD256:
	case HASH_RIPEMD320:
	case HASH_SM3:
		break;
	default:
		return (-198);
	}



	cmd = (char *)malloc(
		msghdlen +		/* Message head */
		2 +             /* Command */
		2 +             /* Hash Identifier */
		5 +             /* Data length */
		data_len +             /* Data to be hashed */
		1);

	if (cmd == NULL)   return (-1);

	p = cmd;

	/* Messages head */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;


	*p++ = 'G';
	*p++ = 'M';


	/* Hash Identifier */
	sprintf((char *)p, "%02d", hash_id);
	p += 2;

	/* Length of message data to be hashed */
	sprintf((char *)p, "%05d", data_len);
	p += 5;

	/* Data to be hashed */
	memcpy(p, data, data_len);
	p += data_len;

	*p = 0x00;
	//printf("SEND: %s\n",cmd);

	cmdlen = p - cmd;
	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	free(cmd);

	if (ret < 0)
	{
		return (ret);
	}



	p = rsp;

	switch (hash_id)
	{
	case HASH_MD2:
	case HASH_MD5:
	case HASH_MD4:
	case HASH_RIPEMD128:
	case HASH_ISO10118_2:
		ret = 16;
		break;
	case HASH_RIPEMD160:
	case HASH_SHA1:
		ret = 20;
		break;
	case HASH_SHA224:
		ret = 28;
		break;
	case HASH_SHA256:
	case HASH_RIPEMD256:
	case HASH_SM3:
		ret = 32;
		break;
	case HASH_RIPEMD320:
		ret = 40;
		break;
	case HASH_SHA384:
		ret = 48;
		break;
	case HASH_SHA512:
		ret = 64;
		break;
	}
	memcpy(hash_value, p, ret);
	p += ret;

	return 0;
}

/*SJL22 command "VG"*/
int gendeskey(int comid, int msghdlen, char *msghd, int algo, int mode, char * keytype, int keylen, int inputmode, int randomgen, int maskinput, int timeout, \
	int promptlen, char * prompt, int nofcomp1, char *porekey, int nofcomp2, char *twokeys, UCHAR *outkey, char *kcv)
{
	char	*cmd, *p;
	int 	cmdlen, rsplen;
	char	rsp[MAX_MSGDATA + 1];

	int	ret;

	if (keylen > 49)
	{
		return(-106);
	}

	if (promptlen > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	cmd = (char *)malloc(msghdlen 		/* Message head */
		+ 2			/* Command */
		+ 3                      /* Pxx */
		+ 1                      /* mode */
		+ 4                      /* key type */
		+ 1                      /* keylen */
		+ 1                      /* input mode */
		+ 1                      /* random generate */
		+ 1                      /* mask input */
		+ 2                      /* timeout */
		+ 4                      /* prompt string length */
		+ promptlen              /* prompt string */
		+ 1                      /* ';' */
		+ 1                      /* n of comp 1 */
		+ keylen * 2 * nofcomp1 /* p or e key */
		+ 1                      /* n of comp 2 */
		+ keylen * 2 * 2        /* two key */
		+ 1);			/* 0x00 */

	if (cmd == NULL) return (-1);

	p = cmd;

	/* Messages head */

	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/* IC COMMAND CODE 'VG' */
	*p++ = 'V';
	*p++ = 'G';

	*p++ = 'P';
	*p++ = '0' + algo;
	*p++ = '0' + algo;


	/* mode */
	sprintf((char *)p, "%01d", mode);
	p += 1;

	/* key type * /
//        sprintf( p, "%04d", keytype);
//        p += 4;
*/
	memcpy(p, keytype, 3);
	p += 3;

	/* key len */
	sprintf((char *)p, "%01d", (keylen / 8) - 1);
	p += 1;

	if ((mode == 1) || (mode == 3)) {
		*p++ = inputmode + '0';
		if (inputmode == 1) {
			*p++ = randomgen + '0';
			*p++ = maskinput + '0';
			sprintf((char *)p, "%02d", timeout);
			p += 2;
			sprintf((char *)p, "%04d", promptlen);
			p += 4;
			memcpy(p, prompt, promptlen);
			p += promptlen;
			*p++ = ';';
		}
	}


	if ((mode == 1) || (mode == 2)) {
		/* n of comp 1 */
		sprintf((char *)p, "%01d", nofcomp1);
		p += 1;

		/* p or e key * /
//                memcpy( p, porekey, (keylen+1)*16*nofcomp1 );
//	        p += (keylen+1)*16*nofcomp1;
*/                UnpackBCD((unsigned char *)porekey, p, keylen * 2 * nofcomp1);
		p += (keylen * 2 * nofcomp1);
	}

	if (mode == 3) {
		/* n of comp 2 */
		nofcomp2 = 2;
		sprintf((char *)p, "%01d", nofcomp2);
		p += 1;

		/* p or e key * /
//                memcpy( p, twokeys, (keylen+1)*16*2 );
//	        p += (keylen+1)*16*2;
*/                UnpackBCD((unsigned char *)twokeys, p, keylen * 2 * 2);
		p += (keylen * 2 * 2);
	}

	*p = 0x00;

	cmdlen = p - cmd;

	/*        //TraceMessage("sjl22.log", cmd, cmdlen);*/

	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	/*        //TraceMessage("sjl22.log", rsp, rsplen);*/

	free(cmd);

	if (ret < 0)
	{
		return (ret);
	}

	p = rsp;

	/*        memcpy( outkey, p, (keylen+1)*16 );*/

	PackBCD(p, outkey, keylen * 2);

	//	*( outkey + keylen ) = 0x00;

	p += (keylen * 2);

	/*	memcpy( kcv, p, 8 );*/

	PackBCD(p, (unsigned char *)kcv, 8);

	//	*( kcv + 4 ) = 0x00;


	return 0;

}

/*SJL22 command "VI"*/
int derivatekey(int comid,int msghdlen,char *msghd, 
				int algo,int derivationmode,int encmode,
				char * derivedkeytype,char * derivationkeytype,
				int derivationkeylen,char * derivationkey, 
				int datalen1,char * iv1,char *derivate_data1,
				int datalen2,char * iv2,char *derivate_data2, 
				char * derivedkey,char * kcv)
{
	char	*cmd, *p;
	int 	cmdlen, rsplen;
	char	rsp[MAX_MSGDATA + 1];

	int	ret;

	if (derivationkeylen > 49)
	{
		return(-106);
	}

	if (datalen1 > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (datalen2 > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	cmd = (char *)malloc(msghdlen 		/* Message head */
		+ 2			/* Command */
		+ 3                /* Pxx */
		+ 1                      /* derivation mode */
		+ 1                      /* encryption mode */
		+ 4                      /* derived key type*/
		+ 4                      /* derivation key type */
		+ 1                      /* derivation key len */
		+ 49/* derivation key */
		+ 4                      /* derivation data len1 */
		+ 32                      /* iv1 */
		+ datalen1               /* derivation data1 */
		+ 1                      /* ; */
		+ 4                      /* derivation data len2 */
		+ 32                      /* iv2 */
		+ datalen2               /* derivation data2 */
		+ 1);			/* 0x00 */

	if (cmd == NULL) return (-1);

	p = cmd;

	/* Messages head */

	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*COMMAND CODE 'VI' */
	*p++ = 'V';
	*p++ = 'I';

	*p++ = 'P';
	*p++ = '0' + algo;
	*p++ = '0' + algo;

	/* derivation mode */
	*p++ = derivationmode + '0';

	/* encryption mode */
	*p++ = encmode + '0';


	memcpy(p, derivedkeytype, 3);
	p += 3;

	/* derivation key type */
	memcpy(p, derivationkeytype, 3);
	p += 3;


	/* derivation key len */
	sprintf((char *)p, "%01d", (derivationkeylen / 8) - 1);
	p += 1;


	/* derivation key * /
//	memcpy( p, derivationkey, (derivationkeylen+1)*16 );
//	p += (derivationkeylen+1)*16;
*/
	UnpackBCD((unsigned char *)derivationkey, p, derivationkeylen * 2);
	p += derivationkeylen * 2;

	/*        UnpackBCD(derivationkey, p, (derivationkeylen+1)*16);
	//        p += (derivationkeylen+1)*16;
	*/

	/* derivation data len1 */
	sprintf((char *)p, "%04d", datalen1);
	p += 4;

	if (datalen1 > 0) {
		/* iv1 */
		if (derivationmode != 0) {
			if (algo == ALGO_DESTDES) {
				memcpy(p, iv1, 8);
				p += 8;
			}
			else {
				memcpy(p, iv1, 16);
				p += 16;
			}
		}
		/* derivation data1 */
		memcpy(p, derivate_data1, datalen1);
		p += datalen1;

		if (datalen2 > 0) {
			*p++ = ';';

			/* derivation data len2 */
			sprintf((char *)p, "%04d", datalen2);
			p += 4;

			/* iv2 */
			if (derivationmode != 0) {
				if (algo == ALGO_DESTDES) {
					memcpy(p, iv2, 8);
					p += 8;
				}
				else {
					memcpy(p, iv2, 16);
					p += 16;
				}
			}
			/* derivation data2 */
			memcpy(p, derivate_data2, datalen2);
			p += datalen2;
		}
	}

	*p = 0x00;

	cmdlen = p - cmd;
	//        //TraceMessage("sjl22.log", cmd, cmdlen);
	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	//        //TraceMessage("sjl22.log", rsp, rsplen);
	free(cmd);

	if (ret < 0)
	{
		return (ret);
	}

	p = rsp;

	/*        
	//        PackBCD(p, derivedkey, (derivationkeylen+1)*16);
	//        *( derivedkey + (derivationkeylen+1)*8)  = 0x00;

	PackBCD(p, (unsigned char *)derivedkey, derivationkeylen * 2);
	*(derivedkey + derivationkeylen * 2) = 0x00;
	*/
	
	memcpy(derivedkey, p, derivationkeylen);
	*(derivedkey + derivationkeylen) = 0x00;
	p += derivationkeylen;
	
	/*	
	memcpy( kcv, p, 8 );
	//        PackBCD(p, kcv, 8);

	//	*( kcv + 4 ) = 0x00;
	p += derivationkeylen * 2;
	*/

	/*	
	PackBCD(p, (unsigned char *)kcv, 6);
	p += 6;
	*(kcv + 3) = 0x00;
	*/
	
	memcpy( kcv, p, 8 );
	*(kcv + 8) = 0x00;
	p += 8;

	return 0;

}

/*SJL22 command "VD"*/
int derivateEMVkey(int comid, int msghdlen, char *msghd, int algo, int mode, char * derivedkeytype, char * derivationkeytype, \
	int derivationkeylen, char * derivationkey, char * iv, char *gpkey, char *pkey, int branch, \
	int hparam, int apptranscnt, int napptranscnt, int keyscheme, int kcvtype, char * ngpkey, char *npkey, char * derivedkey, char *kcv)

{
	char	*cmd, *p;
	int 	cmdlen, rsplen;
	char	rsp[MAX_MSGDATA + 1];

	int	ret;

	if (derivationkeylen > 49)
	{
		return(-106);
	}

	cmd = (char *)malloc(msghdlen 		/* Message head */
		+ 2			/* Command */
		+ 3                /* Pxx */
		+ 1                      /* mode */
		+ 4                      /* derived key type*/
		+ 4                      /* derivation key type */
		+ 1                      /* derivation key len */
		+ 49/* derivation key */
		+ 32                      /* iv */
		+ 16               /* grand parent key */
		+ 16               /* parent key */
		+ 2                /* branch */
		+ 2                /* height parameters */
		+ 2                /* application transaction counter */
		+ 2                /* new application transaction counter */
		+ 1                /* ';' */
		+ 1                /* key scheme ZMK */
		+ 1                /* key scheme LMK */
		+ 1                /* key check value type */
		+ 1);			/* 0x00 */

	if (cmd == NULL) return (-1);

	p = cmd;

	/* Messages head */

	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*COMMAND CODE 'VD' */
	*p++ = 'V';
	*p++ = 'D';

	*p++ = 'P';
	*p++ = '0' + algo;
	*p++ = '0' + algo;

	/* derivation mode */
	*p++ = mode + '0';



	/* derived key type*/

	memcpy(p, derivedkeytype, 3);
	p += 3;

	/* derivation key type */
	memcpy(p, derivationkeytype, 3);
	p += 3;


	/* derivation key len */
	sprintf((char *)p, "%01d", (derivationkeylen / 8) - 1);
	p += 1;

	/* derivation key * /
//	memcpy( p, derivationkey, (derivationkeylen+1)*16 );
//	p += (derivationkeylen+1)*16;
*/        if (derivationkeylen == 16) {
	*p++ = 'X';
}
	if (derivationkeylen == 24) {
		*p++ = 'Y';
	}
	UnpackBCD((unsigned char *)derivationkey, p, derivationkeylen * 2);
	p += derivationkeylen * 2;



	if (mode == 0) {
		if (algo == ALGO_DESTDES) {
			memcpy(p, iv, 16);
			p += 16;
		}
		else {
			memcpy(p, iv, 32);
			p += 32;
		}
	}

	if (mode == 1) {
		if (gpkey != NULL_PTR) {
			memcpy(p, gpkey, 16);
			p += 16;
		}
		if (pkey != NULL_PTR) {
			memcpy(p, pkey, 16);
			p += 16;
		}
	}

	sprintf((char *)p, "%02d", branch);
	p += 2;

	sprintf((char *)p, "%02d", hparam);
	p += 2;


	/*        sprintf( p, "%02x", apptranscnt );*/
	memcpy(p, &apptranscnt, 2);
	p += 2;

	if (mode == 1) {
		/*                sprintf( p, "%02x", napptranscnt );*/
		memcpy(p, &napptranscnt, 2);
		p += 2;
	}



	*p = 0x00;

	cmdlen = p - cmd;

	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	free(cmd);

	if (ret < 0)
	{
		return (ret);
	}

	p = rsp;

	if (mode == 1) {

		memcpy(p, ngpkey, 16);
		p += 16;
		memcpy(p, npkey, 16);
		p += 16;
	}

	/*        memcpy(derivedkey, p, (derivationkeylen+1)*16);
	//        *( derivedkey + (derivationkeylen+1)*16)  = 0x00;
	*/
	if ((*p == 'X') || (*p == 'Y')) {
		p++;
	}

	PackBCD(p, (unsigned char *)derivedkey, derivationkeylen * 2);
	*(derivedkey + derivationkeylen * 2) = 0x00;

	p += derivationkeylen * 2;

	/*	memcpy( kcv, p, 8 );*/
	PackBCD(p, (unsigned char *)kcv, 6);
	p += 6;

	*(kcv + 3) = 0x00;

	return 0;

}

/*SJL22 command "VJ"*/
int derivateFISCPBOCkey(int comid, int msghdlen, char *msghd, int algo, int mode, char * derivedkeytype, char * derivationkeytype, \
	int derivationkeylen, char * derivationkey, char * derivationdata, char * keytype, int keylen, char * key, \
	char * derivedkey, char * kcv)

{
	char	*cmd, *p;
	int 	cmdlen, rsplen;
	char	rsp[MAX_MSGDATA + 1];

	int	ret;

	if (keylen > 49)
	{
		return(-106);
	}

	if (derivationkeylen > 49) {
		return(-106);
	}

	cmd = (char *)malloc(msghdlen 		/* Message head */
		+ 2			/* Command */
		+ 3                      /* Pxx */
		+ 1                      /* mode */
		+ 4                      /* derived key type*/
		+ 4                      /* derivation key type */
		+ 1                      /* derivation key len */
		+ 49/* derivation key */
		+ 8                      /* derivation data */
		+ 4               /* key type */
		+ 1                      /* key len */
		+ 49/* key */
		+ 1);			/* 0x00 */

	if (cmd == NULL) return (-1);

	p = cmd;

	/* Messages head */

	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*COMMAND CODE 'VJ' */
	*p++ = 'V';
	*p++ = 'J';

	*p++ = 'P';
	*p++ = '0' + algo;
	*p++ = '0' + algo;

	/* derivation mode */
	*p++ = mode + '0';



	/* derived key type*/

	memcpy(p, derivedkeytype, 3);
	p += 3;

	/* derivation key type */
	memcpy(p, derivationkeytype, 3);
	p += 3;


	/* derivation key len */
	sprintf((char *)p, "%01d", (derivationkeylen / 8) - 1);
	p += 1;

	/* derivation key * /
//	memcpy( p, derivationkey, (derivationkeylen+1)*16 );
//	p += (derivationkeylen+1)*16;
*/
	UnpackBCD((unsigned char *)derivationkey, p, derivationkeylen * 2);
	p += derivationkeylen * 2;



	if (mode != 4) {
		if (algo == ALGO_DESTDES) {
			memcpy(p, derivationdata, 8);
			p += 8;
		}
		else {
			memcpy(p, derivationdata, 16);
			p += 16;
		}
	}
	else {
		memcpy(p, keytype, 3);
		p += 3;


		/* derivation key len */
		sprintf((char *)p, "%01d", (keylen / 8) - 1);
		p += 1;

		UnpackBCD((unsigned char *)key, p, keylen * 2);
		p += keylen * 2;
	}



	*p = 0x00;

	cmdlen = p - cmd;

	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	free(cmd);

	if (ret < 0)
	{
		return (ret);
	}

	p = rsp;


	/*        memcpy(derivedkey, p, (derivationkeylen+1)*16);
	//        *( derivedkey + (derivationkeylen+1)*16)  = 0x00;
	*/
	if ((*p == 'X') || (*p == 'Y')) {
		p++;
	}

	PackBCD(p, (unsigned char *)derivedkey, derivationkeylen * 2);
	*(derivedkey + derivationkeylen * 2) = 0x00;

	p += derivationkeylen * 2;

	/*	memcpy( kcv, p, 8 );*/
	PackBCD(p, (unsigned char *)kcv, 8);
	p += 8;

	*(kcv + 4) = 0x00;

	return 0;

}

/*SJL22 command "T0"*/
int gepin(int comid, int msghdlen, char *msghd, int algo, int mode, int encmode, int cpinlen, char * cpin, int pinfmt, int pinpadmode, \
	char * pinkeytype, int pinkeylen, char * pinkey, char * iv, char * pan, int *epinlen, char * epin)

{
	char	*cmd, *p;
	int 	cmdlen, rsplen;
	char	rsp[MAX_MSGDATA + 1];

	int	ret;


	if (cpinlen > MAX_PIN_SIZE)
	{
		return(-106);
	}

	if (pinkeylen > 49)
	{
		return(-106);
	}

	cmd = (char *)malloc(msghdlen 		/* Message head */
		+ 2			/* Command */
		+ 1                      /* mode */
		+ 3
		+ 1                      /* encrypt mode */
		+ 2                      /* pin length */
		+ cpinlen                /* pin */
		+ 2                      /* pin format */
		+ 1                      /* pin pad mode */
		+ 4                      /* pin key type*/
		+ 1                      /* pin key len */
		+ 49/* pin key */
		+ 8                      /* iv */
		+ 12               /* account number */
		+ 1);			/* 0x00 */

	if (cmd == NULL) return (-1);

	p = cmd;

	/* Messages head */

	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*COMMAND CODE 'T0' */
	*p++ = 'T';
	*p++ = '0';

	*p++ = 'P';
	*p++ = '0' + algo;
	*p++ = '0' + algo;

	/* mode */
	*p++ = mode + '0';

	*p++ = encmode + '0';

	sprintf((char *)p, "%02d", cpinlen);
	p += 2;



	/* pin*/

	if (mode == 1) {
		memcpy(p, cpin, cpinlen);
		p += cpinlen;
	}


	sprintf((char *)p, "%02d", pinfmt);
	p += 2;

	*p++ = pinpadmode + '0';

	/* pin key type */
	memcpy(p, pinkeytype, 3);
	p += 3;

	*p++ = (pinkeylen / 8) - 1 + '0';

	UnpackBCD((unsigned char *)pinkey, p, pinkeylen * 2);
	p += pinkeylen * 2;


	if ((encmode == 1) || (encmode == 2)) {
		if (algo == ALGO_DESTDES) {
			memcpy(p, iv, 8);
			p += 8;
		}
		else {
			memcpy(p, iv, 16);
			p += 16;
		}
	}

	if ((pinfmt == 1) || (pinfmt == 35) || (pinfmt == 47)) {
		memcpy(p, pan, 12);
		p += 12;
	}





	*p = 0x00;

	cmdlen = p - cmd;

	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	free(cmd);

	if (ret < 0)
	{
		return (ret);
	}

	p = rsp;


	if ((*epinlen = dec2int((unsigned char*)p, 4)) < 0)
	{
		return -198;
	}
	p += 4;

	memcpy(epin, p, *epinlen);
	p += *epinlen;



	return 0;

}

/*SJL22 command "VU"*/
int desencrypt(int comid, int msghdlen, char *msghd, int algo, int encmode, char * keytype, int keylen, char *key, char * iv, \
	int indatalen, char *indata, int * outdatalen, char *outdata)
{
	char	*cmd, *p;
	int 	cmdlen, rsplen;
	char	rsp[MAX_MSGDATA + 1];

	int	ret;


	if (keylen > 49)
	{
		return(-106);
	}

	if (indatalen > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	cmd = (char *)malloc(msghdlen +	/* Message head */
		2 + 		/* Command */
		3 +             /* Pxx */
		1 +             /* enc mode */
		4 +             /* key type */
		1 +             /* key len */
		keylen * 2 +             /* key */
		32 +             /* IV */
		4 +             /* data len */
		indatalen +             /* data */
		1);		/* 0x00 */

	if (cmd == NULL)	return (-1);

	p = cmd;

	/* Messages head */

	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	// COMMAND CODE 'VU'
	*/
	*p++ = 'V';
	*p++ = 'U';

	*p++ = 'P';
	*p++ = '0' + algo;
	*p++ = '0' + algo;

	/* enc mode */
	*p++ = encmode + '0';

	/* key type * /
//        sprintf((char *)p,"%04d",keytype);
//	p += 4;
*/
	memcpy(p, keytype, 3);

	p += 3;

	/* key len */
	sprintf((char *)p, "%01d", (keylen / 8) - 1);
	p += 1;

	/* key * /
//        memcpy(p,key, (keylen+1)*16);
//	p += (keylen+1)*16;
*/
	UnpackBCD((unsigned char *)key, p, keylen * 2);
	p += keylen * 2;

	/* IV */
	if ((encmode != 0)) {

		if (algo == ALGO_DESTDES) {
			memcpy(p, iv, 8);

			p += 8;
		}
		else {
			memcpy(p, iv, 16);

			p += 16;
		}
	}


	/* data len */
	sprintf((char *)p, "%04d", indatalen);
	p += 4;



	/* indata */
	memcpy(p, indata, indatalen);
	p += indatalen;

	*p = 0x00;


	cmdlen = p - cmd;


	/*        //TraceMessage("sjl22.log", cmd, cmdlen);*/

	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	/*        //TraceMessage("sjl22.log", rsp, rsplen);*/

	free(cmd);

	if (ret < 0) {

		return (ret);
	}

	p = rsp;


	/* get outdatalen */
	*outdatalen = dec2int((unsigned char*)p, 4);
	p += 4;



	/* Get outdata */
	memcpy(outdata, p, *outdatalen);
	*(outdata + (*outdatalen)) = 0x00;

	return 0;

}

/*SJL22 command "VW"*/
int desdecrypt(int comid, int msghdlen, char *msghd, int algo, int encmode, char * keytype, int keylen, char *key, char * iv, \
	int indatalen, char *indata, int * outdatalen, char *outdata)
{
	char	*cmd, *p;
	int 	cmdlen, rsplen;
	char	rsp[MAX_MSGDATA + 1];

	int	ret;

	if (keylen > 49)
	{
		return(-106);
	}

	if (indatalen > LEN_MAX_BLOCK)
	{
		return(-106);
	}


	cmd = (char *)malloc(msghdlen +	/* Message head */
		2 + 		/* Command */
		3 +             /* algo */
		1 +             /* enc mode */
		4 +             /* key type */
		1 +             /* key len */
		keylen * 2 +             /* key */
		32 +             /* IV */
		4 +             /* data len */
		indatalen +             /* data */
		1);		/* 0x00 */

	if (cmd == NULL)	return (-1);

	p = cmd;

	/* Messages head */

	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	//COMMAND CODE 'VW'
	*/
	*p++ = 'V';
	*p++ = 'W';

	*p++ = 'P';
	*p++ = '0' + algo;
	*p++ = '0' + algo;

	/* enc mode */
	*p++ = encmode + '0';

	/* key type * /
//        sprintf((char *)p,"%04d",keytype);
//	p += 4;
*/        memcpy(p, keytype, 3);
	p += 3;

	/* key len */
	sprintf((char *)p, "%01d", (keylen / 8) - 1);
	p += 1;

	/* key * /
//        memcpy(p,key, (keylen+1)*16);
//	p += (keylen+1)*16;
*/
	UnpackBCD((unsigned char *)key, p, keylen * 2);
	p += keylen * 2;

	/* IV */
	if ((encmode != 0)) {

		if (algo == ALGO_DESTDES) {
			memcpy(p, iv, 8);

			p += 8;
		}
		else {
			memcpy(p, iv, 16);

			p += 16;
		}
	}


	/* data len */
	sprintf((char *)p, "%04d", indatalen);
	p += 4;



	/* indata */
	memcpy(p, indata, indatalen);
	p += indatalen;

	*p = 0x00;


	cmdlen = p - cmd;



	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	free(cmd);

	if (ret < 0) {

		return (ret);
	}

	p = rsp;


	/* get outdatalen */
	*outdatalen = dec2int((unsigned char*)p, 4);
	p += 4;



	/* Get outdata */
	memcpy(outdata, p, *outdatalen);
	*(outdata + (*outdatalen)) = 0x00;

	return 0;

}

/* import des key "VQ"*/
int importdeskey(
	int comid,
	int msghdlen, char * msghd, int algo, int dalgo,
	int mode,
	int importmode,
	char * kektype,
	int keklen,
	unsigned char * kek,
	char * usrkeytype,
	int usrkeylen,
	int usrkeydatalen,
	unsigned char * usrkeydata,
	unsigned char * iv,
	int prefixlen,
	int postfixlen,
	unsigned char * outkey,
	unsigned char * kcv
)
{
	char    *cmd, *p;
	int     cmdlen, rsplen;
	char    rsp[MAX_MSGDATA + 1];

	int     ret;


	if (keklen > 49)
	{
		return(-106);
	}

	if (usrkeylen > 49)
	{
		return(-106);
	}

	if (usrkeydatalen > LEN_MAX_BLOCK)
	{
		return(-106);
	}


	cmd = (char *)malloc(
		msghdlen +		/* Message head */
		2 +             /* Command */
		3 +
		1 +             /* mode */
		1 +             /* import mode */
		4 +             /* kek type */
		1 +             /* kek len */
		(keklen + 1) * 16 +             /* kek */
		4 +             /* usr key type */
		1 +             /* usr key len */
		4 +             /* usr key data len */
		usrkeydatalen +             /* usr key data */
		16 +             /* iv */
		4 +             /* prefix len */
		4 +             /* postfix len */
		1);

	if (cmd == NULL)   return (-1);

	p = cmd;

	/* Messages head */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;


	*p++ = 'V';
	*p++ = 'Q';

	*p++ = 'P';
	*p++ = '0' + algo;
	*p++ = '0' + dalgo;

	/* mode */
	*p++ = mode + '0';

	/* import mode */
	*p++ = importmode + '0';

	/* kek type */
/*        sprintf((char *)p, "%04d", 400);*/
	memcpy(p, kektype, 3);
	p += 3;

	/* kek len */
	*p++ = (keklen / 8) - 1 + '0';

	/* kek */
/*        memcpy(p, kek, (keklen+1)*16);*/
	UnpackBCD(kek, p, keklen * 2);
	p += keklen * 2;

	/* usr key type */
/*        sprintf((char *)p, "%04d", usrkeytype);*/
	memcpy(p, usrkeytype, 3);
	p += 3;

	/* usr key len */
	*p++ = (usrkeylen / 8) - 1 + '0';

	/* usr key data len */
	sprintf((char *)p, "%04d", usrkeydatalen);
	p += 4;

	/* usr key data */
	memcpy(p, usrkeydata, usrkeydatalen);
	p += usrkeydatalen;

	if ((mode == 1) || (mode == 2)) {
		/* iv */
		if (algo == ALGO_DESTDES) {
			memcpy(p, iv, 8);
			p += 8;
		}
		else {
			memcpy(p, iv, 16);
			p += 16;
		}
	}

	/* prefix len */
	sprintf((char *)p, "%04d", prefixlen);
	p += 4;

	/* postfix len */
	sprintf((char *)p, "%04d", postfixlen);
	p += 4;


	*p = 0x00;

	cmdlen = p - cmd;

	/*        //TraceMessage("sjl22.log", cmd, cmdlen);*/

	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	/*        //TraceMessage("sjl22.log", rsp, rsplen);*/

	free(cmd);

	if (ret < 0)
	{
		return (ret);
	}



	p = rsp;


	/*	memcpy(outkey, p, (usrkeylen+1)*16);*/
	PackBCD(p, outkey, usrkeylen * 2);
	p += usrkeylen * 2;
	PackBCD(p, kcv, 6);
	p += 6;

	return 0;
}

/* export des key "VS"*/
int exportdeskey(
	int comid,
	int msghdlen, char * msghd, int algo, int dalgo,
	int mode,
	int exportmode,
	char * kektype,
	int keklen,
	unsigned char * kek,
	char * usrkeytype,
	int usrkeylen,
	unsigned char * usrkey,
	unsigned char * iv,
	int prefixlen,
	unsigned char * prefixdata,
	int postfixlen,
	unsigned char * postfixdata,
	int * outkeylen,
	unsigned char * outkey
)
{
	char    *cmd, *p;
	int     cmdlen, rsplen;
	char    rsp[MAX_MSGDATA + 1];

	int     ret;



	if (keklen > 49)
	{
		return(-106);
	}

	if (usrkeylen > 49)
	{
		return(-106);
	}

	if (prefixlen > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (postfixlen > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	cmd = (char *)malloc(
		msghdlen +		/* Message head */
		2 +             /* Command */
		3 +
		1 +             /* mode */
		1 +             /* export mode */
		4 +             /* kek type */
		1 +             /* kek len */
		(keklen + 1) * 16 +             /* kek */
		4 +             /* usr key type */
		1 +             /* usr key len */
		(usrkeylen + 1) * 16 +             /* usr key */
		48 +             /* iv */
		4 +             /* prefix len */
		prefixlen +             /* prefix data */
		4 +             /* postfix len */
		postfixlen +             /* postfix data */
		1);

	if (cmd == NULL)   return (-1);

	p = cmd;

	/* Messages head */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;


	*p++ = 'V';
	*p++ = 'S';
	*p++ = 'P';
	*p++ = '0' + algo;
	*p++ = '0' + dalgo;

	/* mode */
	*p++ = mode + '0';

	/* export mode */
	*p++ = exportmode + '0';

	/* kek type */
/*        sprintf((char *)p, "%04d", 400);*/
	memcpy(p, kektype, 3);
	p += 3;

	/* kek len */
	*p++ = (keklen / 8) - 1 + '0';

	/* kek * /
//        memcpy(p, kek, (keklen+1)*16);
//        p += (keklen+1)*16;
*/
	UnpackBCD(kek, p, keklen * 2);
	p += keklen * 2;

	/* usr key type */
/*        sprintf((char *)p, "%04d", usrkeytype);*/
	memcpy(p, usrkeytype, 3);
	p += 3;

	/* usr key len */
	*p++ = (usrkeylen / 8) - 1 + '0';

	/* usr key data * /
//        memcpy(p, usrkey, (usrkeylen+1)*16);
//        p += (usrkeylen+1)*16;
*/
	UnpackBCD(usrkey, p, usrkeylen * 2);
	p += usrkeylen * 2;

	if ((mode == 1) || (mode == 2)) {
		/* iv */
		if (algo == ALGO_DESTDES) {
			memcpy(p, iv, 8);
			p += 8;
		}
		else {
			memcpy(p, iv, 16);
			p += 16;
		}
	}

	/* prefix len */
	sprintf((char *)p, "%04d", prefixlen);
	p += 4;

	/* prefix data */
	memcpy(p, prefixdata, prefixlen);
	p += prefixlen;

	/* postfix len */
	sprintf((char *)p, "%04d", postfixlen);
	p += 4;

	/* postfix data */
	memcpy(p, postfixdata, postfixlen);
	p += postfixlen;


	*p = 0x00;

	cmdlen = p - cmd;

	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	free(cmd);

	if (ret < 0)
	{
		return (ret);
	}



	p = rsp;

	if ((*outkeylen = dec2int((unsigned char*)p, 4)) < 0)
	{
		return -98;
	}
	p += 4;

	/* out key */
	memcpy(outkey, p, *outkeylen);
	p += *outkeylen;

	return 0;
}

/* Generate MAC on large data using ZAK or TAK "M6"*/
int genmac(
	int comid,
	int msghdlen, char *msghd,
	int algo,
	int mode_flag,
	int MACalgo,
	int pad_method,
	char *key_type,
	int key_len,
	char *wk_lmk,
	int input_format,
	int data_len,
	char *data,
	int * ivLen,
	char *mab
)
{

	char	*cmd, *p;
	int	cmdlen, rsplen;
	char	rsp[MAX_MSGDATA + 1];
	int     ret;

	int     dataLen = data_len;


	*ivLen = 8;

	switch (mode_flag)
	{
	case 0:
	case 1:
	case 2:
	case 3:
		break;
	default:
		return (-102);
	}




	if (input_format != 0 && input_format != 1 && input_format != 2)
	{
		return -103;
	}

	if (input_format == 1)
	{
		dataLen *= 2;
	}
	if (dataLen > LEN_MAX_BLOCK)
	{
		return(-106);
	}




	cmd = (char *)malloc(sizeof(char)*(
		msghdlen +		/* Message header */
		2 +		/* Command Code */
		3 + 		/* Algorithm: Pxx */
		1 +		/* Mode flag */
		1 +		/* Input format flag */
		2 +		/* MAC algorithm */
		1 +		/* Padding method */
		4 +		/* Key type */
		49 +		/* ZAK/TAK under LMK */
		*ivLen * 4 +		/* IV length */
		4 +		/* data length */
		dataLen +		/* data */
		1));

	if (cmd == NULL)	return (-1);

	p = cmd;


	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	// COMMAND CODE 'M6'
	*/
	*p++ = 'M';
	*p++ = '6';

	/* Algo:P00 P11 P22 */
	*p++ = 'P';
	//	sprintf((char *)p, "%02d", algo);
	//	p += 2;
	*p++ = '0' + algo;
	*p++ = '0' + algo;

	/*
	// Message block number
	// 0 : The only block
	// 1 : The first block
	// 2 : A middle block
	// 3 : The last block
	*/
	*p++ = '0' + mode_flag;

	/* Input data format */
	*p++ = '0' + input_format;

	/* MAC algorithm */
	sprintf((char *)p, "%02d", MACalgo);
	p += 2;

	/* Padding method */
	*p++ = '0' + pad_method;

	/* Key type */
	*p++ = 'T';
	memcpy(p, key_type, 3);
	p += 3;


	/*
	// TAK/ZAK encrypted under LMK pair 26 - 27
	*/
	if (key_len * 2 == 32) {
		*p++ = 'X';
	}
	/*	memcpy(p, wk_lmk, keylen);*/
	UnpackBCD((unsigned char *)wk_lmk, p, key_len * 2);

	p += key_len * 2;

	/*
	// ICV
	*/
	switch (mode_flag)
	{
	case 0:
	case 1:
	default:
	{
	} break;
	case 2:
	case 3:
	{
		/*			memcpy(p, mab, ivLen);*/
		if (algo == ALGO_DESTDES) {
			UnpackBCD((unsigned char *)mab, p, *ivLen * 2);
			p += *ivLen * 2;
		}
		else {
			UnpackBCD((unsigned char *)mab, p, IV_LEN * 4);
			p += IV_LEN * 4;
		}
	} break;
	}

	/*
	// Message length
	*/
	sprintf((char *)p, "%04X", dataLen);

	p += 4;

	/*
	// Data to be MACed: Max. length 7680 or larger
	*/
	memcpy(p, data, dataLen);
	/*
			switch(input_format)
			{
			case 1:		// Hex-Encoded Binary
			case 2:		// Text
				if(isHsmConfigedCharSetEBCDIC())
					AsciiToEbcdic(p, p, dataLen);
				break;
			}*/

	p += dataLen;


	*p = 0x00;

	cmdlen = p - cmd;

	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	free(cmd);

	if (ret < 0)
	{
		return (ret);
	}



	p = rsp;
	/*
	// MAC: The calculated MAB/MAC.
	*/
	switch (mode_flag)
	{
	case 0:
	case 3:
	default:
	{
		/*			memcpy(mab, p, 8);*/
		PackBCD(p, (unsigned char *)mab, 8);
		*ivLen = 4;
		p += 8;
	} break;
	case 1:
	case 2:
	{
		/*			memcpy(mab, p, ivLen);*/
		PackBCD(p, (unsigned char *)mab, *ivLen * 2);
		p += *ivLen * 2;
	} break;
	}

	return 0;
}

/* Import RSA key pair using PKCS#8 structure - EB */
int import_rsa_key_P8(
	int comid,
	int msghdlen, char * msghd,
	int algo,
	int key_usage,
	int import_mode,
	int import_fmt,
	int outputFlag,
	int  passwdLen,
	char *passwd,
	int dec_mode,
	int pad_mode,
	char *GVIindex,
	int dec_kindex,
	int keyTypeMode,
	char *keyType,
	int keyLen,
	char *keyLmk,
	int ivLen,
	char *iv,
	int data_len,
	char *data,
	int public_key_encoding,
	int index,
	int authenDataLen,
	char *authenData,
	char *public_key,
	int *public_key_len,
	char *mac,
	char *private_key,
	int *private_key_len,
	char * n, int * nlen,
	char * e, int * elen,
	char * d, int * dlen,
	char * prime1, int * prime1len,
	char * prime2, int * prime2len,
	char * dp, int * dplen,
	char * dq, int * dqlen,
	char * qinv, int * qinvlen
)

{
	char    *cmd, *p;
	int     cmdlen, rsplen;
	char    rsp[MAX_MSGDATA + 1];

	int 	ret;



	if (keyLen > 49)
	{
		return(-106);
	}

	if (data_len > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (authenDataLen < 0)
	{
		authenDataLen = 0;
	}

	if (authenDataLen > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (key_usage != 0 && key_usage != 1 && key_usage != 2 && key_usage != 3)
	{
		return (-196);
	}

	if (outputFlag != 0 && outputFlag != 1)
	{
		return (-199);
	}

	switch (import_mode)
	{
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
	case 8:
		break;
	default:
		return (-115);
	}

	if (import_mode == 2 || import_mode == 3 || import_mode == 4 || import_mode == 8)
	{

		if (import_mode == 3 || import_mode == 8)
		{

			if (keyTypeMode != 0 && keyTypeMode != 1)
			{
				return (-115);
			}

		}


		if (dec_mode != 0 && dec_mode != 1)
		{
			return (-115);
		}

		if (dec_mode == 1)
		{

			if (ivLen < 0)
			{
				return (ivLen);
			}
		}
	}

	if (import_fmt != 0 && import_fmt != 1)
	{
		return (-197);
	}


	cmd = (char *)malloc(
		msghdlen +		/* Message head */
		2 + 		/* Command */
		3 +
		3 +		/* Algorithm identification block */
		1 + 		/* Key usage */
		1 +		/* Import mode */
		1 + 		/* Import format */
		1 +		/* Output flag */
		(import_mode == 1 ? 4 : 0) +		/* OpenSSL password length */
		(import_mode == 1 ? passwdLen : 0) +		/* OpenSSL password mode */
		(import_mode == 2 ? 1 : 0) +		/* GVI decryption mode */
		(import_mode == 3 ? 1 : 0) +		/* THALES decryption mode */
		(import_mode == 4 ? 1 : 0) +		/* JK decryption mode */
		(import_mode == 2 ? 6 : 0) +		/* GVI mode */
		(import_mode == 3 ? 1 : 0) +		/* Key type mode */
		(import_mode == 3 ? 1 : 0) +		/* Key length */
		(import_mode == 3 ? 4 : 0) +		/* Key type */
		(import_mode ? 1 : 0) +		/* pad mode */
		keyLen * 2 + 1 +		/* THALES decryption mode: Key under LMK */
		(import_mode == 4 ? 4 : 0) +		/* JK index mode */
		ivLen * 4 +		/* Key initial vector */
		4 +		/* PKCS#8 data length */
		data_len +		/* PKCS#8 data */
		2 + 		/* Public key encoding */
		authenDataLen +		/* Authentication data */
		1 +		/* Terminator,value";" */
		2 +		/* Private Key Location */
		1);

	if (cmd == NULL)	return (-1);


	p = cmd;


	/* Messages head */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	// COMMAND CODE 'EB'
	*/
	*p++ = 'E';
	*p++ = 'B';

	/* Algorithm identification block */
	*p++ = 'P';
	//	sprintf((char *)p, "%02d", algo);
	//	p += 2;
	*p++ = '0' + algo;
	*p++ = '0' + algo;


	/* Key usage */
	*p++ = key_usage + '0';

	/* Import Mode:
	// 0 - clear components (HSM must be authorized)
	// 1 - OpenSSL compatiable password
	// 2 - Encrypted key using GVI index mode
	// 3 - Encrypted key using THALES key type
	// 4 - Encrypted key using JK index */
	*p++ = import_mode + '0';


	*p++ = import_fmt + '0';

	/* Output flag:
	// 0 - Do not output public & private key
	// 1 - Output public & private key */
	/* Output flag */
	*p++ = outputFlag + '0';


	if (import_mode == 1)
	{

		sprintf((char *)p, "%04d", passwdLen);
		p += 4;


		memcpy(p, passwd, passwdLen);
		p += passwdLen;
	}


	if (import_mode == 2 || import_mode == 3 || import_mode == 4 || import_mode == 8)
	{

		*p++ = dec_mode + '0';


		/* Import Pad format mode */
		*p++ = pad_mode + '0';
		/*		*p++ = 1 + '0'; */

	}
	/* GVI mode */
	if (import_mode == 2)
	{
		memcpy(p, GVIindex, 6);
		p += 6;
	}
	/* THALES ZMK mode */
	else if (import_mode == 3 || import_mode == 8)
	{
		/* Decryption key type */
		if (keyTypeMode)
		{
			memcpy(p, keyType, 4);
			p += 4;
		}
		else
		{
			memcpy(p, keyType, 3);
			p += 3;
		}

		/* Decryption key length */
		*p++ = (keyLen / 8) - 1 + '0';


		if (keyLen == 16) {
			*p++ = 'X';
		}
		if (keyLen == 24) {
			*p++ = 'Y';
		}
		/* Decryption key under LMK */
/*		memcpy(p, keyLmk, keylen); */
		UnpackBCD((unsigned char *)keyLmk, p, keyLen * 2);
		p += keyLen * 2;

	}

	else if (import_mode == 4)
	{
		sprintf((char *)p, "%04d", dec_kindex);
		p += 4;
	}


	if (import_mode == 2 || import_mode == 3 || import_mode == 4 || import_mode == 8)
	{

		if (dec_mode)
		{
			/* Initial vector
//			memcpy(p, iv, ivLen); */
			if (algo == ALGO_DESTDES) {
				UnpackBCD((unsigned char *)iv, p, ivLen * 2);
				p += ivLen * 2;
			}
			else {
				UnpackBCD((unsigned char *)iv, p, IV_LEN * 4);
				p += IV_LEN * 4;
			}
		}
	}

	/* PKCS#8 data length */
	sprintf((char *)p, "%04d", data_len);
	p += 4;

	/* PKCS#8 data */
	memcpy(p, data, data_len);
	p += data_len;

	/* Delimeter */
	*p++ = ';';

	/* Public key encoding */
	sprintf((char *)p, "%02d", public_key_encoding);
	p += 2;

	/* Authentication data option */
	if (authenDataLen > 0)
	{
		memcpy(p, authenData, authenDataLen);
		p += authenDataLen;
	}

	/* Key index option */
	if (index >= 0 && index != 99)
	{
		/* Terminator */
		*p++ = ';';

		/* Private key Location */
		sprintf((char *)p, "%02d", index);
		p += 2;
	}


	*p = 0x00;

	cmdlen = p - cmd;

	//        //TraceMessage("sjl22.log", cmd, cmdlen); 

	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	//        //TraceMessage("sjl22.log", rsp, rsplen); 
	free(cmd);

	if (ret < 0)
	{


		return (ret);
	}



	p = rsp;

	/* Get the MAC of the Public key */
	memcpy(mac, p, 4);
	p += 4;


	if (import_mode != 8) {

		/* Get Public key length */
		if (GetDerByteNum((unsigned char*)p, (long*)public_key_len) < 0)
		{
			return (-197);
		}
		if (*public_key_len <= 0)
		{
			return (-197);
		}


		/* Get the Public key acording to the Public key length */
		memcpy(public_key, p, *public_key_len);
		p += *public_key_len;
	}
	else {
		if ((*public_key_len = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;
		memcpy(public_key, p, *public_key_len);
		p += *public_key_len;
	}
	/* The output Private Key with the format "04" and "05" */
	if ((*private_key_len = dec2int((unsigned char*)p, 4)) < 0)
	{
		return -198;
	}
	p += 4;

	memcpy(private_key, p, *private_key_len);
	p += *private_key_len;


	if (3 == key_usage && import_mode != 8) {
		/* n */
		if ((*nlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(n, p, *nlen);
		p += *nlen;


		/* e */
		if ((*elen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(e, p, *elen);
		p += *elen;

		/* d */
		if ((*dlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(d, p, *dlen);
		p += *dlen;


		/* p */
		if ((*prime1len = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(prime1, p, *prime1len);
		p += *prime1len;


		/* q */
		if ((*prime2len = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(prime2, p, *prime2len);
		p += *prime2len;


		/* dp */
		if ((*dplen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(dp, p, *dplen);
		p += *dplen;


		/* dq */
		if ((*dqlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(dq, p, *dqlen);
		p += *dqlen;



		/* qinv */
		if ((*qinvlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(qinv, p, *qinvlen);
		p += *qinvlen;


	}

	return 0;
}

/* Export RSA key pair using PKCS#8 structure - ED */
int Export_rsa_key_P8(
	int comid,
	int msghdlen, char * msghd,
	int algo,
	int export_mode,
	int export_fmt,
	int enc_mode1,
	int  passwdLen,
	char *passwd,
	int enc_mode,
	int pad_mode,
	char *GVIindex,
	int enc_kindex,
	int keyTypeMode,
	char *keyType,
	int keyLen,
	char *keyLmk,
	int ivLen,
	char *iv,
	int index,
	int private_key_len,
	char *private_key,
	char *data,
	int *data_len
)

{
	char    *cmd, *p;
	int     cmdlen, rsplen;
	char    rsp[MAX_MSGDATA + 1];

	int 	ret;


	int     i_index;


	if (keyLen > 49)
	{
		return(-106);
	}

	if (private_key_len > LEN_MAX_BLOCK)
	{
		return(-106);
	}


	if (index < 0 || index == 99)
	{
		i_index = 99;
	}
	else
	{
		i_index = index;
		private_key_len = 0;
	}


	switch (export_mode)
	{
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
	case 8:
		break;
	default:
		return (-115);
	}

	if (export_mode == 2 || export_mode == 3 || export_mode == 4 || export_mode == 8)
	{

		if (export_mode == 3 || export_mode == 8)
		{

			if (keyTypeMode != 0 && keyTypeMode != 1)
			{
				return (-115);
			}
			/* WK encrypted under the LMK*/
		}


		if (enc_mode != 0 && enc_mode != 1)
		{
			return (-115);
		}

		if (enc_mode == 1)
		{

			if (ivLen < 0)
			{
				return (ivLen);
			}
		}
	}

	if (export_fmt != 0 && export_fmt != 1)
	{
		return (-197);
	}



	cmd = (char *)malloc(
		msghdlen +		/* Message head */
		2 + 		/* Command */
		3 +
		3 +		/* Algorithm identification block */
		1 +		/* Export mode */
		1 + 		/* Export format */
		(export_mode == 1 ? 2 : 0) +		/* OpenSSL encryption mode */
		(export_mode == 1 ? 4 : 0) +		/* OpenSSL password length */
		(export_mode == 1 ? passwdLen : 0) +		/* OpenSSL password mode */
		(export_mode == 2 ? 1 : 0) +		/* GVI Encryption mode */
		(export_mode == 3 ? 1 : 0) +		/* THALES Encryption mode */
		(export_mode == 4 ? 1 : 0) +		/* JK Encryption mode */
		(export_mode == 2 ? 6 : 0) +		/* GVI mode */
		(export_mode == 3 ? 1 : 0) +		/* Key type mode */
		(export_mode == 3 ? 1 : 0) +		/* Key length */
		(export_mode == 3 ? 4 : 0) +		/* Key type */
		(export_mode ? 1 : 0) +		/* Pad mode */
		keyLen * 2 + 1 +		/* THALES Encryption mode: Key under LMK */
		(export_mode == 4 ? 4 : 0) +		/* JK index mode */
		ivLen * 4 +		/* Key initial vector */
		4 +		/* Private key length */
		private_key_len +		/* Private key */
		2 +		/* Private Key Location */
		1);

	if (cmd == NULL)	return (-1);


	p = cmd;


	/* Messages head */
	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	// COMMAND CODE 'ED'
	*/
	*p++ = 'E';
	*p++ = 'D';

	/* Algorithm identification block */
	*p++ = 'P';
	*p++ = '0' + algo;
	*p++ = '0' + algo;


	/* Export Mode:
	// 0 - clear components (HSM must be authorized)
	// 1 - OpenSSL compatiable password
	// 2 - Encrypted key using GVI index mode
	// 3 - Encrypted key using THALES key type
	// 4 - Encrypted key using JK index */
	*p++ = export_mode + '0';


	*p++ = export_fmt + '0';



	if (export_mode == 1)
	{

		sprintf((char *)p, "%02d", enc_mode1);
		p += 2;


		sprintf((char *)p, "%04d", passwdLen);
		p += 4;


		memcpy(p, passwd, passwdLen);
		p += passwdLen;
	}


	if (export_mode == 2 || export_mode == 3 || export_mode == 4 || export_mode == 8)
	{

		*p++ = enc_mode + '0';

		/* Export Pad format mode */
		*p++ = pad_mode + '0';
		/*		*p++ = 1 + '0'; */

	}
	/* GVI mode */
	if (export_mode == 2)
	{
		memcpy(p, GVIindex, 6);
		p += 6;
	}
	/* THALES ZMK mode */
	else if (export_mode == 3 || export_mode == 8)
	{
		/* Encryption key type */
		if (keyTypeMode)
		{
			memcpy(p, keyType, 4);
			p += 4;
		}
		else
		{
			memcpy(p, keyType, 3);
			p += 3;
		}

		/* Encryption key length */
		*p++ = (keyLen / 8) - 1 + '0';

		if (keyLen == 16) {
			*p++ = 'X';
		}
		if (keyLen == 24) {
			*p++ = 'Y';
		}
		/* Encryption key under LMK */
/*		memcpy(p, keyLmk, keylen); */
		UnpackBCD((unsigned char *)keyLmk, p, keyLen * 2);
		p += keyLen * 2;

	}
	else if (export_mode == 4)
	{
		sprintf((char *)p, "%04d", enc_kindex);
		p += 4;
	}


	if (export_mode == 2 || export_mode == 3 || export_mode == 4 || export_mode == 8)
	{

		if (enc_mode)
		{
			/* Initial vector
//			memcpy(p, iv, ivLen); */
			if (algo == ALGO_DESTDES) {
				UnpackBCD((unsigned char *)iv, p, ivLen * 2);
				p += ivLen * 2;
			}
			else {
				UnpackBCD((unsigned char *)iv, p, IV_LEN * 4);
				p += IV_LEN * 4;
			}
		}
	}

	/* Private key flag */
	sprintf((char *)p, "%02d", i_index);
	p += 2;

	if (i_index == 99)
	{
		/* Private key length */
		sprintf((char *)p, "%04d", private_key_len);
		p += 4;

		/* Private key */
		memcpy(p, private_key, private_key_len);
		p += private_key_len;
	}

	*p = 0x00;

	cmdlen = p - cmd;


	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	if (ret) {
		//TraceMessage("sjl22.log", cmd, cmdlen);
		//TraceMessage("sjl22.log", rsp, rsplen);
		free(cmd);
		return (ret);
	}



	p = rsp;

	/* The output PKCS#8 private key length */
	if ((*data_len = dec2int((unsigned char*)p, 4)) < 0)
	{
		//TraceMessage("sjl22.log", cmd, cmdlen);
		//TraceMessage("sjl22.log", rsp, rsplen);
		free(cmd);
		return -198;
	}
	free(cmd);
	p += 4;

	/* The output PKCS#8 private key information */
	memcpy(data, p, *data_len);
	p += *data_len;

	return 0;
}

/* 2M */
int objectmac(int comid, int msghdlen, char * msghd, int algo, int dalgo, int modeflag, int macalgflag, int keyflag,
	int blocktype, int padmode, char * mackeytype, char * mackey, char *macin,
	char* keytype, int keylen, char * key, int indatalen, char * indata, char * macout, int * maclen)

{
	char    *cmd, *p;
	int     cmdlen, rsplen;
	char    rsp[MAX_MSGDATA + 1];

	int 	ret;


	if (keylen > LEN_MAX_BLOCK)
	{
		return(-106);
	}

	if (indatalen > LEN_MAX_BLOCK * 3)
	{
		return(-106);
	}


	cmd = (char *)malloc(sizeof(char)*(
		/* Message header */
		msghdlen +
		2 +			/* Command Code */
		3 +                     /* Pxx */
		2 + 			/* mode flag */
		1 +			/* mac alg flag */
		1 +			/* key flag */
		1 +			/* block type */
		1 +			/* pad mode */
		4 +                     /* mac key type */
		49 +			/* mac key under LMK */
		8 +                     /* mac in */
		4 +                     /* key type */
		49 +			/* key under LMK */
		4 +			/* key length */
		keylen * 2 +              /* key */
		4 +                     /* indatalen*/
		indatalen +              /* indata */
/* If trailer present,
End trailer delimiter + Message trailer + NULL char */
1));

	if (cmd == NULL)	return (-1);

	p = cmd;

	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	// RACAL COMMAND CODE '2M'
	*/
	*p++ = '2';
	*p++ = 'M';
	*p++ = 'P';
	*p++ = '0' + algo;
	*p++ = '0' + dalgo;


	sprintf((char *)p, "%02d", modeflag);
	p += 2;

	*p++ = '0' + macalgflag;
	*p++ = '0' + keyflag;
	*p++ = '0' + blocktype;
	*p++ = '0' + padmode;

	memcpy(p, mackeytype, 3);
	p += 3;

	if (macalgflag == 0) {
		UnpackBCD((unsigned char *)mackey, p, 16);
		p += 16;
	}
	else {
		UnpackBCD((unsigned char *)mackey, p, 32);
		p += 32;
	}

	if (modeflag == 1) {
		memcpy(p, macin, 4);
		p += 4;
	}

	if (modeflag == 11) {
		memcpy(p, macin, 8);
		p += 8;
	}

	if (keyflag == 0 || keyflag == 5 || keyflag == 6) {
		memcpy(p, keytype, 3);
		p += 3;

		*p++ = '0' + ((keylen / 8) - 1);
		UnpackBCD((unsigned char *)key, p, keylen * 2);
		p += keylen * 2;
	}
	else {
		sprintf((char *)p, "%04d", keylen);
		p += 4;

		memcpy(p, key, keylen);
		p += keylen;
	}

	sprintf((char *)p, "%04d", indatalen);
	p += 4;

	memcpy(p, indata, indatalen);
	p += indatalen;


	*p = 0x00;
	cmdlen = p - cmd;

	/*        //TraceMessage("sjl22.log", cmd, cmdlen); */

	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	/*        //TraceMessage("sjl22.log", rsp, rsplen); */
	free(cmd);

	if (ret < 0)
	{
		return ret;
	}


	p = rsp;
	/*
	// Translated ZAK; encrypted under LMK pair 26 - 27
	*/
	if (modeflag == 0) {
		memcpy(macout, p, 4);
		p += 4;
		*maclen = 4;
	}
	else {
		memcpy(macout, p, 8);
		p += 8;
		*maclen = 8;
	}


	return 0;

}

/* - VX */
int  xlateoperate(int comid,
	int msghdlen, char * msghd, int algo, int dalgo, int decmode, int encmode, int oformat,
	char * deckeytype, int deckeylen, char * deckey, char * deciv,
	char * enckeytype, int enckeylen, char * enckey, char * enciv,
	int indatalen, char * indata, int * outdatalen, char *outdata,
	int * encpriexponentlen, char * encpriexponent, int * encplen, char * encp,
	int * encqlen, char * encq, int * encd1len, char * encd1,
	int * encd2len, char * encd2, int * encqinvlen, char * encqinv)
{
	char    *cmd, *p;
	int     cmdlen, rsplen;
	char    rsp[MAX_MSGDATA + 1];

	int 	ret;



	if (indatalen > LEN_MAX_BLOCK)
	{
		return(-106);
	}



	cmd = (char *)malloc(sizeof(char)*(
		/* Message header */
		msghdlen +
		2 +			/* Command Code */
		3 +
		1 +                     /* dec mode */
		1 +                     /* enc mode */
		1 +                     /* out format method */
		4 +                     /* dec key type */
		1 +                     /* dec key len */
		48 +                     /* dec key */
		48 +                     /* dec iv */
		4 +                     /* enc key type */
		1 +                     /* enc key len */
		48 +                     /* enc key */
		48 +                     /* enc iv */
		4 +                     /* indata len */
		indatalen +                     /* indata */
				/* If trailer present,
				End trailer delimiter + Message trailer + NULL char */
		+1));

	if (cmd == NULL)	return (-1);

	p = cmd;

	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	// RACAL COMMAND CODE 'VX'
	*/
	*p++ = 'V';
	*p++ = 'X';

	*p++ = 'P';
	*p++ = '0' + algo;
	*p++ = '0' + dalgo;

	*p++ = '0' + decmode;
	*p++ = '0' + encmode;

	*p++ = '0' + oformat;


	if (decmode != 3) {
		memcpy(p, deckeytype, 3);
		p += 3;

		*p++ = '0' + ((deckeylen / 8) - 1);
		UnpackBCD((unsigned char *)deckey, p, deckeylen * 2);
		p += deckeylen * 2;

		if ((decmode == 1) || (decmode == 2)) {
			if (algo == ALGO_DESTDES) {
				memcpy(p, deciv, 8);
				p += 8;
			}
			else {
				memcpy(p, deciv, 16);
				p += 16;
			}
		}
	}


	memcpy(p, enckeytype, 3);
	p += 3;

	*p++ = '0' + ((enckeylen / 8) - 1);
	UnpackBCD((unsigned char *)enckey, p, enckeylen * 2);
	p += enckeylen * 2;

	if ((encmode == 1) || (encmode == 2)) {
		if (dalgo == ALGO_DESTDES) {
			memcpy(p, enciv, 8);
			p += 8;
		}
		else {
			memcpy(p, enciv, 16);
			p += 16;
		}
	}

	sprintf((char *)p, "%04d", indatalen);
	p += 4;

	if ((decmode == 3) && (indatalen == 2)) {
		sprintf((char *)p, "%02d", indata[0]);
		p += 2;
	}
	else {

		memcpy(p, indata, indatalen);
		p += indatalen;
	}



	*p = 0x00;

	cmdlen = p - cmd;

	/*        //TraceMessage("sjl22.log", cmd, cmdlen); */

	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);
	/*        //TraceMessage("sjl22.log", rsp, rsplen); */
	free(cmd);

	if (ret < 0)
	{
		return ret;
	}


	p = rsp;

	if ((*outdatalen = dec2int((unsigned char*)p, 4)) < 0)
	{
		return -198;
	}
	p += 4;

	memcpy(outdata, p, *outdatalen);
	p += *outdatalen;


	if (decmode == 3) {


		if ((*encpriexponentlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(encpriexponent, p, *encpriexponentlen);
		p += *encpriexponentlen;


		if ((*encplen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(encp, p, *encplen);
		p += *encplen;


		if ((*encqlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(encq, p, *encqlen);
		p += *encqlen;


		if ((*encd1len = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(encd1, p, *encd1len);
		p += *encd1len;


		if ((*encd2len = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(encd2, p, *encd2len);
		p += *encd2len;


		if ((*encqinvlen = dec2int((unsigned char*)p, 4)) < 0)
		{
			return -198;
		}
		p += 4;

		memcpy(encqinv, p, *encqinvlen);
		p += *encqinvlen;
	}



	return 0;
}

/* Generate and Verify MAC on large data using ZAK or TAK "VM"*/
int genverifymac(
	int comid,
	int msghdlen, char *msghd,
	int algo,
	int mode_flag,
	int MACalgo,

	int pad_method,
	int block_type,
	char *key_type,
	int key_len,
	char *wk_lmk,
	char * mac_in,
	char * iv_in,
	int data_len,
	char *data,
	char * iv_out,
	char *mac_out
)
{

	char	*cmd, *p;
	int	cmdlen, rsplen;
	char	rsp[MAX_MSGDATA + 1];
	int     ret;



	if (key_len > 49)
	{
		return(-106);
	}



	switch (mode_flag)
	{
	case 00:
	case 01:
	case 10:
	case 11:
		break;
	default:
		return (-102);
	}





	if (data_len > LEN_MAX_BLOCK)
	{
		return(-106);
	}




	cmd = (char *)malloc(sizeof(char)*(
		msghdlen +		/* Message header */
		2 +		/* Command Code */
		3 +             /* algo */
		2 +		/* Mode flag */
		1 +		/* MAC algorithm */
		1 +		/* block type */
		4 +		/* Key type */
		49 +		/* ZAK/TAK under LMK */
		8 +             /* mac in */
		48 +		/* IV in */
		4 +		/* data length */
		data_len +		/* data */
		1));

	if (cmd == NULL)	return (-1);

	p = cmd;


	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	/*
	// COMMAND CODE 'VM'
	*/
	*p++ = 'V';
	*p++ = 'M';


	*p++ = 'P';
	*p++ = '0' + algo;
	*p++ = '0' + algo;






	sprintf((char *)p, "%02d", mode_flag);
	p += 2;

	*p++ = '0' + MACalgo;


	*p++ = '0' + block_type;


	memcpy(p, key_type, 3);
	p += 3;

	if (key_len == 8) {
		*p++ = 'Z';
	}

	if (key_len == 16) {
		*p++ = 'X';
	}
	if (key_len == 24) {
		*p++ = 'Y';
	}

	UnpackBCD((unsigned char *)wk_lmk, p, key_len * 2);

	p += key_len * 2;


	switch (mode_flag)
	{
	case 01:
	{
		if ((block_type == 0) || (block_type == 3)) {
			memcpy(p, mac_in, 4);
			p += 4;
		}

	}
	break;
	case 11:
	{
		if ((block_type == 0) || (block_type == 3)) {
			memcpy(p, mac_in, 8);
			p += 8;
		}

	}
	break;
	case 00:
	case 10:
	default:
	{

	}
	break;
	}

	/*
	// ICV
	*/
	switch (block_type)
	{

	case 2:
	case 3:
	{
		if (algo == ALGO_DESTDES) {
			memcpy(p, iv_in, 8);
			p += 8;
		}
		else {
			memcpy(p, iv_in, 16);
			p += 16;
		}
	} break;
	case 0:
	case 1:
	default:
	{
	} break;
	}

	/*
	// Message length
	*/
	sprintf((char *)p, "%04d", data_len);

	p += 4;

	/*
	// Data to be MACed: Max. length 7680 or larger
	*/
	memcpy(p, data, data_len);

	p += data_len;


	*p = 0x00;

	cmdlen = p - cmd;

	//        //TraceMessage("sjl22.log", cmd, cmdlen);


	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdlen, (char *)rsp, &rsplen);

	//	//TraceMessage("sjl22.log", rsp, rsplen);

	free(cmd);

	if (ret < 0)
	{
		return (ret);
	}



	p = rsp;
	/*
	// MAC: The calculated MAB/MAC.
	*/
	switch (mode_flag)
	{
	case 00:
	{
		if ((block_type == 0) || (block_type == 3)) {
			memcpy(mac_out, p, 4);
			p += 4;
		}

	}
	break;
	case 10:
	{
		if ((block_type == 0) || (block_type == 3)) {
			memcpy(mac_out, p, 8);
			p += 8;
		}

	}
	break;
	case 01:
	case 11:
	default:
	{

	}
	break;
	}

	/*
	// ICV
	*/
	switch (block_type)
	{

	case 1:
	case 2:
	{
		if (algo == ALGO_DESTDES) {
			memcpy(iv_out, p, 8);
			p += 8;
		}
		else {
			memcpy(iv_out, p, 16);
			p += 16;
		}
	} break;
	case 0:
	case 3:
	default:
	{
	} break;
	}

	return 0;
}

