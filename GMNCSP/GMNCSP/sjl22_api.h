#ifndef __SJL22_API__
#define __SJL22_API__

#define MAX_PIN_SIZE 32

#define NULL_PTR NULL

int testHSM(int comid, int msghdlen, char * msghd, char *chkvalue, char *version);

int encpasswd(int comid, int msghdlen, char * msghd, int passwdlen, char *passwd, char * epin);


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
);


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
);

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
);

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
);

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
);

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
);


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
);

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
);

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
);

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
);

int genrandom(
	int comid,
	int msghdlen, char * msghd,
	int rndLen,
	unsigned char *rnd
);

int genhash(
	int comid,
	int msghdlen, char * msghd,
	int hash_id,
	int data_len,
	UCHAR *data,
	UCHAR *hash_value
);

int gendeskey(int comid, int msghdlen, char *msghd, int algo, int mode, char * keytype, int keylen, int inputmode, int randomgen, int maskinput, int timeout, \
	int promptlen, char * prompt, int nofcomp1, char *porekey, int nofcomp2, char *twokeys, UCHAR *outkey, char *kcv);

int derivatekey(int comid, int msghdlen, char *msghd, int algo, int derivationmode, int encmode, char * derivedkeytype, char * derivationkeytype, \
	int derivationkeylen, char * derivationkey, int datalen1, char * iv1, char *derivate_data1, int datalen2, char * iv2, char *derivate_data2, char * derivedkey, char * kcv);

int derivateEMVkey(int comid, int msghdlen, char *msghd, int algo, int mode, char * derivedkeytype, char * derivationkeytype, \
	int derivationkeylen, char * derivationkey, char * iv, char *gpkey, char *pkey, int branch, \
	int hparam, int apptranscnt, int napptranscnt, int keyscheme, int kcvtype, char * ngpkey, char *npkey, char * derivedkey, char *kcv);
int derivateFISCPBOCkey(int comid, int msghdlen, char *msghd, int algo, int mode, char * derivedkeytype, char * derivationkeytype, \
	int derivationkeylen, char * derivationkey, char * derivationdata, char * keytype, int keylen, char * key, \
	char * derivedkey, char * kcv);
int gepin(int comid, int msghdlen, char *msghd, int algo, int mode, int encmode, int cpinlen, char * cpin, int pinfmt, int pinpadmode, \
	char * pinkeytype, int pinkeylen, char * pinkey, char * iv, char * pan, int *epinlen, char * epin);





int desencrypt(int comid, int msghdlen, char *msghd, int algo, int encmode, char * keytype, int keylen, char *key, char * iv, \
	int indatalen, char *indata, int * outdatalen, char *outdata);

int desdecrypt(int comid, int msghdlen, char *msghd, int algo, int encmode, char * keytype, int keylen, char *key, char * iv, \
	int indatalen, char *indata, int * outdatalen, char *outdata);

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
);

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
);



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
);


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
);


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
);





int objectmac(int comid, int msghdlen, char * msghd, int algo, int dalgo, int modeflag, int macalgflag, int keyflag,
	int blocktype, int padmode, char * mackeytype, char * mackey, char *macin,
	char* keytype, int keylen, char * key, int indatalen, char * indata, char * macout, int * maclen);


int  xlateoperate(int comid,
	int msghdlen, char * msghd, int algo, int dalgo, int decmode, int encmode, int oformat,
	char * deckeytype, int deckeylen, char * deckey, char * deciv,
	char * enckeytype, int enckeylen, char * enckey, char * enciv,
	int indatalen, char * indata, int * outdatalen, char *outdata,
	int * encpriexponentlen, char * encpriexponent, int * encplen, char * encp,
	int * encqlen, char * encq, int * encd1len, char * encd1,
	int * encd2len, char * encd2, int * encqinvlen, char * encqinv);



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
);



#endif

