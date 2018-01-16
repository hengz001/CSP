#ifndef	__SJL22X_HSM__
#define	__SJL22X_HSM__

#include <stdio.h>


char HexToASCII(int ch);
char *strupper(char *str);
unsigned char *int_to_byte2(int i, unsigned char *p);
unsigned char *short2hex(unsigned short s, unsigned char *p);
unsigned char *long2hex(unsigned long l, unsigned char *p);
int isBufferHex(char *buffer, int len);
int hex2int(unsigned char *buffer, int len);
unsigned long hex2long(unsigned char *p);
unsigned short hex2short(unsigned char *p);
int CheckNum(char *str);
int UnpackBCD(unsigned char *InBuf, char *OutBuf, int Len);
int PackBCD(char *InBuf, unsigned char *OutBuf, int Len);
int CheckSchem(char schem);

int CheckAlgo(int algo);

int GetIvLength(int algo);

int GetKeyLen(char *key);

int GetCvLength(char cvFlag);

void GetByteNum(int bitnum, int *bytenum);

int GetDerByteNum(unsigned char *DerBuffer, long *derbytenum);

void rsaFormParmBlockOAEP(unsigned char **buf, int mgf, int mgfHash, int OAEP_parm_len, unsigned char *OAEP_parm);

void rsaFormParmBlockPSS(unsigned char **buf, int mgf, int mgfHash, int pssRule, int trailerField);

int isBufferDec(char *buffer, int len);

int dec2int(unsigned char *buffer, int len);

int Decode_PublicKey_Der(unsigned char *der_buf, int *bufLen, unsigned char *n, int *nlen, unsigned char *e, int *elen);

int Encode_PublicKey_Der(unsigned char * n, int nlen, unsigned char * e, int elen, unsigned char *der_buf, int *bufLen);

int Encode_ECPublicKey_Der(unsigned char * pubkey, int pubkeylen, unsigned char *der_buf, int *bufLen);

int Decode_ECPublicKey_Der(unsigned char *der_buf, int *bufLen, unsigned char *pubkey, int *pubkeylen);



#endif


