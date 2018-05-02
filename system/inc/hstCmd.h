
int HandleMultiAlgoIdentidyBlock(int cst, unsigned char **buf, int *len,int *mca, int *sca, int *dca);

int hsmCmdInterpret(int cst, int protocol, UCHAR *i_buf, int ilen, UCHAR *o_buf,int *olen, int *prt_cmd);

int WhatExpCmd(UCHAR *cmdcode);

int PreproExpCmd(int proto, UCHAR *buf, int len, int charset);

int isExpCmd(UCHAR *buf, int charset);

UCHAR *getHostCmdString(UCHAR *pBuf, int len, int charset);
