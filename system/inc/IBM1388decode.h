

#define	CHINESE_BEGIN	0x0e	/* Shift OUT */
#define	CHINESE_END		0x0f	/* Shift IN  */

#define	C_FALSE			0
#define	C_TRUE			1

int IBM1388Decode(UCHAR *SourcePtr, UCHAR *TargetPte, int *DataLen);
