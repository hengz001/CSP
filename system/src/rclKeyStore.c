#include "mgrSvr.h"

/* Read LMKs Keys from Key Card */
int _ReadKeysFromCard ( struct cfgMasterKeyFile_t *ksCard )
{
	//读主密钥
	return _read_lpsram ( (unsigned char *)ksCard, 0, sizeof(struct cfgMasterKeyFile_t));
}

int _ReadParmFromCard ( racal_cfg_t *hsmcfg )
{
	return _read_nvram ( (unsigned char *)hsmcfg, sizeof(racal_cfg_t));
}

int ReadHsmDefaultParm(void)
{
	int    rc;
	struct cfgMasterKeyFile_t ksCard;

	rc = _ReadKeysFromCard(&ksCard);

	if(rc==0)
	{
		rc = _ReadParmFromCard(&phsmShm->hsmcfg);
	}
	return rc;
}

int ReadKeysFromCard(void)
{
	int rc;
	struct cfgMasterKeyFile_t ksCard;

	rc = _ReadKeysFromCard(&ksCard);
	if(rc==0)
	{
		memcpy(phsmShm->LMKs[0],ksCard.LMKs[0],sizeof(phsmShm->LMKs));
		memcpy(phsmShm->oldLMKs[0],ksCard.oldLMKs[0],sizeof(phsmShm->oldLMKs));
	}
	return rc;
}

int ReadRsaKeysFromCard ( void )
{
	return _read_lpsram ( phsmShm->ShareMemRsaKey, HSM_KSTORE_RSA_OFFSET, LEN_RSA_PAD*MAX_RSAKEY);
}

int ReadSm2KeysFromCard ( void )
{
	return _read_lpsram ( phsmShm->ShareMemSm2Key, HSM_KSTORE_SM2_OFFSET, sizeof(SM2Key)*MAX_SM2KEY);
}

int ReadSm4KeysFromCard ( void )
{
	return _read_lpsram ( phsmShm->jkstore, HSM_KSTORE_SM4_OFFSET, MAX_SM4KEY*LEN_SHARE_STORE_KEY);	//20171019modify by xiang
}

