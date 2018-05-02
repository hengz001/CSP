#ifndef __PLXAPI_H
#define __PLXAPI_H

/**** Define Api Error Code ****/

#define API_RETURN_CODE_STARTS              0x0000  /* Starting return code */

/* API Return Code Values */
typedef enum _RETURN_CODE {

	ApiSuccess = API_RETURN_CODE_STARTS,
	ApiFailed,
	ApiSsp05cCheckFailed,
	ApiSsp04bCheckFailed,
	ApiHifn7902CheckFailed,
	ApiAccessDenied,
	ApiDriverBusy,
	ApiSignalInter,
	ApiDmaAllocError,
	ApiDmaChannelUnavailable,
	ApiDmaChannelInvalid,
	ApiDmaChannelTypeError,
	ApiDmaInProgress,
	ApiDmaDone,
	ApiDmaPaused,
	ApiDmaNotPaused,
	ApiDmaCommandInvalid,
	ApiDmaManReady,
	ApiDmaManNotReady,
	ApiDmaInvalidChannelPriority,
	ApiDmaManCorrupted,
	ApiDmaInvalidElementIndex,
	ApiDmaNoMoreElements,
	ApiDmaSglInvalid,
	ApiDmaSglQueueFull,
	ApiOperationInProgress,
	ApiOperationDone,
	ApiNullParam,
	ApiInvalidBusIndex,
	ApiUnsupportedFunction,
	ApiInvalidPciSpace,
	ApiInvalidIopSpace,
	ApiInvalidSize,
	ApiInvalidAddress,
	ApiInvalidAccessType,
	ApiInvalidIndex,
	ApiMuNotReady,
	ApiMuFifoEmpty,
	ApiMuFifoFull,
	ApiInvalidRegister,
	ApiDoorbellClearFailed,
	ApiInvalidUserPin,
	ApiInvalidUserState,
	ApiEepromNotPresent,
	ApiEepromTypeNotSupported,
	ApiEepromBlank,
	ApiConfigAccessFailed,
	ApiInvalidDeviceInfo,
	ApiNoActiveDriver,
	ApiInsufficientResources,
	ApiObjectAlreadyAllocated,
	ApiAlreadyInitialized,
	ApiNotInitialized,
	ApiBadConfigRegEndianMode,
	ApiInvalidPowerState,
	ApiPowerDown,
	ApiFlybyNotSupported,
	ApiNotSupportThisChannel,
	ApiNoAction,
	ApiHSNotSupported,
	ApiVPDNotSupported,
	ApiVpdNotEnabled,
	ApiNoMoreCap,
	ApiInvalidOffset,
	ApiBadPinDirection,
	ApiPciTimeout,
	ApiDmaChannelClosed,
	ApiDmaChannelError,
	ApiInvalidHandle,
	ApiBufferNotReady,
	ApiInvalidData,
	ApiDoNothing,
	ApiDmaSglBuildFailed,
	ApiPMNotSupported,
	ApiInvalidDriverVersion,
	ApiInvalidChipType,
	ApiWaitTimeout,
	ApiWaitCanceled,
	ApiLastError               // Do not add API errors below this line

} RETURN_CODE;

/**** Define ioctl param ****/

#define PLX_IOC_MAGIC    'l'			// Crypto "magic" number (for ioctls below)
#define PLX_IOCTL_CODE_BASE	0x80

typedef enum _DRIVER_MSGS {

	MSG_CRYPTO_REQUEST = PLX_IOCTL_CODE_BASE,
	MSG_CRYPTO_RANDOM,
	MSG_CRYPTO_QUERY,
	MSG_CRYPTO_LED,
	MSG_CRYPTO_SUPPORT,
	MSG_CRYPTO_MODIFY,
	MSG_CRYPTO_RESET,
	MSG_DMA_CONTROL,
	MSG_DMA_STATUS,
	MSG_DMA_BLOCK_CHANNEL_OPEN,
	MSG_DMA_BLOCK_TRANSFER,
	MSG_DMA_BLOCK_CHANNEL_CLOSE

} DRIVER_MSGS;

/* exported IOCTLs, we have 'l', 0x80-0xBF */
#define CRYPTO_REQUEST		_IOWR(PLX_IOC_MAGIC,MSG_CRYPTO_REQUEST,arith_req_struct)
#define CRYPTO_REQUEST1		_IOWR(PLX_IOC_MAGIC,MSG_CRYPTO_REQUEST,crypto_req_struct)
#define CRYPTO_RANDOM		_IOWR(PLX_IOC_MAGIC,MSG_CRYPTO_RANDOM,unsigned long)
#define CRYPTO_QUERY		_IOWR(PLX_IOC_MAGIC,MSG_CRYPTO_QUERY,unsigned long)
#define CRYPTO_LED			_IOWR(PLX_IOC_MAGIC,MSG_CRYPTO_LED,unsigned long)
#define CRYPTO_SUPPORT		_IOWR(PLX_IOC_MAGIC,MSG_CRYPTO_SUPPORT,int)
#define CRYPTO_MODIFY		_IOWR(PLX_IOC_MAGIC,MSG_CRYPTO_MODIFY,int)
#define CRYPTO_RESET		_IO(PLX_IOC_MAGIC,MSG_CRYPTO_RESET)

#endif /* __PLXAPI_H  */
