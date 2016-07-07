#ifndef CODEC_H
#define CODEC_H 1

#include <xpl.h>

// codecFile() error codes
#define CODEC_OK			0
#define CODEC_IO_ERROR			1
#define CODEC_OPEN_FILE_ERROR		2
#define CODEC_CREATE_FILE_ERROR		3
#define CODEC_NOT_ENOUGH_MEMORY		4

// codecInit(,ulType), codecConvBuf(ulType,,,,)
#define CODEC_ENC_BASE64		0
#define CODEC_DEC_BASE64		1
#define CODEC_ENC_QUOTED_PRINTABLE	2 // Quoted-printable without SP, CRLF.
#define CODEC_ENC_QUOTED_PRINTABLE_SP	3 // More readable quoted-printable.
#define CODEC_DEC_QUOTED_PRINTABLE	4
#define CODEC_ENC_DEC_8BIT		5

// codecEncodedWordNew(ulType,,)
#define CODEC_EW_BASE64			0x00000000 // -, bits 0-7, mask FF
#define CODEC_EW_AUTO			0x00000001 //  |
#define CODEC_EW_QUOTED_PRINTABLE	0x00000002 //  |
#define CODEC_EW_PLAIN			0x00000005 // -'
#define CODEC_EW_MODE_MESSAGE		0x00000000 // -, bit 8
#define CODEC_EW_MODE_HTTP		0x00000100 // -'

typedef struct _CODEC {
  PVOID		pFunc;
  CHAR		acInBuf[4];
  ULONG		cbInBuf;
  CHAR		acOutBuf[8];
  ULONG		cbOutBuf;
  ULONG		ulOutCnt;
} CODEC, *PCODEC;

BOOL codecInit(PCODEC pCodec, ULONG ulType);
// codecConv(), rc != 0 when have internal data for output ==> must be called
//              with *pcbSrc == 0 to pool last bytes.
ULONG codecConv(PCODEC pCodec, PCHAR *ppcDst, PULONG pcbDst, PCHAR *ppcSrc,
               PULONG pcbSrc);
// codecConvBuf(), rc - number of bytes written to pcDst or
//                 -1 - invalid encode/decode type
//                 -2 - not enough space
LONG codecConvBuf(ULONG ulType, PCHAR pcDst, ULONG cbDst,
                  PCHAR pcSrc, ULONG cbSrc);
// codecFile() return CODEC_* error codes
ULONG codecFile(PCODEC pCodec, PSZ pszFOut, PSZ pszFIn);
PSZ codecEncodedWordNew(ULONG ulType, PSZ pszCharset, ULONG ulFirstLineSpace,
                        PSZ pszData);
PSZ codecDecodeWordNew(PSZ pszCharset, PCHAR pcData, ULONG cbData);
VOID codecFree(PSZ pszEncodedWord);
// codecIConvBuf(), rc - number of bytes written to pcDst or
//                  -1 - invalid charset or character in source
//                  -2 - not enough destination space
LONG codecIConvBuf(PSZ pszDstCode, PCHAR pcDst, ULONG cbDst,
                   PSZ pszSrcCode, PCHAR pcSrc, ULONG cbSrc);

#endif // CODEC_H
