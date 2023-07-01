using System;
using System.Collections.Generic;
using System.Text;

namespace NaOH.Mono
{
    internal static class Constants
    {
        internal const int S_OK                   = 0;
        internal const int NTE_FILENOTFOUND       = unchecked((int) 0x80070002); // The system cannot find the file specified.
        internal const int NTE_NO_KEY             = unchecked((int) 0x8009000D); // Key does not exist.
        internal const int NTE_BAD_KEYSET         = unchecked((int) 0x80090016); // Keyset does not exist.
        internal const int NTE_KEYSET_NOT_DEF     = unchecked((int) 0x80090019); // The keyset is not defined.

        internal const int KP_IV                  = 1;
        internal const int KP_MODE                = 4;
        internal const int KP_MODE_BITS           = 5;
        internal const int KP_EFFECTIVE_KEYLEN    = 19;

        internal const int ALG_CLASS_SIGNATURE    = (1 << 13);
        internal const int ALG_CLASS_DATA_ENCRYPT = (3 << 13);
        internal const int ALG_CLASS_HASH         = (4 << 13);
        internal const int ALG_CLASS_KEY_EXCHANGE = (5 << 13);

        internal const int ALG_TYPE_DSS           = (1 << 9);
        internal const int ALG_TYPE_RSA           = (2 << 9);
        internal const int ALG_TYPE_BLOCK         = (3 << 9);
        internal const int ALG_TYPE_STREAM        = (4 << 9);
        internal const int ALG_TYPE_ANY           = (0);

        internal const int CALG_MD5               = (ALG_CLASS_HASH | ALG_TYPE_ANY | 3);
        internal const int CALG_SHA1              = (ALG_CLASS_HASH | ALG_TYPE_ANY | 4);
        internal const int CALG_SHA_256           = (ALG_CLASS_HASH | ALG_TYPE_ANY | 12);
        internal const int CALG_SHA_384           = (ALG_CLASS_HASH | ALG_TYPE_ANY | 13);
        internal const int CALG_SHA_512           = (ALG_CLASS_HASH | ALG_TYPE_ANY | 14);
        internal const int CALG_RSA_KEYX          = (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | 0);
        internal const int CALG_RSA_SIGN          = (ALG_CLASS_SIGNATURE | ALG_TYPE_RSA | 0);
        internal const int CALG_DSS_SIGN          = (ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | 0);
        internal const int CALG_DES               = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 1);
        internal const int CALG_RC2               = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 2);
        internal const int CALG_3DES              = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 3);
        internal const int CALG_3DES_112          = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 9);
        internal const int CALG_AES_128           = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 14);
        internal const int CALG_AES_192           = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 15);
        internal const int CALG_AES_256           = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 16);
        internal const int CALG_RC4               = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_STREAM | 1);

        internal const int PROV_RSA_FULL = 1;
        internal const int PROV_DSS_DH = 13;
        internal const int PROV_RSA_AES = 24;

        internal const int AT_KEYEXCHANGE         = 1;
        internal const int AT_SIGNATURE = 2;
        internal const int PUBLICKEYBLOB          = 0x6;
        internal const int PRIVATEKEYBLOB         = 0x7;
        internal const int CRYPT_OAEP             = 0x40;


        internal const uint CRYPT_VERIFYCONTEXT    = 0xF0000000;
        internal const uint CRYPT_NEWKEYSET        = 0x00000008;
        internal const uint CRYPT_DELETEKEYSET     = 0x00000010;
        internal const uint CRYPT_MACHINE_KEYSET   = 0x00000020;
        internal const uint CRYPT_SILENT           = 0x00000040;
        internal const uint CRYPT_EXPORTABLE       = 0x00000001;

        internal const uint CLR_KEYLEN            = 1;
        internal const uint CLR_PUBLICKEYONLY     = 2;
        internal const uint CLR_EXPORTABLE        = 3;
        internal const uint CLR_REMOVABLE         = 4;
        internal const uint CLR_HARDWARE          = 5;
        internal const uint CLR_ACCESSIBLE        = 6;
        internal const uint CLR_PROTECTED         = 7;
        internal const uint CLR_UNIQUE_CONTAINER  = 8;
        internal const uint CLR_ALGID             = 9;
        internal const uint CLR_PP_CLIENT_HWND    = 10;
        internal const uint CLR_PP_PIN            = 11;

        internal const string OID_RSA_SMIMEalgCMS3DESwrap   = "1.2.840.113549.1.9.16.3.6";
        internal const string OID_RSA_MD5                   = "1.2.840.113549.2.5";
        internal const string OID_RSA_RC2CBC                = "1.2.840.113549.3.2";
        internal const string OID_RSA_DES_EDE3_CBC          = "1.2.840.113549.3.7";
        internal const string OID_OIWSEC_desCBC             = "1.3.14.3.2.7";
        internal const string OID_OIWSEC_SHA1               = "1.3.14.3.2.26";
        internal const string OID_OIWSEC_SHA256             = "2.16.840.1.101.3.4.2.1";
        internal const string OID_OIWSEC_SHA384             = "2.16.840.1.101.3.4.2.2";
        internal const string OID_OIWSEC_SHA512             = "2.16.840.1.101.3.4.2.3";
        internal const string OID_OIWSEC_RIPEMD160          = "1.3.36.3.2.1";
    }
}
