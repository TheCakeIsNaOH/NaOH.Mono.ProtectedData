// ==++==
//
//   Copyright (c) Microsoft Corporation.  All rights reserved.
//
// ==--==
// <OWNER>Microsoft</OWNER>
//

//
// RSACryptoServiceProvider.cs
//
// CSP-based implementation of RSA
//

using System.Security.Cryptography;

namespace NaOH.Mono
{
    using System;
    using System.Globalization;
    using System.IO;
    using System.Security;
    using System.Runtime.InteropServices;
    using System.Runtime.CompilerServices;
    using System.Runtime.Versioning;
    using System.Security.Cryptography.X509Certificates;
    using System.Security.Permissions;
    using System.Diagnostics.Contracts;

    [System.Runtime.InteropServices.ComVisible(true)]
    internal sealed partial class RSACryptoServiceProvider : RSA
        , ICspAsymmetricAlgorithm
    {
        private static volatile CspProviderFlags s_UseMachineKeyStore = 0;

        public override string SignatureAlgorithm
        {
            get { return "http://www.w3.org/2000/09/xmldsig#rsa-sha1"; }
        }

        public static bool UseMachineKeyStore
        {
            get { return (s_UseMachineKeyStore == CspProviderFlags.UseMachineKeyStore); }
            set { s_UseMachineKeyStore = (value ? CspProviderFlags.UseMachineKeyStore : 0); }
        }
        //
        // Adapt new RSA abstraction to legacy RSACryptoServiceProvider surface area.
        //

        // NOTE: For the new API, we go straight to CAPI for fixed set of hash algorithms and don't use crypto config here.
        //
        // Reasons:
        //       1. We're moving away from crypto config and we won't have it when porting to .NET Core
        //
        //       2. It's slow to lookup and slow to use as the base HashAlgorithm adds considerable overhead
        //          (redundant defensive copy + double-initialization for the single-use case).
        //

        [SecuritySafeCritical]
        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            // we're sealed and the base should have checked this already
            Contract.Assert(data != null);
            Contract.Assert(offset >= 0 && offset <= data.Length);
            Contract.Assert(count >= 0 && count <= data.Length);
            Contract.Assert(!String.IsNullOrEmpty(hashAlgorithm.Name));

            var hash = HashAlgorithm.Create (hashAlgorithm.Name);
            return hash.ComputeHash (data, offset, count);
        }

        [SecuritySafeCritical]
        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
        {
            // we're sealed and the base should have checked this already
            Contract.Assert(data != null);
            Contract.Assert(!String.IsNullOrEmpty(hashAlgorithm.Name));

            var hash = HashAlgorithm.Create (hashAlgorithm.Name);
            return hash.ComputeHash (data);
        }

        private static int GetAlgorithmId(HashAlgorithmName hashAlgorithm)
        {
            switch (hashAlgorithm.Name)
            {
                case "MD5":
                    return Constants.CALG_MD5;
                case "SHA1":
                    return Constants.CALG_SHA1;
                case "SHA256":
                    return Constants.CALG_SHA_256;
                case "SHA384":
                    return Constants.CALG_SHA_384;
                case "SHA512":
                    return Constants.CALG_SHA_512;
                default:
                    throw new CryptographicException("Cryptography_UnknownHashAlgorithm");
            }
        }

        public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
        {
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }
            if (padding == null)
            {
                throw new ArgumentNullException("padding");
            }

            if (padding == RSAEncryptionPadding.Pkcs1)
            {
                return Encrypt(data, fOAEP: false);
            }
            else if (padding == RSAEncryptionPadding.OaepSHA1)
            {
                return Encrypt(data, fOAEP: true);
            }
            else
            {
                throw PaddingModeNotSupported();
            }
        }

        public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
        {
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }
            if (padding == null)
            {
                throw new ArgumentNullException("padding");
            }

            if (padding == RSAEncryptionPadding.Pkcs1)
            {
                return Decrypt(data, fOAEP: false);
            }
            else if (padding == RSAEncryptionPadding.OaepSHA1)
            {
                return Decrypt(data, fOAEP: true);
            }
            else
            {
                throw PaddingModeNotSupported();
            }
        }

        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            if (hash == null)
            {
                throw new ArgumentNullException("hash");
            }
            if (String.IsNullOrEmpty(hashAlgorithm.Name))
            {
                throw HashAlgorithmNameNullOrEmpty();
            }
            if (padding == null)
            {
                throw new ArgumentNullException("padding");
            }
            if (padding != RSASignaturePadding.Pkcs1)
            {
                throw PaddingModeNotSupported();
            }

            return SignHash(hash, GetAlgorithmId(hashAlgorithm));
        }

        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            if (hash == null)
            {
                throw new ArgumentNullException("hash");
            }
            if (signature == null)
            {
                throw new ArgumentNullException("signature");
            }
            if (String.IsNullOrEmpty(hashAlgorithm.Name))
            {
                throw HashAlgorithmNameNullOrEmpty();
            }
            if (padding == null)
            {
                throw new ArgumentNullException("padding");
            }
            if (padding != RSASignaturePadding.Pkcs1)
            {
                throw PaddingModeNotSupported();
            }

            return VerifyHash(hash, GetAlgorithmId(hashAlgorithm), signature);
        }

        private static Exception PaddingModeNotSupported()
        {
            return new CryptographicException("Cryptography_InvalidPaddingMode");
        }

        internal static Exception HashAlgorithmNameNullOrEmpty()
        {
            return new ArgumentException("hashAlgorithm");
        }
    }
}
