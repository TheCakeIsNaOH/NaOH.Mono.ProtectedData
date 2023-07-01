//
// ManagedProtection.cs -
//	Protect (encrypt) data without (user involved) key management
//
// Author:
//	Sebastien Pouliot  <sebastien@ximian.com>
//
// Copyright (C) 2005 Novell, Inc (http://www.novell.com)
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;
using System.Security.Cryptography;

namespace NaOH.Mono
{

    // Managed Protection Implementation
    //
    // Features
    // * Separate RSA 1536 bits keypairs for each user and the computer
    // * AES 128 bits encryption (separate key for each data protected)
    // * SHA256 digest to ensure integrity

    internal static class ManagedProtection
    {
        public static byte[] Unprotect(byte[] encryptedData, byte[] optionalEntropy, DataProtectionScope scope)
        {
            if (encryptedData == null)
                throw new System.ArgumentNullException("encryptedData");

            byte[] decdata = null;

            Rijndael aes = Rijndael.Create();
            RSA rsa = GetKey(scope);
            int headerSize = (rsa.KeySize >> 3);
            bool valid1 = (encryptedData.Length >= headerSize);
            if (!valid1)
                headerSize = encryptedData.Length;

            byte[] header = new byte[headerSize];
            Buffer.BlockCopy(encryptedData, 0, header, 0, headerSize);

            byte[] secret = null;
            byte[] key = null;
            byte[] iv = null;
            bool valid2 = false;
            bool valid3 = false;
            bool valid4 = false;
            SHA256 hash = SHA256.Create();

            try
            {
                try
                {
                    RSAOAEPKeyExchangeDeformatter deformatter = new RSAOAEPKeyExchangeDeformatter(rsa);
                    secret = deformatter.DecryptKeyExchange(header);
                    valid2 = (secret.Length == 68);
                }
                catch
                {
                    valid2 = false;
                }

                if (!valid2)
                    secret = new byte[68];

                // known values for structure (version 1 or 2)
                valid3 = ((secret[1] == 16) && (secret[18] == 16) && (secret[35] == 32));

                key = new byte[16];
                Buffer.BlockCopy(secret, 2, key, 0, 16);
                iv = new byte[16];
                Buffer.BlockCopy(secret, 19, iv, 0, 16);

                if ((optionalEntropy != null) && (optionalEntropy.Length > 0))
                {
                    // the decrypted data won't be valid if the entropy isn't
                    // the same as the one used to protect (encrypt) it
                    byte[] mask = hash.ComputeHash(optionalEntropy);
                    for (int i = 0; i < 16; i++)
                    {
                        key[i] ^= mask[i];
                        iv[i] ^= mask[i + 16];
                    }
                    valid3 &= (secret[0] == 2); // with entropy
                }
                else
                {
                    valid3 &= (secret[0] == 1); // without entropy
                }

                using (System.IO.MemoryStream ms = new System.IO.MemoryStream())
                {
                    ICryptoTransform t = aes.CreateDecryptor(key, iv);
                    using (CryptoStream cs = new CryptoStream(ms, t, CryptoStreamMode.Write))
                    {
                        try
                        {
                            cs.Write(encryptedData, headerSize, encryptedData.Length - headerSize);
                            cs.Close();
                        }
                        catch
                        {
                            // whatever, we keep going
                        }
                    }
                    decdata = ms.ToArray();
                }

                byte[] digest = hash.ComputeHash(decdata);
                valid4 = true;
                for (int i = 0; i < 32; i++)
                {
                    if (digest[i] != secret[36 + i])
                        valid4 = false;
                }
            }
            finally
            {
                if (key != null)
                {
                    Array.Clear(key, 0, key.Length);
                    key = null;
                }
                if (secret != null)
                {
                    Array.Clear(secret, 0, secret.Length);
                    secret = null;
                }
                if (iv != null)
                {
                    Array.Clear(iv, 0, iv.Length);
                    iv = null;
                }
                aes.Clear();
                hash.Clear();
            }

            // single point of error (also limits timing informations)
            if (!valid1 || !valid2 || !valid3 || !valid4)
            {
                if (decdata != null)
                {
                    Array.Clear(decdata, 0, decdata.Length);
                    decdata = null;
                }
                throw new CryptographicException("Invalid data.");
            }
            return decdata;
        }

        // private stuff

        private static RSA user;
        private static RSA machine;
        private readonly static object user_lock = new object();
        private readonly static object machine_lock = new object();

        private static RSA GetKey(DataProtectionScope scope)
        {
            switch (scope)
            {
                case DataProtectionScope.CurrentUser:
                    if (user == null)
                    {
                        lock (user_lock)
                        {
                            CspParameters csp = new CspParameters();
                            csp.KeyContainerName = "DAPI";
                            user = new NaOH.Mono.RSACryptoServiceProvider(1536, csp);
                        }
                    }
                    return user;
                case DataProtectionScope.LocalMachine:
                    if (machine == null)
                    {
                        lock (machine_lock)
                        {
                            CspParameters csp = new CspParameters();
                            csp.KeyContainerName = "DAPI";
                            csp.Flags = CspProviderFlags.UseMachineKeyStore;
                            machine = new NaOH.Mono.RSACryptoServiceProvider(1536, csp);
                        }
                    }
                    return machine;
                default:
                    throw new CryptographicException("Invalid scope.");
            }
        }
    }
}
