﻿//
// RSACryptoServiceProvider.cs: Handles an RSA implementation.
//
// Authors:
//	Sebastien Pouliot <sebastien@ximian.com>
//	Ben Maurer (bmaurer@users.sf.net)
//
// (C) 2002, 2003 Motus Technologies Inc. (http://www.motus.com)
// Portions (C) 2003 Ben Maurer
// Copyright (C) 2004-2005 Novell, Inc (http://www.novell.com)
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
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace NaOH.Mono
{

    internal partial class RSACryptoServiceProvider
    {
        private const int PROV_RSA_FULL = 1;    // from WinCrypt.h

        private KeyPairPersistence store;
        private bool persistKey;
        private bool persisted;

        private bool privateKeyExportable = true;
        private bool m_disposed;

        private RSAManaged rsa;

        public RSACryptoServiceProvider(int dwKeySize, CspParameters parameters)
        {
            bool has_parameters = parameters != null;
            Common(dwKeySize, has_parameters);
            if (has_parameters)
                Common(parameters);
            // no keypair generation done at this stage
        }

        private void Common(int dwKeySize, bool parameters)
        {
            // Microsoft RSA CSP can do between 384 and 16384 bits keypair
            LegalKeySizesValue = new KeySizes[1];
            LegalKeySizesValue[0] = new KeySizes(384, 16384, 8);
            base.KeySize = dwKeySize;

            rsa = new RSAManaged(KeySize);

            persistKey = parameters;
            if (parameters)
                return;

            // no need to load - it cannot exists
            var p = new CspParameters(PROV_RSA_FULL);
            if (UseMachineKeyStore)
                p.Flags |= CspProviderFlags.UseMachineKeyStore;
            store = new KeyPairPersistence(p);
        }

        private void Common(CspParameters p)
        {
            store = new KeyPairPersistence(p);
            bool exists = store.Load();
            bool required = (p.Flags & CspProviderFlags.UseExistingKey) != 0;
            privateKeyExportable = (p.Flags & CspProviderFlags.UseNonExportableKey) == 0;

            if (required && !exists)
                throw new CryptographicException("Keyset does not exist");

            if (store.KeyValue != null)
            {
                persisted = true;
                FromXmlString(store.KeyValue);
            }
        }

        public override int KeySize
        {
            get
            {
                if (rsa == null)
                    return KeySizeValue;
                else
                    return rsa.KeySize;
            }
        }

        public bool PublicOnly
        {
            get { throw new NotImplementedException(); }
        }

        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            throw new NotImplementedException();
        }

        public override void ImportParameters(RSAParameters parameters)
        {
            throw new NotImplementedException();
        }

        public byte[] SignHash(byte[] rgbHash, string str)
        {
            throw new NotImplementedException();
        }

        // NOTE: this method can work with ANY configured (OID in machine.config)
        // HashAlgorithm descendant
        public bool VerifyData(byte[] buffer, object halg, byte[] signature)
        {
            throw new NotImplementedException();
        }

        public bool VerifyHash(byte[] rgbHash, string str, byte[] rgbSignature)
        {
            throw new NotImplementedException();
        }

        protected override void Dispose(bool disposing)
        {
            if (!m_disposed)
            {
                // the key is persisted and we do not want it persisted
                if ((persisted) && (!persistKey))
                {
                    store.Remove(); // delete the container
                }
                rsa?.Clear();
                // call base class
                // no need as they all are abstract before us
                m_disposed = true;
            }
        }

        // ICspAsymmetricAlgorithm

        public CspKeyContainerInfo CspKeyContainerInfo
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public byte[] ExportCspBlob(bool includePrivateParameters)
        {
            throw new NotImplementedException();
        }

        public void ImportCspBlob(byte[] keyBlob)
        {
            throw new NotImplementedException();
        }
    }
}
