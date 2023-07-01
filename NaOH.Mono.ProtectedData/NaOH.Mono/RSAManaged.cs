//
// RSAManaged.cs - Implements the RSA algorithm.
//
// Authors:
//	Sebastien Pouliot (sebastien@ximian.com)
//	Ben Maurer (bmaurer@users.sf.net)
//
// (C) 2002, 2003 Motus Technologies Inc. (http://www.motus.com)
// Portions (C) 2003 Ben Maurer
// Copyright (C) 2004,2006 Novell, Inc (http://www.novell.com)
//
// Key generation translated from Bouncy Castle JCE (http://www.bouncycastle.org/)
// See bouncycastle.txt for license.
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
using System.Text;

// Big chunks of code are coming from the original RSACryptoServiceProvider class.
// The class was refactored to :
// a.	ease integration of new hash algorithm (like MD2, RIPEMD160, ...);
// b.	provide better support for the coming SSL implementation (requires
//	EncryptValue/DecryptValue) with, or without, Mono runtime/corlib;
// c.	provide an alternative RSA implementation for all Windows (like using
//	OAEP without Windows XP).

namespace NaOH.Mono
{

	internal class RSAManaged : RSA
    {
        private readonly bool keypairGenerated = false;
        private bool m_disposed = false;

        private BigInteger d;
        private BigInteger p;
        private BigInteger q;
        private BigInteger dp;
        private BigInteger dq;
        private BigInteger qInv;
        private BigInteger n;       // modulus
        private BigInteger e;

        public RSAManaged(int keySize)
        {
            LegalKeySizesValue = new KeySizes[1];
            LegalKeySizesValue[0] = new KeySizes(384, 16384, 8);
            base.KeySize = keySize;
        }

        ~RSAManaged()
        {
            // Zeroize private key
            Dispose(false);
        }

        // overrides from RSA class

        public override int KeySize
        {
            get
            {
                if (m_disposed)
                    throw new ObjectDisposedException("Keypair was disposed");

                // in case keypair hasn't been (yet) generated
                if (keypairGenerated)
                {
                    int ks = n.BitCount();
                    if ((ks & 7) != 0)
                        ks += (8 - (ks & 7));
                    return ks;
                }
                else
                    return base.KeySize;
            }
        }

        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            throw new NotImplementedException();
        }

        public override void ImportParameters(RSAParameters parameters)
        {
            throw new NotImplementedException();
        }

        protected override void Dispose(bool disposing)
        {
            if (!m_disposed)
            {
                // Always zeroize private key
                if (d != null)
                {
                    d.Clear();
                    d = null;
                }
                if (p != null)
                {
                    p.Clear();
                    p = null;
                }
                if (q != null)
                {
                    q.Clear();
                    q = null;
                }
                if (dp != null)
                {
                    dp.Clear();
                    dp = null;
                }
                if (dq != null)
                {
                    dq.Clear();
                    dq = null;
                }
                if (qInv != null)
                {
                    qInv.Clear();
                    qInv = null;
                }

                if (disposing)
                {
                    // clear public key
                    if (e != null)
                    {
                        e.Clear();
                        e = null;
                    }
                    if (n != null)
                    {
                        n.Clear();
                        n = null;
                    }
                }
            }
            // call base class
            // no need as they all are abstract before us
            m_disposed = true;
        }

        public override string ToXmlString(bool includePrivateParameters)
        {
            throw new NotImplementedException();
        }
    }
}
