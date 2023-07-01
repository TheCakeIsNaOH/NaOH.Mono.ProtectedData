//
// ProtectedData.cs: Protect (encrypt) data without (user involved) key management
//
// Author:
//	Sebastien Pouliot  <sebastien@ximian.com>
//
//
// (C) 2003 Motus Technologies Inc. (http://www.motus.com)
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

namespace NaOH.Mono
{

    // References:
    // a.	Windows Data Protection
    //	http://msdn.microsoft.com/library/en-us/dnsecure/html/windataprotection-dpapi.asp?frame=true

    public sealed class ProtectedData
    {

        private ProtectedData()
        {
        }

        public static byte[] Unprotect(byte[] encryptedData, byte[] optionalEntropy, DataProtectionScope scope)
        {
            if (encryptedData == null)
                throw new System.ArgumentNullException("encryptedData");

            // on Windows this is supported by CoreFX implementation
            Check(scope);

            switch (impl)
            {
                case DataProtectionImplementation.ManagedProtection:
                    try
                    {
                        return ManagedProtection.Unprotect(encryptedData, optionalEntropy, scope);
                    }
                    catch (System.Exception e)
                    {
                        string msg = "Data unprotection failed.";
                        throw new System.Security.Cryptography.CryptographicException(msg, e);
                    }
                default:
                    throw new System.PlatformNotSupportedException();
            }
        }

        // private stuff

        enum DataProtectionImplementation
        {
            Unknown,
            Win32CryptoProtect,
            ManagedProtection,
            Unsupported = System.Int32.MinValue
        }

        private static DataProtectionImplementation impl;

        private static void Detect()
        {
            System.OperatingSystem os = System.Environment.OSVersion;
            switch (os.Platform)
            {
                case System.PlatformID.Unix:
                    impl = DataProtectionImplementation.ManagedProtection;
                    break;
                case System.PlatformID.Win32NT:
                default:
                    impl = DataProtectionImplementation.Unsupported;
                    break;
            }
        }

        private static void Check(DataProtectionScope scope)
        {
            switch (impl)
            {
                case DataProtectionImplementation.Unknown:
                    Detect();
                    break;
                case DataProtectionImplementation.Unsupported:
                    throw new System.PlatformNotSupportedException();
            }
        }
    }
}
