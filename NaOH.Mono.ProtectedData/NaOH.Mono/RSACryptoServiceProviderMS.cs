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
    using System.IO;
    using System.Security;
    using System.Diagnostics.Contracts;

    [System.Runtime.InteropServices.ComVisible(true)]
    internal sealed partial class RSACryptoServiceProvider : RSA, ICspAsymmetricAlgorithm
    {
        private static volatile CspProviderFlags s_UseMachineKeyStore = 0;

        public static bool UseMachineKeyStore
        {
            get { return (s_UseMachineKeyStore == CspProviderFlags.UseMachineKeyStore); }
            set { s_UseMachineKeyStore = (value ? CspProviderFlags.UseMachineKeyStore : 0); }
        }
    }
}
