//
// BigInteger.cs - Big Integer implementation
//
// Authors:
//	Ben Maurer
//	Chew Keong TAN
//	Sebastien Pouliot <sebastien@ximian.com>
//	Pieter Philippaerts <Pieter@mentalis.org>
//
// Copyright (c) 2003 Ben Maurer
// All rights reserved
//
// Copyright (c) 2002 Chew Keong TAN
// All rights reserved.
//
// Copyright (C) 2004, 2007 Novell, Inc (http://www.novell.com)
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

    internal class BigInteger
    {

        #region Data Storage

        /// <summary>
        /// The Length of this BigInteger
        /// </summary>
        uint length = 1;

        /// <summary>
        /// The data for this BigInteger
        /// </summary>
        readonly uint[] data;

        #endregion

        #region Constants

        private enum Sign
        {
            Negative = -1,
            Zero = 0,
            Positive = 1
        };


        #endregion

        #region Conversions
        private BigInteger(uint ui)
        {
            data = new uint[] { ui };
        }

        private BigInteger(ulong ul)
        {
            data = new uint[2] { (uint)ul, (uint)(ul >> 32) };
            length = 2;

            this.Normalize();
        }

        public static implicit operator BigInteger(uint value)
        {
            return (new BigInteger(value));
        }

        public static implicit operator BigInteger(int value)
        {
            if (value < 0) throw new ArgumentOutOfRangeException("value");
            return (new BigInteger((uint)value));
        }

        public static implicit operator BigInteger(ulong value)
        {
            return (new BigInteger(value));
        }

        #endregion

        #region Bitwise

        public int BitCount()
        {
            this.Normalize();

            uint value = data[length - 1];
            uint mask = 0x80000000;
            uint bits = 32;

            while (bits > 0 && (value & mask) == 0)
            {
                bits--;
                mask >>= 1;
            }
            bits += ((length - 1) << 5);

            return (int)bits;
        }

        #endregion

        #region Compare

        public static bool operator ==(BigInteger bi1, BigInteger bi2)
        {
            // we need to compare with null
            if ((bi1 as object) == (bi2 as object))
                return true;
            if (null == bi1 || null == bi2)
                return false;
            return Kernel.Compare(bi1, bi2) == 0;
        }

        public static bool operator !=(BigInteger bi1, BigInteger bi2)
        {
            // we need to compare with null
            if ((bi1 as object) == (bi2 as object))
                return false;
            if (null == bi1 || null == bi2)
                return true;
            return Kernel.Compare(bi1, bi2) != 0;
        }

        public override int GetHashCode()
        {
            uint val = 0;

            for (uint i = 0; i < this.length; i++)
                val ^= this.data[i];

            return (int)val;
        }

        public override bool Equals(object o)
        {
            if (o == null)
                return false;
            if (o is int v)
                return v >= 0 && this == (uint)o;

            BigInteger bi = o as BigInteger;
            if (bi == null)
                return false;

            return Kernel.Compare(this, bi) == 0;
        }

        #endregion

        #region Misc

        /// <summary>
        ///     Normalizes this by setting the length to the actual number of
        ///     uints used in data and by setting the sign to Sign.Zero if the
        ///     value of this is 0.
        /// </summary>
        private void Normalize()
        {
            // Normalize length
            while (length > 0 && data[length - 1] == 0) length--;

            // Check for zero
            if (length == 0)
                length++;
        }

        public void Clear()
        {
            for (int i = 0; i < length; i++)
                data[i] = 0x00;
        }

        #endregion

        /// <summary>
        /// Low level functions for the BigInteger
        /// </summary>
        private static class Kernel
        {

            #region Compare

            /// <summary>
            /// Compares two BigInteger
            /// </summary>
            /// <param name="bi1">A BigInteger</param>
            /// <param name="bi2">A BigInteger</param>
            /// <returns>The sign of bi1 - bi2</returns>
            public static Sign Compare(BigInteger bi1, BigInteger bi2)
            {
                //
                // Step 1. Compare the lengths
                //
                uint l1 = bi1.length, l2 = bi2.length;

                while (l1 > 0 && bi1.data[l1 - 1] == 0) l1--;
                while (l2 > 0 && bi2.data[l2 - 1] == 0) l2--;

                if (l1 == 0 && l2 == 0) return Sign.Zero;

                // bi1 len < bi2 len
                if (l1 < l2) return Sign.Negative;
                // bi1 len > bi2 len
                else if (l1 > l2) return Sign.Positive;

                //
                // Step 2. Compare the bits
                //

                uint pos = l1 - 1;

                while (pos != 0 && bi1.data[pos] == bi2.data[pos]) pos--;

                if (bi1.data[pos] < bi2.data[pos])
                    return Sign.Negative;
                else if (bi1.data[pos] > bi2.data[pos])
                    return Sign.Positive;
                else
                    return Sign.Zero;
            }

            #endregion
        }
    }
}

