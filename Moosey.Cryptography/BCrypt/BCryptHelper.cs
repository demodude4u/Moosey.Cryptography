/*
 * The MIT License (MIT)
 * =====================
 * Copyright (c) 2018 Michael J. Gray
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
*/

using System;
using System.Runtime.InteropServices;

namespace Moosey.Cryptography.BCrypt
{
    public static class BCryptHelper
    {
        public static void SetBlockChainingMode(IntPtr hAlgorithmProvider, BlockCipherMode mode)
        {
            string chainingModeValue;
            switch (mode)
            {
                case BlockCipherMode.CBC:
                    chainingModeValue = BCryptConstants.BCRYPT_CHAIN_MODE_CBC;
                    break;

                case BlockCipherMode.CCM:
                    chainingModeValue = BCryptConstants.BCRYPT_CHAIN_MODE_CCM;
                    break;

                case BlockCipherMode.CFB:
                    chainingModeValue = BCryptConstants.BCRYPT_CHAIN_MODE_CFB;
                    break;

                case BlockCipherMode.ECB:
                    chainingModeValue = BCryptConstants.BCRYPT_CHAIN_MODE_ECB;
                    break;

                case BlockCipherMode.GCM:
                    chainingModeValue = BCryptConstants.BCRYPT_CHAIN_MODE_GCM;
                    break;

                case BlockCipherMode.Unspecified:
                    chainingModeValue = BCryptConstants.BCRYPT_CHAIN_MODE_NA;
                    break;

                default:
                    throw new ArgumentException("The specified block cipher chaining mode is not recognized.", nameof(mode));
            }

            GCHandle gcChainingModeValue = GCHandle.Alloc(chainingModeValue, GCHandleType.Pinned);

            uint result;
            try
            {
                result = BCryptCore.BCryptSetProperty(hAlgorithmProvider, BCryptConstants.BCRYPT_CHAINING_MODE, gcChainingModeValue.AddrOfPinnedObject(), (ulong)chainingModeValue.Length, 0);
            }
            finally
            {
                gcChainingModeValue.Free();
            }

            if (result != 0)
            {
                throw new SystemException("An error was encountered while setting the cipher chaining mode.");
            }
        }
    }
}
