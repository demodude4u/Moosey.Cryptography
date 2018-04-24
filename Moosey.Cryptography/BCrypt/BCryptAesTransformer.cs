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
    public class BCryptAesTransformer : IBlockTransformer
    {
        private readonly BlockCipherMode mode;
        private readonly IntPtr hAlgorithmProvider;
        private readonly IntPtr hKey;
        private readonly byte[] iv;
        private readonly bool isEncrypting;

        public int InputBlockSize => 16;

        public int OutputBlockSize => 16;

        public BCryptAesTransformer(BlockCipherMode mode, byte[] key, byte[] iv, bool isEncrypting)
        {
            this.mode = mode;

            uint result = BCryptCore.BCryptOpenAlgorithmProvider(out this.hAlgorithmProvider, "AES", null, 0);
            if (result != 0)
            {
                throw new SystemException("An error was encountered while opening the algorithm provider.");
            }

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

            try
            {
                result = BCryptCore.BCryptSetProperty(this.hAlgorithmProvider, BCryptConstants.BCRYPT_CHAINING_MODE, gcChainingModeValue.AddrOfPinnedObject(), (ulong)chainingModeValue.Length, 0);
            }
            finally
            {
                gcChainingModeValue.Free();
            }

            if (result != 0)
            {
                throw new SystemException("An error was encountered while setting the cipher chaining mode.");
            }

            result = BCryptCore.BCryptGenerateSymmetricKey(this.hAlgorithmProvider, out this.hKey, null, 0, key, (ulong)key.Length, 0);
            if (result != 0)
            {
                throw new SystemException("An error was encountered while generating a symmetric key.");
            }

            this.iv = iv;
            this.isEncrypting = isEncrypting;
        }

        ~BCryptAesTransformer()
        {
            this.Dispose(false);
        }

        protected virtual void Dispose(bool disposing)
        {
            BCryptCore.BCryptDestroyKey(this.hKey);
            BCryptCore.BCryptCloseAlgorithmProvider(this.hAlgorithmProvider, 0);
        }

        public void TransformBlock(byte[] input, int inputOffset, byte[] output, int outputOffset, int count)
        {
            ulong pcbResult;
            ulong ivLength = this.iv == null ? 0 : (ulong)this.iv.Length;

            if (this.isEncrypting)
            {
                uint result = BCryptCore.BCryptEncrypt(this.hKey, input, (ulong)count, IntPtr.Zero, this.iv, ivLength, output, (ulong)output.Length, out pcbResult, BCryptConstants.BCRYPT_NO_PADDING);
                if (result != 0)
                {
                    throw new SystemException("An error was encountered during encryption.");
                }
            }
            else
            {
                uint result = BCryptCore.BCryptDecrypt(this.hKey, input, (ulong)count, IntPtr.Zero, this.iv, ivLength, output, (ulong)output.Length, out pcbResult, BCryptConstants.BCRYPT_NO_PADDING);
                if (result != 0)
                {
                    throw new SystemException("An error was encountered during decryption.");
                }
            }
        }

        public byte[] TransformFinalBlock(byte[] input, int inputOffset, int count)
        {
            ulong ivLength = this.iv == null ? 0 : (ulong)this.iv.Length;

            uint result;
            ulong outputSize;

            // Get the required size of the plaintext/ciphertext buffer
            if (this.isEncrypting)
            {
                result = BCryptCore.BCryptEncrypt(this.hKey, input, (ulong)count, IntPtr.Zero, this.iv, ivLength, null, 0, out outputSize, BCryptConstants.BCRYPT_BLOCK_PADDING);
                if (result != 0)
                {
                    throw new SystemException("An error was encountered while retrieving the ciphertext size.");
                }
            }
            else
            {
                result = BCryptCore.BCryptDecrypt(this.hKey, input, (ulong)count, IntPtr.Zero, this.iv, ivLength, null, 0, out outputSize, BCryptConstants.BCRYPT_BLOCK_PADDING);
                if (result != 0)
                {
                    throw new SystemException("An error was encountered while retrieving the plaintext size.");
                }
            }

            byte[] output = new byte[outputSize];

            // No padding is used with authenticatied modes
            // Bypass final block transformation and defer to regular transformation
            if (this.mode == BlockCipherMode.GCM || this.mode == BlockCipherMode.CCM)
            {
                this.TransformBlock(input, inputOffset, output, 0, count);
                return output;
            }

            ulong pcbResult;
            if (this.isEncrypting)
            {
                result = BCryptCore.BCryptEncrypt(this.hKey, input, (ulong)count, IntPtr.Zero, this.iv, ivLength, output, (ulong)output.Length, out pcbResult, BCryptConstants.BCRYPT_BLOCK_PADDING);
                if (result != 0)
                {
                    throw new SystemException("An error was encountered during encryption.");
                }
            }
            else
            {
                result = BCryptCore.BCryptDecrypt(this.hKey, input, (ulong)count, IntPtr.Zero, this.iv, ivLength, output, (ulong)output.Length, out pcbResult, BCryptConstants.BCRYPT_BLOCK_PADDING);
                if (result != 0)
                {
                    throw new SystemException("An error was encountered during decryption.");
                }
            }

            return output;
        }

        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
