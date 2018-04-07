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
using System.Collections.Generic;
using System.Text;

namespace Moosey.Cryptography.BCrypt
{
    public class BCryptAesTransformer : IBlockTransformer
    {
        private readonly IntPtr hAlgorithmProvider;
        private readonly IntPtr hKey;
        private readonly byte[] iv;
        private readonly bool isEncrypting;

        public int InputBlockSize => 16;

        public int OutputBlockSize => 16;

        public BCryptAesTransformer(BlockCipherMode mode, byte[] key, byte[] iv, bool isEncrypting)
        {
            uint result = BCryptCore.BCryptOpenAlgorithmProvider(out this.hAlgorithmProvider, "AES", null, 0);
            if (result != 0)
            {
                throw new SystemException("An error was encountered while opening the algorithm provider.");
            }

            result = BCryptCore.BCryptGenerateSymmetricKey(this.hAlgorithmProvider, out this.hKey, null, 0, key, (ulong)key.Length, 0);
            if (result != 0)
            {
                throw new SystemException("An error was encountered while generating a symmetric key.");
            }

            this.iv = iv;
            this.isEncrypting = isEncrypting;
        }

        public void TransformBlock(byte[] input, int inputOffset, byte[] output, int outputOffset, int count)
        {
            ulong pcbResult;
            ulong ivLength = this.iv == null ? 0 : (ulong)this.iv.Length;

            if (this.isEncrypting)
            {
                BCryptCore.BCryptEncrypt(this.hKey, input, (ulong)count, IntPtr.Zero, this.iv, ivLength, output, (ulong)output.Length, out pcbResult, 0);
            }
        }

        public byte[] TransformFinalBlock(byte[] input, int inputOffset, byte[] output, int outputOffset, int count)
        {
            throw new NotImplementedException();
        }
    }
}
