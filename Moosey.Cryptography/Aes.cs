﻿/*
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
using Moosey.Cryptography.BCrypt;

namespace Moosey.Cryptography
{
    public class Aes : IBlockCipher
    {
        public int BlockSize => 16;

        public Aes()
        {

        }

        public IBlockTransformer CreateEncryptor(BlockCipherMode mode, byte[] key, byte[] iv)
        {
            switch (PlatformDetector.GetCurrentPlatform())
            {
                case OperatingPlatform.Windows:
                    return new BCryptAesTransformer(mode, key, iv, true);

                default:
                    throw new PlatformNotSupportedException("The current system platform is not supported.");
            }
        }

        public IBlockTransformer CreateDecryptor(BlockCipherMode mode, byte[] key, byte[] iv)
        {
            switch (PlatformDetector.GetCurrentPlatform())
            {
                case OperatingPlatform.Windows:
                    return new BCryptAesTransformer(mode, key, iv, false);

                default:
                    throw new PlatformNotSupportedException("The current system platform is not supported.");
            }
        }

        public void SetBlockSize(int blockSize)
        {
            // We'll support setting the block size, but not really.
            // AES only supports 128-bit block sizes. This isn't Rijndael!

            if (blockSize != 16)
            {
                throw new ArgumentException("The block size must be exactly 16 bytes.");
            }
        }
    }
}
