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
using Moosey.Cryptography.BCrypt;

namespace Moosey.Cryptography.Example
{
    internal static class Program
    {
        private static void Main()
        {
            IntPtr algorithm;
            uint result = BCryptCore.BCryptOpenAlgorithmProvider(out algorithm, "AES", null, 0);

            IntPtr key;
            byte[] secret = new byte[16];
            result = BCryptCore.BCryptGenerateSymmetricKey(algorithm, out key, null, 0, secret, (ulong)secret.Length, 0);

            byte[] plaintext = new byte[] { 0x6a, 0x84, 0x86, 0x7c, 0xd7, 0x7e, 0x12, 0xad, 0x07, 0xea, 0x1b, 0xe8, 0x95, 0xc5, 0x3f, 0xa3 };

            byte[] ciphertext = new byte[plaintext.Length];

            ulong pcbResult;
            BCryptCore.BCryptEncrypt(key, plaintext, (ulong)plaintext.Length, IntPtr.Zero, null, 0, ciphertext, (ulong)ciphertext.Length, out pcbResult, 0);

            Aes aes = new Aes();
            IBlockTransformer encryptor = aes.CreateEncryptor(BlockCipherMode.ECB, secret, null);

            byte[] ciphertext2 = new byte[plaintext.Length];
            encryptor.TransformBlock(plaintext, 0, ciphertext2, 0, ciphertext2.Length);
        }
    }
}
