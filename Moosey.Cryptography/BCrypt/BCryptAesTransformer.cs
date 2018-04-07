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
        public int InputBlockSize => 16;

        public int OutputBlockSize => 16;

        public BCryptAesTransformer(byte[] key, byte[] iv)
        {

        }

        public void TransformBlock(byte[] input, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public byte[] TransformFinalBlock(byte[] input, int offset, int count)
        {
            throw new NotImplementedException();
        }
    }
}
