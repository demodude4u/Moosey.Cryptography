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
using System.Runtime.InteropServices;
using System.Text;

namespace Moosey.Cryptography.BCrypt
{
    public static class BCryptCore
    {
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375479(v=vs.85).aspx
        [DllImport("bcrypt.dll")]
        public static extern uint BCryptOpenAlgorithmProvider(
            out IntPtr phAlgorithm,
            [MarshalAs(UnmanagedType.LPWStr)] string pszAlgId,
            [MarshalAs(UnmanagedType.LPWStr)] string pszImplementation,
            uint dwFlags);

        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375377(v=vs.85).aspx
        [DllImport("bcrypt.dll")]
        public static extern uint BCryptCloseAlgorithmProvider(
            ref IntPtr hAlgorithm,
            ulong dwFlags);

        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375504(v=vs.85).aspx
        [DllImport("bcrypt.dll")]
        public static extern uint BCryptSetProperty(
            ref IntPtr hObject,
            [MarshalAs(UnmanagedType.LPWStr)] string pszProperty,
            byte[] pbInput,
            ulong cbInput,
            ulong dwFlags);

        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375453(v=vs.85).aspx
        [DllImport("bcrypt.dll")]
        public static extern uint BCryptGenerateSymmetricKey(
            IntPtr hAlgorithm,
            out IntPtr phKey,
            byte[] pbKeyObject,
            ulong cbKeyObject,
            byte[] pbSecret,
            ulong cbSecret,
            ulong dwFlags);

        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375421(v=vs.85).aspx
        [DllImport("bcrypt.dll")]
        public static extern uint BCryptEncrypt(
            IntPtr hKey,
            byte[] pbInput,
            ulong cbInput,
            IntPtr pPaddingInfo,
            byte[] pvIv,
            ulong cbIv,
            byte[] pbOutput,
            ulong cbOutput,
            out ulong pcbReesult,
            ulong dwFlags);
    }
}
