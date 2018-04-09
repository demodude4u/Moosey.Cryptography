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
    public static class BCryptCore
    {
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375479(v=vs.85).aspx
        [DllImport("bcrypt.dll")]
        public static extern uint BCryptOpenAlgorithmProvider(
            [Out] out IntPtr phAlgorithm,
            [In, MarshalAs(UnmanagedType.LPWStr)] string pszAlgId,
            [In, MarshalAs(UnmanagedType.LPWStr)] string pszImplementation,
            [In] uint dwFlags);

        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375377(v=vs.85).aspx
        [DllImport("bcrypt.dll")]
        public static extern uint BCryptCloseAlgorithmProvider(
            [In] IntPtr hAlgorithm,
            [In] ulong dwFlags);

        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375377(v=vs.85).aspx
        [DllImport("bcrypt.dll")]
        public static extern uint BCryptCloseAlgorithmProvider(
            [In, Out] ref IntPtr hAlgorithm,
            [In] ulong dwFlags);

        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375504(v=vs.85).aspx
        [DllImport("bcrypt.dll")]
        public static extern uint BCryptSetProperty(
            [In, Out] ref IntPtr hObject,
            [In, MarshalAs(UnmanagedType.LPWStr)] string pszProperty,
            [In] byte[] pbInput,
            [In] ulong cbInput,
            [In] ulong dwFlags);

        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375453(v=vs.85).aspx
        [DllImport("bcrypt.dll")]
        public static extern uint BCryptGenerateSymmetricKey(
            [In] IntPtr hAlgorithm,
            [Out] out IntPtr phKey,
            [Out] byte[] pbKeyObject,
            [In] ulong cbKeyObject,
            [In] byte[] pbSecret,
            [In] ulong cbSecret,
            [In] ulong dwFlags);

        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375404(v=vs.85).aspx
        [DllImport("bcrypt.dll")]
        public static extern uint BCryptDestroyKey(
            [In] IntPtr hKey);

        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375421(v=vs.85).aspx
        [DllImport("bcrypt.dll")]
        public static extern uint BCryptEncrypt(
            [In] IntPtr hKey,
            [In] byte[] pbInput,
            [In] ulong cbInput,
            [In] IntPtr pPaddingInfo,
            [In, Out] byte[] pvIv,
            [In] ulong cbIv,
            [Out] byte[] pbOutput,
            [In] ulong cbOutput,
            [Out] out ulong pcbReesult,
            [In] ulong dwFlags);

        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375391(v=vs.85).aspx
        [DllImport("bcrypt.dll")]
        public static extern uint BCryptDecrypt(
            [In] IntPtr hKey,
            [In] byte[] pbInput,
            [In] ulong cbInput,
            [In] IntPtr pPaddingInfo,
            [In, Out] byte[] pvIv,
            [In] ulong cbIv,
            [Out] byte[] pbOutput,
            [In] ulong cbOutput,
            [Out] out ulong pcbReesult,
            [In] ulong dwFlags);
    }
}
