using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Moosey.Cryptography
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
