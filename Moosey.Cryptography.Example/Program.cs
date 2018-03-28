﻿using System;
using System.Runtime.InteropServices;

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
        }
    }
}