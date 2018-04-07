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

namespace Moosey.Cryptography.BCrypt
{
    public static class BCryptConstants
    {
        /*
         * Algorithm Identifiers
         * Source: https://msdn.microsoft.com/en-us/library/windows/desktop/aa375534(v=vs.85).aspx
        */
        public const string BCRYPT_AES_ALGORITHM = "AES";
        public const string BCRYPT_AES_CMAC_ALGORITHM = "AES-CMAC";
        public const string BCRYPT_AES_GMAC_ALGORITHM = "AES-GMAC";

        /*
         * Cryptography Primitive Property Identifiers
         * Source: https://msdn.microsoft.com/en-us/library/windows/desktop/aa376211(v=vs.85).aspx
        */
        public const string BCRYPT_ALGORITHM_NAME = "AlgorithmName";
        public const string BCRYPT_AUTH_TAG_LENGTH = "AuthTagLength";
        public const string BCRYPT_BLOCK_LENGTH = "BlockLength";
        public const string BCRYPT_BLOCK_SIZE_LIST = "BlockSizeList";
        public const string BCRYPT_CHAINING_MODE = "ChainingMode";
        public const string BCRYPT_CHAIN_MODE_CBC = "ChainingModeCBC";
        public const string BCRYPT_CHAIN_MODE_CCM = "ChainingModeCCM";
        public const string BCRYPT_CHAIN_MODE_CFB = "ChainingModeCFB";
        public const string BCRYPT_CHAIN_MODE_ECB = "ChainingModeECB";
        public const string BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM";
        public const string BCRYPT_CHAIN_MODE_NA = "ChainingModeN/A";
        public const string BCRYPT_DH_PARAMETERS = "DHParameters";
        public const string BCRYPT_DSA_PARAMETERS = "DSAParameters";
        public const string BCRYPT_EFFECTIVE_KEY_LENGTH = "EffectiveKeyLength";
        public const string BCRYPT_HASH_LENGTH = "HashDigestLength";
        public const string BCRYPT_HASH_OID_LIST = "HashOIDList";
        public const string BCRYPT_INITIALIZATION_VECTOR = "IV";
        public const string BCRYPT_KEY_LENGTH = "KeyLength";
        public const string BCRYPT_KEY_LENGTHS = "KeyLengths";
        public const string BCRYPT_KEY_OBJECT_LENGTH = "KeyObjectLength";
        public const string BCRYPT_KEY_STRENGTH = "KeyStrength";
        public const string BCRYPT_MESSAGE_BLOCK_LENGTH = "MessageBlockLength";
        public const string BCRYPT_MULTI_OBJECT_LENGTH = "MultiObjectLength";
        public const string BCRYPT_OBJECT_LENGTH = "ObjectLength";
        public const string BCRYPT_PADDING_SCHEMES = "PaddingSchemes";
        public const uint BCRYPT_SUPPORTED_PAD_ROUTER = 0x00000001;
        public const uint BCRYPT_SUPPORTED_PAD_PKCS1_ENC = 0x00000002;
        public const uint BCRYPT_SUPPORTED_PAD_PKCS1_SIG = 0x00000004;
        public const uint BCRYPT_SUPPORTED_PAD_OAEP = 0x00000008;
        public const uint BCRYPT_SUPPORTED_PAD_PSS = 0x00000010;
        public const string BCRYPT_PROVIDER_HANDLE = "ProviderHandle";
        public const string BCRYPT_SGINATURE_LENGTH = "SignatureLength";
    }
}
